package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var errNativeWorkerConcreteRuntime = errors.New("HOLD: protected Native runtime evidence is unavailable")

// This is a Go composition contract, never a manifest or request DTO. A
// successful constructor takes ownership of the supplied factory/RPC handles.
// A failed constructor takes no ownership and closes nothing supplied by its
// caller. The caller continues to own the database.
type NativeWorkerConcreteRuntimeConfig struct {
	DB           *sql.DB
	Policy       model.Manifest
	Factories    map[string]*capacity.NativeWorkerPrivateFactory
	PhaseRead    capacity.NativeWorkerPhaseReadFunc
	PhysicalRead capacity.NativeWorkerPhysicalReadFunc
	RPCClients   []*capacity.NativeWorkerRPCClient
}

type NativeWorkerConcreteRuntime struct {
	*nativeWorkerConcreteRuntimeState
}

type nativeWorkerConcreteRuntimeState struct {
	mu        sync.RWMutex
	closed    bool
	db        *sql.DB
	policy    model.Manifest
	spec      model.CapacityPolicySpec
	source    string
	factories map[string]*capacity.NativeWorkerPrivateFactory
	clients   []*capacity.NativeWorkerRPCClient
	phase     *capacity.NativeWorkerPhaseReader
	physical  *capacity.NativeWorkerACKQualifier
}

func (NativeWorkerConcreteRuntime) String() string     { return "[private Native worker runtime]" }
func (r NativeWorkerConcreteRuntime) GoString() string { return r.String() }
func (NativeWorkerConcreteRuntime) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_runtime":"redacted"}`), nil
}

// Provider literals are paired with the independently reviewed ACK qualifier.
// A generic test provider or an alias cannot select either real provider path.
func nativeConcreteRuntimeProvider(provider string) bool {
	return provider == "aws" || provider == "hetzner"
}

func NewNativeWorkerConcreteRuntime(c NativeWorkerConcreteRuntimeConfig) (*NativeWorkerConcreteRuntime, error) {
	return newNativeWorkerConcreteRuntime(c, capacity.CurrentGuestCoreSource())
}

// The separate argument permits deterministic metadata fixtures in this
// package's CI tests. The public constructor always reads native build metadata.
func newNativeWorkerConcreteRuntime(c NativeWorkerConcreteRuntimeConfig, source string) (*NativeWorkerConcreteRuntime, error) {
	p, err := parseCapacityPolicy(c.Policy)
	if err != nil || c.DB == nil || c.Policy.Kind != "capacity_policy" || c.Policy.ID == uuid.Nil ||
		!c.Policy.Metadata.Active || c.Policy.Checksum == "" || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.PhaseObserver == nil ||
		p.NativeWorkerLifecycleBinding.SourceCommit != source || c.PhaseRead == nil || c.PhysicalRead == nil || len(c.Factories) != len(p.NativeWorkerLifecycleBinding.Profiles) {
		return nil, errNativeWorkerConcreteRuntime
	}
	// No expected Source can stand in for absent/dirty native build metadata.
	if len(source) != 40 {
		return nil, errNativeWorkerConcreteRuntime
	}
	for _, ch := range source {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return nil, errNativeWorkerConcreteRuntime
		}
	}
	factories := make(map[string]*capacity.NativeWorkerPrivateFactory, len(c.Factories))
	for _, execution := range p.NativeWorkerLifecycleBinding.Profiles {
		pairedProfile := false
		for _, profile := range p.Profiles {
			if profile.Name == execution.Profile && nativeConcreteRuntimeProvider(profile.Provider) {
				pairedProfile = true
			}
		}
		factory := c.Factories[execution.Profile]
		if !pairedProfile || factory == nil || !factory.MatchesExecution(execution) {
			return nil, errNativeWorkerConcreteRuntime
		}
		factories[execution.Profile] = factory
	}
	phase, err := capacity.NewNativeWorkerPhaseReader(p, c.PhaseRead, nil)
	if err != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	physical, err := capacity.NewNativeWorkerACKQualifier(p, c.PhysicalRead)
	if err != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	raw, err := json.Marshal(c.Policy)
	var policy model.Manifest
	if err != nil || json.Unmarshal(raw, &policy) != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	// Preserve the stored JSONB bytes: a Manifest JSON roundtrip compacts
	// RawMessage, while policyMatches intentionally requires exact identity.
	policy.Spec = append(json.RawMessage(nil), c.Policy.Spec...)
	var ownSpec model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &ownSpec) != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	clients := append([]*capacity.NativeWorkerRPCClient(nil), c.RPCClients...)
	for _, client := range clients {
		if client == nil {
			return nil, errNativeWorkerConcreteRuntime
		}
	}
	return &NativeWorkerConcreteRuntime{&nativeWorkerConcreteRuntimeState{db: c.DB, policy: policy, spec: ownSpec, source: source,
		factories: factories, clients: clients, phase: phase, physical: physical}}, nil
}

func (r *NativeWorkerConcreteRuntime) SourceCommit() string {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return ""
	}
	return r.source
}

func (r *NativeWorkerConcreteRuntime) BoundToDatabase(db *sql.DB) bool {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.closed && db != nil && r.db == db
}

func (r *NativeWorkerConcreteRuntime) policyMatches(p model.Manifest) bool {
	return p.ID == r.policy.ID && p.Kind == r.policy.Kind && p.Version == r.policy.Version && p.Metadata.Namespace == r.policy.Metadata.Namespace && p.Metadata.Name == r.policy.Metadata.Name &&
		p.Checksum == r.policy.Checksum && bytes.Equal(p.Spec, r.policy.Spec)
}

// A complete header is not a useful-worker snapshot. This runtime deliberately
// has no fallback that manufactures a zero-member/ready pool observation.
func (*NativeWorkerConcreteRuntime) ObserveAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPoolObservation, error) {
	return nil, errNativeWorkerConcreteRuntime
}

func (r *NativeWorkerConcreteRuntime) ObservePhaseAuthority(ctx context.Context, policy model.Manifest) (*model.CapacityNativeWorkerPhaseReadObservation, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.phase == nil || !r.policyMatches(policy) {
		return nil, errNativeWorkerConcreteRuntime
	}
	return r.phase.ObservePhaseAuthority(ctx, policy)
}

// Provider and market region belong to the frozen stored profile, not merely
// to a known-provider allowlist. This also protects phase and pure factory ports.
func (r *NativeWorkerConcreteRuntime) attemptProfileBound(a model.CapacityNativeWorkerAttempt) bool {
	for _, p := range r.spec.Profiles {
		if p.Name == a.Profile {
			return nativeConcreteRuntimeProvider(p.Provider) && a.Provider == p.Provider && a.Region == p.Region
		}
	}
	return false
}

func (r *NativeWorkerConcreteRuntime) phaseAttemptBound(a model.CapacityNativeWorkerAttempt) bool {
	b, pool := r.spec.NativeWorkerLifecycleBinding, r.spec.NativeWorkerPoolBinding
	if b == nil || pool == nil || b.PhaseObserver == nil || b.RegistryWriter == nil || !r.attemptProfileBound(a) || a.SourceCommit != r.source ||
		a.PolicyID != r.policy.ID || a.PolicyChecksum != r.policy.Checksum || a.Namespace != r.policy.Metadata.Namespace ||
		a.PoolUID != pool.PoolUID || a.PoolEpoch != pool.ExpectedPoolEpoch || a.Registry != pool.RegistryRef {
		return false
	}
	for _, execution := range b.Profiles {
		if execution.Profile == a.Profile && reflect.DeepEqual(execution, a.Execution) {
			return true
		}
	}
	return false
}

// These are the existing real phase-reader ports, without a readiness fallback.
// The reader's nil readiness port continues to refuse admission/release plans.
func (r *NativeWorkerConcreteRuntime) PreparePhase(ctx context.Context, a model.CapacityNativeWorkerAttempt, action string) (model.CapacityNativeWorkerPhasePreparation, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return model.CapacityNativeWorkerPhasePreparation{}, errNativeWorkerConcreteRuntime
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.phase == nil || !r.phaseAttemptBound(a) {
		return model.CapacityNativeWorkerPhasePreparation{}, errNativeWorkerConcreteRuntime
	}
	return r.phase.PreparePhase(ctx, a, action)
}

func (r *NativeWorkerConcreteRuntime) ObservePhase(ctx context.Context, permit model.CapacityNativeWorkerPhasePermit) (model.CapacityNativeWorkerPhaseObservation, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return model.CapacityNativeWorkerPhaseObservation{}, errNativeWorkerConcreteRuntime
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, pool := r.spec.NativeWorkerLifecycleBinding, r.spec.NativeWorkerPoolBinding
	if r.closed || r.phase == nil || b == nil || pool == nil || b.RegistryWriter == nil || b.PhaseObserver == nil ||
		permit.PolicyID != r.policy.ID || permit.BindingName != b.RegistryWriter.BindingName || permit.WriterScopeSHA256 != b.RegistryWriter.ScopeSHA256 ||
		permit.Operation != "ensure_native_worker_pool" || permit.PoolUID != pool.PoolUID || permit.Owner != r.spec.Owner ||
		permit.Epoch != pool.ExpectedPoolEpoch || permit.Registry != pool.RegistryRef || permit.RealmUID != pool.RealmUID || permit.RealmNamespace != b.PhaseObserver.RealmNamespace {
		return model.CapacityNativeWorkerPhaseObservation{}, errNativeWorkerConcreteRuntime
	}
	return r.phase.ObservePhase(ctx, permit)
}

func (r *NativeWorkerConcreteRuntime) Prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil {
		return model.CapacityNativeWorkerLaunch{}, errNativeWorkerConcreteRuntime
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	factory := r.factories[a.Profile]
	if r.closed || !r.attemptProfileBound(a) || a.SourceCommit != r.source || a.PolicyID != r.policy.ID || a.PolicyChecksum != r.policy.Checksum || a.Namespace != r.policy.Metadata.Namespace || factory == nil {
		return model.CapacityNativeWorkerLaunch{}, errNativeWorkerConcreteRuntime
	}
	return factory.Prepare(a) // Pure: existing factory performs no I/O here.
}

func (r *NativeWorkerConcreteRuntime) RenderNativeWorkerPrivateBootstrap(ctx context.Context, a model.CapacityNativeWorkerAttempt, launch json.RawMessage, expiry time.Time) ([]byte, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	factory := r.factories[a.Profile]
	if r.closed || !r.attemptProfileBound(a) || a.SourceCommit != r.source || a.PolicyID != r.policy.ID || a.PolicyChecksum != r.policy.Checksum || a.Namespace != r.policy.Metadata.Namespace || factory == nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	return factory.RenderNativeWorkerPrivateBootstrap(ctx, a, append(json.RawMessage(nil), launch...), expiry)
}

func (r *NativeWorkerConcreteRuntime) loadOriginal(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	var original model.CapacityNativeWorkerOriginalReturn
	if ctx == nil || ctx.Err() != nil || a.PolicyID != r.policy.ID || a.PolicyChecksum != r.policy.Checksum || a.Namespace != r.policy.Metadata.Namespace || a.SourceCommit != r.source {
		return original, errNativeWorkerConcreteRuntime
	}
	var digest string
	err := r.db.QueryRowContext(ctx, `SELECT o.wire,o.raw_sha256,o.capture_complete,o.error_class FROM public.capacity_native_worker_original_returns o JOIN public.capacity_native_worker_attempts a ON a.id=o.attempt_id WHERE a.id=$1 AND a.policy_id=$2 AND a.namespace=$3 AND a.attempt->>'source_commit'=$4 AND a.attempt->>'policy_checksum'=$5`, a.ID, a.PolicyID, a.Namespace, r.source, r.policy.Checksum).Scan(&original.Wire, &digest, &original.CaptureComplete, &original.ErrorClass)
	if errors.Is(err, sql.ErrNoRows) {
		return model.CapacityNativeWorkerOriginalReturn{}, ErrCapacityNativeReturnPending
	}
	if err != nil || len(original.Wire) > 1<<20 || len(original.Wire) == 0 || fmt.Sprintf("%x", sha256.Sum256(original.Wire)) != digest {
		return model.CapacityNativeWorkerOriginalReturn{}, errNativeWorkerConcreteRuntime
	}
	original.Wire = append([]byte(nil), original.Wire...)
	return original, nil
}

func (r *NativeWorkerConcreteRuntime) CaptureOriginalReturn(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil {
		return model.CapacityNativeWorkerOriginalReturn{}, errors.Join(ErrCapacityNativeReturnPending, errNativeWorkerConcreteRuntime)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return model.CapacityNativeWorkerOriginalReturn{}, errors.Join(ErrCapacityNativeReturnPending, errNativeWorkerConcreteRuntime)
	}
	original, err := r.loadOriginal(ctx, a)
	if err != nil {
		// Store.original recognizes this sentinel and must not persist an empty
		// synthetic capture on an archive read error or absent/corrupt evidence.
		return model.CapacityNativeWorkerOriginalReturn{}, errors.Join(ErrCapacityNativeReturnPending, err)
	}
	return original, nil // Archive-only. No actor, pipe or replacement send.
}

func (r *NativeWorkerConcreteRuntime) launchAndOriginal(ctx context.Context, a model.CapacityNativeWorkerAttempt, original model.CapacityNativeWorkerOriginalReturn) ([]byte, error) {
	archived, err := r.loadOriginal(ctx, a)
	if err != nil || !bytes.Equal(archived.Wire, original.Wire) || archived.CaptureComplete != original.CaptureComplete || archived.ErrorClass != original.ErrorClass {
		return nil, errNativeWorkerConcreteRuntime
	}
	var launch, actualRaw []byte
	var actual model.CapacityNativeWorkerAttempt
	if err := r.db.QueryRowContext(ctx, `SELECT attempt,launch_wire FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, a.ID, a.PolicyID, a.Namespace).Scan(&actualRaw, &launch); err != nil || json.Unmarshal(actualRaw, &actual) != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	want, _ := json.Marshal(a)
	have, _ := json.Marshal(actual)
	if !bytes.Equal(want, have) || fmt.Sprintf("%x", sha256.Sum256(launch)) != a.LaunchSHA256 {
		return nil, errNativeWorkerConcreteRuntime
	}
	return append([]byte(nil), launch...), nil
}

func (r *NativeWorkerConcreteRuntime) Qualify(ctx context.Context, a model.CapacityNativeWorkerAttempt, original model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return model.CapacityNativeWorkerObservation{}, errNativeWorkerConcreteRuntime
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || !r.attemptProfileBound(a) {
		return model.CapacityNativeWorkerObservation{}, errNativeWorkerConcreteRuntime
	}
	launch, err := r.launchAndOriginal(ctx, a, original)
	if err != nil {
		return model.CapacityNativeWorkerObservation{}, err
	}
	return r.physical.QualifyACK(ctx, a, launch, original)
}

// Sealed reobservation is a distinct GET-only API; it never rewrites Attempt
// state or synthesizes acknowledged/registered/admitted lifecycle evidence.
func (r *NativeWorkerConcreteRuntime) ReobserveACK(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerPhysical, error) {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return model.CapacityNativeWorkerPhysical{}, errNativeWorkerConcreteRuntime
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || !r.attemptProfileBound(a) {
		return model.CapacityNativeWorkerPhysical{}, errNativeWorkerConcreteRuntime
	}
	original, err := r.loadOriginal(ctx, a)
	if err != nil {
		return model.CapacityNativeWorkerPhysical{}, err
	}
	launch, err := r.launchAndOriginal(ctx, a, original)
	if err != nil {
		return model.CapacityNativeWorkerPhysical{}, err
	}
	return r.physical.ReobserveACK(ctx, a, launch, original)
}

func (r *NativeWorkerConcreteRuntime) Close() error {
	if r == nil || r.nativeWorkerConcreteRuntimeState == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var errs []error
	for _, factory := range r.factories {
		errs = append(errs, factory.Close())
	}
	for _, client := range r.clients {
		errs = append(errs, client.Close())
	}
	r.factories, r.clients, r.phase, r.physical = nil, nil, nil, nil
	return errors.Join(errs...)
}
