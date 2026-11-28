package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var errNativeWorkerConcreteNetwork = errors.New("HOLD: protected Native network composition or original evidence unavailable")

// This private Go composition borrows Workers and the database. On successful
// construction it owns Reader/Writer; a failed constructor closes nothing.
// No URL, credential, provider SDK or readiness proof is accepted here.
type NativeWorkerConcreteNetworkRuntimeConfig struct {
	DB      *sql.DB
	Policy  model.Manifest
	Workers *NativeWorkerConcreteRuntime
	Reader  *capacity.NativeWorkerNetworkRPCClient
	Writer  *capacity.NativeWorkerNetworkRPCClient
}

type NativeWorkerConcreteNetworkRuntime struct {
	*nativeWorkerConcreteNetworkState
}

type nativeWorkerConcreteNetworkState struct {
	mu      sync.RWMutex
	closed  bool
	db      *sql.DB
	policy  model.Manifest
	spec    model.CapacityPolicySpec
	source  string
	workers *NativeWorkerConcreteRuntime
	reader  *capacity.NativeWorkerNetworkRPCClient
	writer  *capacity.NativeWorkerNetworkRPCClient
}

func (NativeWorkerConcreteNetworkRuntime) String() string {
	return "[private Native network runtime]"
}
func (r NativeWorkerConcreteNetworkRuntime) GoString() string { return r.String() }
func (NativeWorkerConcreteNetworkRuntime) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_network_runtime":"redacted"}`), nil
}

func NewNativeWorkerConcreteNetworkRuntime(c NativeWorkerConcreteNetworkRuntimeConfig) (*NativeWorkerConcreteNetworkRuntime, error) {
	return newNativeWorkerConcreteNetworkRuntime(c, capacity.CurrentGuestCoreSource())
}

func nativeNetworkCoreSource(source string) bool {
	if len(source) != 40 {
		return false
	}
	for _, ch := range source {
		if !strings.ContainsRune("0123456789abcdef", ch) {
			return false
		}
	}
	return true
}

// Only in-package CI supplies deterministic native build metadata. The public
// constructor never accepts an expected Source as a substitute for the build.
func newNativeWorkerConcreteNetworkRuntime(c NativeWorkerConcreteNetworkRuntimeConfig, source string) (*NativeWorkerConcreteNetworkRuntime, error) {
	if c.DB == nil || c.Workers == nil || c.Workers.nativeWorkerConcreteRuntimeState == nil || c.Reader == nil || c.Writer == nil || !nativeNetworkCoreSource(source) {
		return nil, errNativeWorkerConcreteNetwork
	}
	w := c.Workers
	w.mu.RLock()
	defer w.mu.RUnlock()
	p, err := parseCapacityPolicy(c.Policy)
	if err != nil || c.Policy.Kind != "capacity_policy" || c.Policy.ID == uuid.Nil || !c.Policy.Metadata.Active ||
		w.closed || w.db != c.DB || w.source != source || w.physical == nil || !w.policyMatches(c.Policy) ||
		p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.SourceCommit != source || p.NativeWorkerLifecycleBinding.Network == nil ||
		capacity.ValidateNativeWorkerNetworkBinding(p) != nil {
		return nil, errNativeWorkerConcreteNetwork
	}
	b := *p.NativeWorkerLifecycleBinding.Network
	if !c.Reader.Matches("reader", b) || !c.Writer.Matches("writer", b) {
		return nil, errNativeWorkerConcreteNetwork
	}
	raw, err := json.Marshal(c.Policy)
	var policy model.Manifest
	if err != nil || json.Unmarshal(raw, &policy) != nil {
		return nil, errNativeWorkerConcreteNetwork
	}
	// Preserve the stored JSONB bytes: a Manifest JSON roundtrip compacts
	// RawMessage, while policyMatches intentionally requires exact identity.
	policy.Spec = append(json.RawMessage(nil), c.Policy.Spec...)
	var spec model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &spec) != nil {
		return nil, errNativeWorkerConcreteNetwork
	}
	return &NativeWorkerConcreteNetworkRuntime{&nativeWorkerConcreteNetworkState{db: c.DB, policy: policy, spec: spec, source: source, workers: w, reader: c.Reader, writer: c.Writer}}, nil
}

// Lock order is composition -> borrowed Workers -> concrete RPC client. No
// database transaction or mutable ownership is held while a remote read runs.
func (r *NativeWorkerConcreteNetworkRuntime) boundLocked(policy model.Manifest) bool {
	w := r.workers
	return !r.closed && w != nil && w.nativeWorkerConcreteRuntimeState != nil && !w.closed && w.db == r.db && w.source == r.source && w.physical != nil &&
		w.policyMatches(r.policy) && w.policyMatches(policy) && r.spec.NativeWorkerPoolBinding != nil && r.spec.NativeWorkerLifecycleBinding != nil && r.spec.NativeWorkerLifecycleBinding.Network != nil
}

func (r *NativeWorkerConcreteNetworkRuntime) attemptBoundLocked(a model.CapacityNativeWorkerAttempt) bool {
	life, pool := r.spec.NativeWorkerLifecycleBinding, r.spec.NativeWorkerPoolBinding
	if !r.workers.attemptProfileBound(a) || a.SourceCommit != r.source || a.PolicyID != r.policy.ID || a.PolicyChecksum != r.policy.Checksum || a.Namespace != r.policy.Metadata.Namespace ||
		a.PoolUID != pool.PoolUID || a.PoolEpoch != pool.ExpectedPoolEpoch || a.Registry != pool.RegistryRef {
		return false
	}
	for _, execution := range life.Profiles {
		if execution.Profile == a.Profile && reflect.DeepEqual(execution, a.Execution) {
			return true
		}
	}
	return false
}

func (r *NativeWorkerConcreteNetworkRuntime) SourceCommit() string {
	if r == nil || r.nativeWorkerConcreteNetworkState == nil || r.workers == nil || r.workers.nativeWorkerConcreteRuntimeState == nil {
		return ""
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.workers.mu.RLock()
	defer r.workers.mu.RUnlock()
	if !r.boundLocked(r.policy) {
		return ""
	}
	return r.source
}

func (r *NativeWorkerConcreteNetworkRuntime) BoundToDatabase(db *sql.DB) bool {
	if r == nil || r.nativeWorkerConcreteNetworkState == nil || db == nil || r.workers == nil || r.workers.nativeWorkerConcreteRuntimeState == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.workers.mu.RLock()
	defer r.workers.mu.RUnlock()
	return r.boundLocked(r.policy) && r.db == db
}

// Original capture is an immutable archive read. It must match the exact
// current Attempt/Launch before either independent reader is contacted.
func (r *NativeWorkerConcreteNetworkRuntime) targetLocked(ctx context.Context, a model.CapacityNativeWorkerAttempt) (json.RawMessage, model.CapacityNativeWorkerOriginalReturn, model.CapacityNativeWorkerNetworkObserveInput, error) {
	var selector model.CapacityNativeWorkerNetworkObserveInput
	if !r.attemptBoundLocked(a) || a.Physical == nil || !capacity.NativeWorkerPhysicalValid(a, *a.Physical) {
		return nil, model.CapacityNativeWorkerOriginalReturn{}, selector, errNativeWorkerConcreteNetwork
	}
	original, err := r.workers.loadOriginal(ctx, a)
	if err != nil {
		return nil, original, selector, errNativeWorkerConcreteNetwork
	}
	launch, err := r.workers.launchAndOriginal(ctx, a, original)
	if err != nil {
		clear(original.Wire)
		return nil, model.CapacityNativeWorkerOriginalReturn{}, selector, errNativeWorkerConcreteNetwork
	}
	selector, err = capacity.NativeWorkerNetworkSelector(r.spec, a, json.RawMessage(launch))
	if err != nil {
		clear(original.Wire)
		return nil, model.CapacityNativeWorkerOriginalReturn{}, model.CapacityNativeWorkerNetworkObserveInput{}, errNativeWorkerConcreteNetwork
	}
	return json.RawMessage(launch), original, selector, nil
}

func (r *NativeWorkerConcreteNetworkRuntime) PrepareNetwork(ctx context.Context, policy model.Manifest, a model.CapacityNativeWorkerAttempt, action string) (capacity.NativeWorkerNetworkPreparation, error) {
	var out capacity.NativeWorkerNetworkPreparation
	if r == nil || r.nativeWorkerConcreteNetworkState == nil || r.workers == nil || r.workers.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil || action != "install" && action != "remove" {
		return out, errNativeWorkerConcreteNetwork
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.workers.mu.RLock()
	defer r.workers.mu.RUnlock()
	if !r.boundLocked(policy) || !r.reader.Matches("reader", *r.spec.NativeWorkerLifecycleBinding.Network) ||
		action == "install" && a.State != "acknowledged" && a.State != "registered" || action == "remove" && a.State != "aborting" && a.State != "draining" {
		return out, errNativeWorkerConcreteNetwork
	}
	launch, original, selector, err := r.targetLocked(ctx, a)
	if err != nil {
		return out, err
	}
	defer clear(original.Wire)
	if action == "install" {
		current, err := r.workers.physical.ReobserveTransportACK(ctx, a, launch, original)
		if err != nil {
			return out, errNativeWorkerConcreteNetwork
		}
		out.Physical, out.PhysicalObservedAt, out.PhysicalEvidenceSHA256 = current.Physical, current.ObservedAt, current.EvidenceSHA256
		out.PhysicalSourceCommit, out.PhysicalScopeSHA256, out.TransportEndpointIPv4 = current.SourceCommit, current.ScopeSHA256, current.TransportEndpointIPv4
	} else {
		// Provider deletion is allowed to precede this compensation. The Store
		// alone supplies the endpoint from its immutable exposed install grant.
		out.Physical = *a.Physical
	}
	out.Floor, err = r.reader.Observe(ctx, selector)
	if err != nil || ctx.Err() != nil || !capacity.NativeWorkerNetworkObservationValid(r.spec, a, launch, out.Floor, time.Now().UTC()) ||
		action == "install" && !capacity.NativeWorkerNetworkPreparationValid(r.spec, a, launch, out, time.Now().UTC()) {
		return capacity.NativeWorkerNetworkPreparation{}, errNativeWorkerConcreteNetwork
	}
	return out, nil
}

func (r *NativeWorkerConcreteNetworkRuntime) ObserveNetwork(ctx context.Context, policy model.Manifest, a model.CapacityNativeWorkerAttempt, grant model.CapacityNativeWorkerNetworkGrant) (model.CapacityNativeWorkerNetworkObservation, error) {
	var zero model.CapacityNativeWorkerNetworkObservation
	if r == nil || r.nativeWorkerConcreteNetworkState == nil || r.workers == nil || r.workers.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil {
		return zero, errNativeWorkerConcreteNetwork
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.workers.mu.RLock()
	defer r.workers.mu.RUnlock()
	if !r.boundLocked(policy) || !r.reader.Matches("reader", *r.spec.NativeWorkerLifecycleBinding.Network) {
		return zero, errNativeWorkerConcreteNetwork
	}
	launch, original, selector, err := r.targetLocked(ctx, a)
	if err != nil {
		return zero, err
	}
	defer clear(original.Wire)
	if !r.grantBound(grant, a) || grant.Peer.WorkerPublicKey != selector.WorkerPublicKey || grant.Peer.WorkerIPv4 != selector.WorkerIPv4 {
		return zero, errNativeWorkerConcreteNetwork
	}
	o, err := r.reader.Observe(ctx, selector)
	if err != nil || ctx.Err() != nil || !capacity.NativeWorkerNetworkObservationValid(r.spec, a, launch, o, time.Now().UTC()) {
		return zero, errNativeWorkerConcreteNetwork
	}
	return o, nil
}

func (r *NativeWorkerConcreteNetworkRuntime) grantBound(g model.CapacityNativeWorkerNetworkGrant, a model.CapacityNativeWorkerAttempt) bool {
	b, pool := r.spec.NativeWorkerLifecycleBinding.Network, r.spec.NativeWorkerPoolBinding
	id, err := uuid.Parse(g.PermitID)
	capability := capacity.NativeWorkerNetworkInstall
	if g.Action == "remove" {
		capability = capacity.NativeWorkerNetworkRemove
	}
	return err == nil && id != uuid.Nil && id.String() == g.PermitID && (g.Action == "install" || g.Action == "remove") &&
		g.Schema == model.CapacityNativeWorkerNetworkPermitSchema && g.AttemptID == a.ID.String() && g.PolicyID == r.policy.ID.String() && g.Capability == capability &&
		g.BindingName == b.Writer.BindingName && g.SystemSourceCommit == b.Writer.SystemSourceCommit && g.WriterScopeSHA256 == b.Writer.ScopeSHA256 &&
		g.Owner == r.spec.Owner && g.PoolUID == pool.PoolUID && g.RegistryUID == pool.RegistryRef.UID && g.PoolEpoch == pool.ExpectedPoolEpoch &&
		g.IntentGeneration == a.Generation && g.FencingToken == a.FencingToken && g.LaunchSHA256 == a.LaunchSHA256 && g.CreationProofSHA256 == a.BirthSHA256 &&
		g.FloorNodeUID == b.Floor.NodeUID && g.NetworkTemplateSHA256 == b.TemplateSHA256 && g.MTU == capacity.NativeWorkerNetworkMTU
}

// RequestNetworkMutation sends one protected RPC for an already retained
// policy/action/permit. It does not redeem or settle anything itself; System's
// callback to Store117 alone grants a batch and archives its original return.
// An error or unknown RPC disposition is never an invitation to resend.
func (r *NativeWorkerConcreteNetworkRuntime) RequestNetworkMutation(ctx context.Context, policy model.Manifest, action string, permitID uuid.UUID) (capacity.NativeWorkerNetworkRPCMutationResult, error) {
	var zero capacity.NativeWorkerNetworkRPCMutationResult
	if r == nil || r.nativeWorkerConcreteNetworkState == nil || r.workers == nil || r.workers.nativeWorkerConcreteRuntimeState == nil || ctx == nil || ctx.Err() != nil || permitID == uuid.Nil || action != "install" && action != "remove" {
		return zero, errNativeWorkerConcreteNetwork
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.workers.mu.RLock()
	defer r.workers.mu.RUnlock()
	if !r.boundLocked(policy) || !r.writer.Matches("writer", *r.spec.NativeWorkerLifecycleBinding.Network) {
		return zero, errNativeWorkerConcreteNetwork
	}
	var grantRaw, bindingRaw []byte
	var source string
	err := r.db.QueryRowContext(ctx, `SELECT record->'context',record->'binding',record->>'source_commit' FROM public.capacity_native_worker_network_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3 AND action=$4`, permitID, policy.ID, policy.Metadata.Namespace, action).Scan(&grantRaw, &bindingRaw, &source)
	var g model.CapacityNativeWorkerNetworkGrant
	var binding model.CapacityNativeWorkerNetworkBinding
	if err != nil || json.Unmarshal(grantRaw, &g) != nil || json.Unmarshal(bindingRaw, &binding) != nil || source != r.source || g.PermitID != permitID.String() || g.Action != action ||
		g.PolicyID != policy.ID.String() || g.BindingName != binding.Writer.BindingName || g.WriterScopeSHA256 != binding.Writer.ScopeSHA256 || g.SystemSourceCommit != binding.Writer.SystemSourceCommit ||
		!nativeNetworkBindingEqual(binding, *r.spec.NativeWorkerLifecycleBinding.Network) || g.MutationPermitted || g.Redeemable {
		return zero, errNativeWorkerConcreteNetwork
	}
	operation := capacity.NativeWorkerNetworkInstall
	if action == "remove" {
		operation = capacity.NativeWorkerNetworkRemove
	}
	if g.Capability != operation {
		return zero, errNativeWorkerConcreteNetwork
	}
	return r.writer.Mutate(ctx, operation, model.CapacityNativeWorkerNetworkMutationInput{BindingName: binding.Writer.BindingName, PermitID: permitID.String()})
}

func (r *NativeWorkerConcreteNetworkRuntime) Close() error {
	if r == nil || r.nativeWorkerConcreteNetworkState == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return errors.Join(r.reader.Close(), r.writer.Close()) // Borrowed Workers/DB remain owned by their caller.
}

var _ NativeWorkerNetworkRuntime = (*NativeWorkerConcreteNetworkRuntime)(nil)
