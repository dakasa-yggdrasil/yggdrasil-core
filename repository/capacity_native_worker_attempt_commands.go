package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Never returned by Read, workflow metadata, a plan or an HTTP response.
type nativeWorkerCommandContext struct {
	AttemptID      uuid.UUID                                  `json:"attempt_id"`
	PolicyID       uuid.UUID                                  `json:"policy_id"`
	PolicyChecksum string                                     `json:"policy_checksum"`
	Namespace      string                                     `json:"namespace"`
	ExecutorID     string                                     `json:"executor_id"`
	WorkflowID     uuid.UUID                                  `json:"workflow_id"`
	Generation     int64                                      `json:"generation"`
	FencingToken   int64                                      `json:"fencing_token"`
	Execution      model.CapacityNativeWorkerExecutionProfile `json:"execution"`
	ExpiresAt      time.Time                                  `json:"expires_at"`
}

type CapacityNativeWorkerCommandStore struct{ Workers CapacityNativeWorkerStore }

// Authorize the fixed machine before a large body is read. The boolean does
// not reveal context IDs, policy or raw bytes; exact target resolution follows.
func (s CapacityNativeWorkerCommandStore) MachineAuthorized(ctx context.Context, instance, source string, capabilities map[string]bool) bool {
	if s.Workers.Capacity.DB == nil {
		return false
	}
	rows, err := s.Workers.Capacity.DB.QueryContext(ctx, `SELECT DISTINCT record#>>'{execution,ensure_capability}' FROM public.capacity_native_worker_command_contexts WHERE record#>>'{execution,adapter,manifest_id}'=$1 AND record#>>'{execution,sdk_source_commit}'=$2 LIMIT 33`, instance, source)
	if err != nil {
		return false
	}
	defer rows.Close()
	found, count := false, 0
	for rows.Next() {
		var capability string
		if rows.Scan(&capability) != nil {
			return false
		}
		count++
		if count > 32 {
			return false
		}
		found = found || capabilities[capability]
	}
	return rows.Err() == nil && found
}

func insertNativeWorkerCommandTx(ctx context.Context, tx *sql.Tx, s CapacityNativeWorkerStore, a model.CapacityNativeWorkerAttempt, parent model.CapacityIntent) error {
	if parent.LeaseExpiresAt == nil || !validCapacityExecutor(s.Capacity.ExecutorID) || s.Capacity.WorkflowID == uuid.Nil || parent.Assessment.Market == nil {
		return ErrCapacityConflict
	}
	expiry := *parent.LeaseExpiresAt
	if parent.Assessment.Market.ValidUntil.Before(expiry) {
		expiry = parent.Assessment.Market.ValidUntil
	}
	if a.QualificationValidUntil.Before(expiry) {
		expiry = a.QualificationValidUntil
	}
	for _, q := range parent.Assessment.Market.Profiles {
		if q.Profile == a.Profile && q.ValidUntil.Before(expiry) {
			expiry = q.ValidUntil
		}
	}
	if !expiry.After(a.CreatedAt) {
		return ErrCapacityConflict
	}
	c := nativeWorkerCommandContext{AttemptID: a.ID, PolicyID: a.PolicyID, PolicyChecksum: a.PolicyChecksum, Namespace: a.Namespace, ExecutorID: s.Capacity.ExecutorID, WorkflowID: s.Capacity.WorkflowID, Generation: a.Generation, FencingToken: a.FencingToken, Execution: a.Execution, ExpiresAt: expiry}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_command_contexts(attempt_id,record) VALUES($1,$2)`, a.ID, raw)
	return err
}

func (s CapacityNativeWorkerCommandStore) context(ctx context.Context, id uuid.UUID) (nativeWorkerCommandContext, error) {
	var c nativeWorkerCommandContext
	if s.Workers.Capacity.DB == nil {
		return c, ErrCapacityDisabled
	}
	var raw []byte
	err := s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, id).Scan(&raw)
	if err != nil || json.Unmarshal(raw, &c) != nil || c.AttemptID != id || !validCapacityExecutor(c.ExecutorID) || c.WorkflowID == uuid.Nil || c.PolicyID == uuid.Nil || c.Namespace == "" || c.ExpiresAt.IsZero() {
		return nativeWorkerCommandContext{}, ErrCapacityMutationAuthorization
	}
	return c, nil
}

func commandCallerMatches(c nativeWorkerCommandContext, caller model.CapacityNativeWorkerCommandCaller) bool {
	return caller.BindingName == c.Execution.BindingName && caller.InstanceID == c.Execution.Adapter.ManifestID && caller.SDKSourceCommit == c.Execution.SDKSourceCommit && caller.Capability == c.Execution.EnsureCapability
}

// Resolve uses an already authenticated exact machine instance/capability.
// Caller cannot choose policy, namespace, controller executor or workflow.
func (s CapacityNativeWorkerCommandStore) Resolve(ctx context.Context, id uuid.UUID, binding, instance, source string, capabilities map[string]bool) (model.Manifest, model.CapacityNativeWorkerCommandCaller, error) {
	var caller model.CapacityNativeWorkerCommandCaller
	c, err := s.context(ctx, id)
	if err != nil || binding != c.Execution.BindingName || instance != c.Execution.Adapter.ManifestID || source != c.Execution.SDKSourceCommit || !capabilities[c.Execution.EnsureCapability] {
		return model.Manifest{}, caller, ErrCapacityMutationAuthorization
	}
	policy, err := GetManifestByID(ctx, s.Workers.Capacity.DB, c.PolicyID)
	if err != nil || policy.Kind != "capacity_policy" || policy.Metadata.Namespace != c.Namespace || policy.Checksum != c.PolicyChecksum {
		return model.Manifest{}, caller, ErrCapacityMutationAuthorization
	}
	caller = model.CapacityNativeWorkerCommandCaller{BindingName: binding, InstanceID: instance, SDKSourceCommit: source, Capability: c.Execution.EnsureCapability}
	return policy, caller, nil
}

func (s CapacityNativeWorkerCommandStore) bound(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerCommandCaller) (CapacityNativeWorkerStore, nativeWorkerCommandContext, model.CapacityNativeWorkerAttempt, error) {
	var a model.CapacityNativeWorkerAttempt
	c, err := s.context(ctx, id)
	if err != nil || !commandCallerMatches(c, caller) || c.PolicyID != policy.ID || c.PolicyChecksum != policy.Checksum || c.Namespace != policy.Metadata.Namespace {
		return s.Workers, c, a, ErrCapacityMutationAuthorization
	}
	a, err = s.Workers.Read(ctx, policy, id)
	if err != nil || a.PolicyChecksum != c.PolicyChecksum || a.Generation != c.Generation || a.FencingToken != c.FencingToken || !capacity.NativeWorkerSameExecution(a.Execution, c.Execution) {
		return s.Workers, c, a, ErrCapacityMutationAuthorization
	}
	w := s.Workers
	w.Capacity.ExecutorID, w.Capacity.WorkflowID = c.ExecutorID, c.WorkflowID
	w.commandExpiresAt = c.ExpiresAt
	return w, c, a, nil
}

func nativeWorkerCommandRead(c nativeWorkerCommandContext, a model.CapacityNativeWorkerAttempt) model.CapacityNativeWorkerCommand {
	return model.CapacityNativeWorkerCommand{Schema: model.CapacityNativeWorkerCommandSchema, AttemptID: a.ID, BindingName: c.Execution.BindingName, AttemptState: a.State, ExpiresAt: c.ExpiresAt, SDKSourceCommit: c.Execution.SDKSourceCommit, ExecutionScopeSHA256: c.Execution.ScopeSHA256}
}

func (s CapacityNativeWorkerCommandStore) Read(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerCommandCaller) (model.CapacityNativeWorkerCommand, error) {
	w, c, a, err := s.bound(ctx, policy, id, caller)
	if err != nil {
		return model.CapacityNativeWorkerCommand{}, err
	}
	out := nativeWorkerCommandRead(c, a)
	// Historical reads survive unavailable/expired authority, without granting a
	// mutation. Fresh protected observations stay outside the transaction.
	authenticated, authErr := w.authenticate(ctx, policy)
	if authErr != nil || a.State != "reserved" {
		return out, nil
	}
	err = authenticated.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		if !c.ExpiresAt.After(now) {
			return ErrCapacityLease
		}
		parent, e := authenticated.current(ctx, tx, policy, p, model.CapacityNativeWorkerAuthority{Generation: c.Generation, FencingToken: c.FencingToken}, now)
		if e != nil {
			return e
		}
		budget, e := nativeAttemptCreationBudget(parent, now)
		if e != nil {
			return e
		}
		count, e := nativeAttemptGenerationCountTx(ctx, tx, policy, parent.Generation)
		if e != nil {
			return e
		}
		current, _, e := nativeAttemptLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		if current.State != "reserved" || current.Profile != parent.Decision.Profile || count < 1 || count > budget {
			return ErrCapacityConflict
		}
		out.Redeemable = true
		return nil
	})
	if err != nil {
		out.Redeemable = false
	}
	return out, nil
}

func (s CapacityNativeWorkerCommandStore) Redeem(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerCommandCaller) (model.CapacityNativeWorkerCommand, error) {
	w, c, a, err := s.bound(ctx, policy, id, caller)
	if err != nil {
		return model.CapacityNativeWorkerCommand{}, err
	}
	permit, err := w.Redeem(ctx, policy, model.CapacityNativeWorkerAuthority{Generation: c.Generation, FencingToken: c.FencingToken}, id)
	if err != nil {
		return model.CapacityNativeWorkerCommand{}, err
	}
	out := nativeWorkerCommandRead(c, a)
	out.AttemptState, out.MutationPermitted = "send_started", true
	out.Profile, out.Provider, out.Region = a.Profile, a.Provider, a.Region
	out.LaunchSHA256, out.OverlayIPv4 = permit.LaunchSHA256, permit.OverlayIPv4
	exec := c.Execution
	out.Execution = &exec
	out.PublicLaunchJSON = permit.PublicLaunchJSON
	return out, nil
}

// Original transport bytes are private and immutable. A duplicate callback may
// repeat only the same captured truth; it never sends or replaces a response.
func persistNativeWorkerOriginal(ctx context.Context, db *sql.DB, id uuid.UUID, original model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerOriginalReturn, string, error) {
	if len(original.Wire) > 1<<20 {
		return model.CapacityNativeWorkerOriginalReturn{}, "", ErrCapacityConflict
	}
	if original.Wire == nil {
		original.Wire = []byte{}
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(original.Wire))
	_, err := db.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_original_returns(attempt_id,wire,raw_sha256,capture_complete,error_class) VALUES($1,$2,$3,$4,$5) ON CONFLICT(attempt_id) DO NOTHING`, id, original.Wire, digest, original.CaptureComplete, original.ErrorClass)
	if err != nil {
		return model.CapacityNativeWorkerOriginalReturn{}, "", err
	}
	var actual model.CapacityNativeWorkerOriginalReturn
	var sha string
	err = db.QueryRowContext(ctx, `SELECT wire,raw_sha256,capture_complete,error_class FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1`, id).Scan(&actual.Wire, &sha, &actual.CaptureComplete, &actual.ErrorClass)
	return actual, sha, err
}

func (s CapacityNativeWorkerCommandStore) Receive(ctx context.Context, policy model.Manifest, caller model.CapacityNativeWorkerCommandCaller, received model.CapacityNativeWorkerCommandReceive) error {
	w, c, a, err := s.bound(ctx, policy, received.AttemptID, caller)
	if err != nil || received.BindingName != c.Execution.BindingName {
		return ErrCapacityMutationAuthorization
	}
	if a.State == "reserved" || len(received.OriginalReturn) > 1<<20 {
		return ErrCapacityConflict
	}
	switch received.ErrorClass {
	case "", "ORIGINAL_TRANSPORT_UNCERTAIN", "ORIGINAL_CAPTURE_BOUND_EXCEEDED":
	default:
		return ErrCapacityConflict
	}
	if received.ErrorClass != "" && received.CaptureComplete {
		return ErrCapacityConflict
	}
	original := model.CapacityNativeWorkerOriginalReturn{Wire: received.OriginalReturn, CaptureComplete: received.CaptureComplete, ErrorClass: received.ErrorClass}
	actual, _, err := persistNativeWorkerOriginal(ctx, w.Capacity.DB, a.ID, original)
	if err != nil {
		return err
	}
	if string(actual.Wire) != string(original.Wire) || actual.CaptureComplete != original.CaptureComplete || actual.ErrorClass != original.ErrorClass {
		return ErrCapacityConflict
	}
	// Private custody has committed. Only historical ACK/unknown creator truth
	// may now be qualified through the installed GET-only runtime. Failures cannot
	// erase that custody or turn the callback into registry/admission authority.
	if a.State == "send_started" || a.State == "unknown" {
		_, _ = w.Record(ctx, policy, model.CapacityNativeWorkerAuthority{Generation: c.Generation, FencingToken: c.FencingToken}, a.ID)
	}
	return nil
}
