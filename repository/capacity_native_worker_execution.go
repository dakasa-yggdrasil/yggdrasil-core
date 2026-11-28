package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// NativeWorkerExecutionSession holds only restored private ledger authority.
// It is borrowed synchronously by one protected owner callback, never an API
// DTO or a transferable lease. A restarted workflow's random executor cannot
// replace the executor committed with its original command114.
type NativeWorkerExecutionSession struct {
	workers   CapacityNativeWorkerStore
	policy    model.Manifest
	authority model.CapacityNativeWorkerAuthority
}

func (NativeWorkerExecutionSession) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_execution":"redacted"}`), nil
}
func (NativeWorkerExecutionSession) String() string     { return "[private Native execution]" }
func (s NativeWorkerExecutionSession) GoString() string { return s.String() }

// OpenNativeExecution restores an existing command identity. Without a
// command, only the still-owning, freshly claimed invocation can reserve its
// first child; another executor cannot adopt the claim after a crash.
func (s CapacityNativeWorkerStore) OpenNativeExecution(ctx context.Context, policy model.Manifest, workflowID uuid.UUID) (*NativeWorkerExecutionSession, error) {
	if workflowID == uuid.Nil || s.Capacity.WorkflowID != workflowID {
		return nil, ErrCapacityMutationAuthorization
	}
	bound, err := s.authenticate(ctx, policy)
	if err != nil {
		return nil, err
	}
	var authority model.CapacityNativeWorkerAuthority
	err = bound.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		parent, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
		if err != nil {
			return err
		}
		if parent.PolicyID != policy.ID || parent.PolicyChecksum != policy.Checksum || parent.Phase != "preparing" || parent.Decision.Profile != parent.BaselineSnapshot.Profile || parent.Decision.Action != "expand" {
			return ErrCapacityConflict
		}
		rows, err := tx.QueryContext(ctx, `SELECT c.record,a.attempt FROM public.capacity_native_worker_attempts a LEFT JOIN public.capacity_native_worker_command_contexts c ON a.id=c.attempt_id WHERE a.policy_id=$1 AND a.generation=$2 AND a.fencing_token=$3 ORDER BY a.id LIMIT 100001`, policy.ID, parent.Generation, parent.FencingToken)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			var raw, attemptRaw []byte
			var c nativeWorkerCommandContext
			var a model.CapacityNativeWorkerAttempt
			if err = rows.Scan(&raw, &attemptRaw); err != nil {
				break
			}
			count++
			if count > 100000 || json.Unmarshal(raw, &c) != nil || json.Unmarshal(attemptRaw, &a) != nil || c.AttemptID != a.ID || !capacity.NativeWorkerSameExecution(c.Execution, a.Execution) || c.ExpiresAt.IsZero() || a.SourceCommit != p.NativeWorkerLifecycleBinding.SourceCommit || c.PolicyID != policy.ID || c.PolicyChecksum != policy.Checksum || c.Namespace != policy.Metadata.Namespace || c.Generation != parent.Generation || c.FencingToken != parent.FencingToken || c.WorkflowID != workflowID || !validCapacityExecutor(c.ExecutorID) || c.ExecutorID != parent.LeaseExecutorID {
				err = ErrCapacityMutationAuthorization
				break
			}
			bound.Capacity.ExecutorID = c.ExecutorID
		}
		if err == nil {
			err = rows.Err()
		}
		closeErr := rows.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		authority = model.CapacityNativeWorkerAuthority{Generation: parent.Generation, FencingToken: parent.FencingToken}
		_, err = bound.current(ctx, tx, policy, p, authority, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &NativeWorkerExecutionSession{workers: bound, policy: policy, authority: authority}, nil
}

// ClaimDispatch commits only permission for this one synchronous SDK call. An
// existing row is uncertainty/receiving, never proof the SDK ran or completed.
// A lost commit outcome yields an error and MUST NOT be followed by an RPC.
func (s *NativeWorkerExecutionSession) ClaimDispatch(ctx context.Context, id uuid.UUID, operation string, target uuid.UUID) (bool, error) {
	if s == nil || target == uuid.Nil || (operation != "provider_create" && operation != "registry_phase" && operation != "network_install") {
		return false, ErrCapacityDisabled
	}
	bound, err := s.workers.authenticate(ctx, s.policy)
	if err != nil {
		return false, err
	}
	won := false
	err = bound.tx(ctx, s.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		if _, err := bound.current(ctx, tx, s.policy, p, s.authority, now); err != nil {
			return err
		}
		a, _, err := nativeAttemptLoadTx(ctx, tx, s.policy, id)
		if err != nil {
			return err
		}
		if a.Generation != s.authority.Generation || a.FencingToken != s.authority.FencingToken {
			return ErrCapacityConflict
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_native_worker_execution_dispatches WHERE target_id=$1 AND operation=$2)`, target, operation).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return nil
		}
		switch operation {
		case "provider_create":
			if target != a.ID || a.State != "reserved" {
				return ErrCapacityConflict
			}
		case "registry_phase":
			r, err := nativePhaseLoadTx(ctx, tx, s.policy, target)
			if err != nil || r.Context.AttemptID != a.ID || r.Context.PhaseState != "issued" || r.ExecutorID != bound.Capacity.ExecutorID || r.WorkflowID != bound.Capacity.WorkflowID || !nativePhaseWriterScopeMatches(r) {
				return ErrCapacityConflict
			}
		case "network_install":
			var targetAttempt uuid.UUID
			var state, action string
			if err = tx.QueryRowContext(ctx, `SELECT attempt_id,state,action FROM public.capacity_native_worker_network_permits WHERE id=$1 AND policy_id=$2 FOR UPDATE`, target, s.policy.ID).Scan(&targetAttempt, &state, &action); err != nil || targetAttempt != a.ID || state != "issued" || action != "install" {
				return ErrCapacityConflict
			}
		}
		raw, err := json.Marshal(a)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_execution_dispatches(target_id,operation,attempt_id,policy_id,namespace,generation,fencing_token,source_commit,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, target, operation, a.ID, a.PolicyID, a.Namespace, a.Generation, a.FencingToken, a.SourceCommit, raw)
		won = err == nil
		return err
	})
	if err != nil {
		return false, err
	}
	return won, nil
}

// Phase reuses the exact consumed action slot. It never calls Issue again for
// issued/redeemed/unknown/observed work. Reconcile below is GET-only.
func (s *NativeWorkerExecutionSession) Phase(ctx context.Context, runtime NativeWorkerPhaseRuntime, id uuid.UUID, action string) (model.CapacityNativeWorkerPhasePermit, error) {
	var zero model.CapacityNativeWorkerPhasePermit
	if s == nil || runtime == nil || (action != "register" && action != "admit_registry" && action != "release_quarantine") {
		return zero, ErrCapacityDisabled
	}
	var raw []byte
	err := s.workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1 AND policy_id=$2 AND action=$3 AND state<>'no_effect'`, id, s.policy.ID, action).Scan(&raw)
	if err == nil {
		var r nativeWorkerPhaseRecord
		if json.Unmarshal(raw, &r) != nil || !nativePhaseWriterScopeMatches(r) || r.ExecutorID != s.workers.Capacity.ExecutorID || r.WorkflowID != s.workers.Capacity.WorkflowID || r.Context.IntentGeneration != s.authority.Generation || r.Context.FencingToken != s.authority.FencingToken {
			return zero, ErrCapacityConflict
		}
		return phaseContext(r), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, err
	}
	return (CapacityNativeWorkerPhaseStore{Workers: s.workers, Runtime: runtime, Enabled: true}).Issue(ctx, s.policy, s.authority, id, action)
}

func (s *NativeWorkerExecutionSession) ReconcilePhase(ctx context.Context, runtime NativeWorkerPhaseRuntime, id uuid.UUID) (model.CapacityNativeWorkerPhasePermit, error) {
	var zero model.CapacityNativeWorkerPhasePermit
	if s == nil {
		return zero, ErrCapacityDisabled
	}
	var raw []byte
	var r nativeWorkerPhaseRecord
	if err := s.workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE id=$1 AND policy_id=$2`, id, s.policy.ID).Scan(&raw); err != nil {
		return zero, err
	}
	if json.Unmarshal(raw, &r) != nil || r.ExecutorID != s.workers.Capacity.ExecutorID || r.WorkflowID != s.workers.Capacity.WorkflowID || !nativePhaseWriterScopeMatches(r) {
		return zero, ErrCapacityConflict
	}
	caller := model.CapacityNativeWorkerPhaseCaller{Adapter: r.Writer.Adapter, PrincipalID: r.Writer.PrincipalID, BindingName: r.Writer.BindingName, SourceCommit: r.Writer.SourceCommit}
	return (CapacityNativeWorkerPhaseStore{Workers: s.workers, Runtime: runtime, Enabled: true}).Reconcile(ctx, s.policy, id, caller)
}

func (s *NativeWorkerExecutionSession) Network(ctx context.Context, runtime NativeWorkerNetworkRuntime, id uuid.UUID) (model.CapacityNativeWorkerNetworkGrant, error) {
	var zero model.CapacityNativeWorkerNetworkGrant
	if s == nil || runtime == nil {
		return zero, ErrCapacityDisabled
	}
	var raw []byte
	var r nativeWorkerNetworkRecord
	err := s.workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_network_permits WHERE attempt_id=$1 AND policy_id=$2 AND action='install' AND state<>'no_effect'`, id, s.policy.ID).Scan(&raw)
	if err == nil {
		if json.Unmarshal(raw, &r) != nil || r.ExecutorID != s.workers.Capacity.ExecutorID || r.WorkflowID != s.workers.Capacity.WorkflowID || r.Context.IntentGeneration != s.authority.Generation || r.Context.FencingToken != s.authority.FencingToken {
			return zero, ErrCapacityConflict
		}
		return nativeNetworkContext(r), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, err
	}
	return (CapacityNativeWorkerNetworkStore{Workers: s.workers, Runtime: runtime, Enabled: true}).Begin(ctx, s.policy, id, "install")
}

func (s *NativeWorkerExecutionSession) ReconcileNetwork(ctx context.Context, runtime NativeWorkerNetworkRuntime, id uuid.UUID) (model.CapacityNativeWorkerNetworkGrant, error) {
	var zero model.CapacityNativeWorkerNetworkGrant
	if s == nil {
		return zero, ErrCapacityDisabled
	}
	store := CapacityNativeWorkerNetworkStore{Workers: s.workers, Runtime: runtime, Enabled: true}
	r, err := store.load(ctx, s.policy, id)
	if err != nil {
		return zero, err
	}
	if r.ExecutorID != s.workers.Capacity.ExecutorID || r.WorkflowID != s.workers.Capacity.WorkflowID {
		return zero, ErrCapacityConflict
	}
	w := r.Binding.Writer
	caller := CapacityNativeWorkerNetworkCaller{PrincipalID: w.PrincipalID, InstanceID: w.AdapterID, SystemSourceCommit: w.SystemSourceCommit, BindingName: w.BindingName, Capability: capacity.NativeWorkerNetworkInstall}
	return store.Reconcile(ctx, s.policy, id, caller)
}

// Historical receiving retains real original/ACK truth after a parent expires.
// It cannot issue, redeem, register, admit, replace a child or renew authority.
func (s CapacityNativeWorkerStore) ReceiveNativeExecution(ctx context.Context, policy model.Manifest) error {
	if s.Capacity.DB == nil || s.Runtime == nil {
		return ErrCapacityDisabled
	}
	rows, err := s.Capacity.DB.QueryContext(ctx, `SELECT id FROM public.capacity_native_worker_attempts WHERE policy_id=$1 AND namespace=$2 AND state IN ('send_started','unknown') ORDER BY id LIMIT 100001`, policy.ID, policy.Metadata.Namespace)
	if err != nil {
		return err
	}
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
		if len(ids) > 100000 {
			err = ErrCapacityConflict
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, id := range ids {
		if _, err = s.Record(ctx, policy, model.CapacityNativeWorkerAuthority{}, id); err != nil && !errors.Is(err, ErrCapacityNativeReturnPending) {
			return err
		}
	}
	return nil
}

// The whole generation is inspected under the parent lock. A different epoch,
// profile, or unresolved historical child cannot be hidden by a fresh claim.
func nativeExecutionChildrenTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, parent model.CapacityIntent) ([]model.CapacityNativeWorkerAttempt, error) {
	rows, err := tx.QueryContext(ctx, `SELECT attempt FROM public.capacity_native_worker_attempts WHERE policy_id=$1 ORDER BY id LIMIT 100001 FOR UPDATE`, policy.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.CapacityNativeWorkerAttempt{}
	count := 0
	for rows.Next() {
		var raw []byte
		var a model.CapacityNativeWorkerAttempt
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		count++
		if count > 100000 || json.Unmarshal(raw, &a) != nil {
			return nil, ErrCapacityConflict
		}
		if a.Generation != parent.Generation || a.FencingToken != parent.FencingToken {
			if a.State != "admitted" && a.State != "absent" {
				return nil, ErrCapacityConflict
			}
			continue
		}
		if a.Profile != parent.Decision.Profile || a.PolicyChecksum != policy.Checksum {
			return nil, ErrCapacityConflict
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func nativeExecutionPending(children []model.CapacityNativeWorkerAttempt) (*model.CapacityNativeWorkerAttempt, error) {
	var pending *model.CapacityNativeWorkerAttempt
	for _, a := range children {
		switch a.State {
		case "admitted", "absent":
		case "reserved", "send_started", "unknown", "acknowledged", "registered", "aborting":
			if pending != nil {
				return nil, ErrCapacityConflict
			}
			copied := a
			pending = &copied
		default:
			return nil, ErrCapacityConflict
		}
	}
	return pending, nil
}

// nativeExecutionPoolTx preserves every baseline identity and admits only this
// generation's exact Ready children as additions. No label or count alone can
// replace the original pool, birth, Node UID or provider ID.
func nativeExecutionPoolTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, parent model.CapacityIntent, children []model.CapacityNativeWorkerAttempt, pool *model.CapacityNativeWorkerPoolObservation, now time.Time) (model.CapacitySnapshot, error) {
	var zero model.CapacitySnapshot
	snapshot, err := capacity.NativeWorkerPoolSnapshot(p, pool, now)
	if err != nil || parent.Assessment.NativeWorkerPool == nil || snapshot.Profile != parent.Decision.Profile || parent.BaselineSnapshot.Profile != snapshot.Profile {
		return zero, ErrCapacityConflict
	}
	if err = marketNativeAttemptBirthsTx(ctx, tx, policy, p, pool); err != nil {
		return zero, err
	}
	known := map[string]string{}
	for _, n := range parent.Assessment.NativeWorkerPool.Nodes {
		known[n.NodeUID] = n.ProviderID
	}
	if len(known) != parent.BaselineSnapshot.Units {
		return zero, ErrCapacityConflict
	}
	for _, a := range children {
		if a.State != "admitted" {
			continue
		}
		if a.Physical == nil || a.NodeUID == "" || !capacity.NativeWorkerPhysicalValid(a, *a.Physical) {
			return zero, ErrCapacityConflict
		}
		if _, exists := known[a.NodeUID]; exists {
			return zero, ErrCapacityConflict
		}
		known[a.NodeUID] = a.Physical.ProviderID
	}
	if len(known) != len(pool.Nodes) {
		return zero, ErrCapacityConflict
	}
	for _, n := range pool.Nodes {
		if known[n.NodeUID] != n.ProviderID {
			return zero, ErrCapacityConflict
		}
		delete(known, n.NodeUID)
	}
	if len(known) != 0 {
		return zero, ErrCapacityConflict
	}
	return snapshot, nil
}

var errNativeExecutionNeedsPool = errors.New("protected current useful pool required")

// Next reuses the original pending child. Only when all prior children are
// terminal does it read the real useful pool, then recheck everything under
// the same market/dimension/parent/child locks before reserving another slot.
func (s *NativeWorkerExecutionSession) Next(ctx context.Context) (model.CapacityNativeWorkerAttempt, error) {
	var zero model.CapacityNativeWorkerAttempt
	if s == nil {
		return zero, ErrCapacityDisabled
	}
	var out model.CapacityNativeWorkerAttempt
	lookup := func(pool *model.CapacityNativeWorkerPoolObservation) error {
		bound, err := s.workers.authenticate(ctx, s.policy)
		if err != nil {
			return err
		}
		return bound.tx(ctx, s.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
			parent, err := bound.current(ctx, tx, s.policy, p, s.authority, now)
			if err != nil {
				return err
			}
			children, err := nativeExecutionChildrenTx(ctx, tx, s.policy, parent)
			if err != nil {
				return err
			}
			pending, err := nativeExecutionPending(children)
			if err != nil {
				return err
			}
			if pending != nil {
				out = *pending
				return nil
			}
			if pool == nil {
				return errNativeExecutionNeedsPool
			}
			snapshot, err := nativeExecutionPoolTx(ctx, tx, s.policy, p, parent, children, pool, now)
			if err != nil {
				return err
			}
			if snapshot.Units >= parent.Decision.Units {
				return sql.ErrNoRows
			}
			return bound.reserveNativeWorkerTx(ctx, tx, s.policy, p, s.authority, now, &out)
		})
	}
	err := lookup(nil)
	if !errors.Is(err, errNativeExecutionNeedsPool) {
		return out, err
	}
	if s.workers.Capacity.MarketObserver == nil {
		return zero, ErrCapacityDisabled
	}
	_, pool, err := s.workers.Capacity.MarketObserver(ctx, s.policy)
	if err != nil {
		return zero, err
	}
	if err = lookup(pool); err != nil {
		return zero, err
	}
	return out, nil
}

// Pending never reserves a child. The admission-only workflow uses this path.
func (s *NativeWorkerExecutionSession) Pending(ctx context.Context) (model.CapacityNativeWorkerAttempt, error) {
	var out model.CapacityNativeWorkerAttempt
	if s == nil {
		return out, ErrCapacityDisabled
	}
	bound, err := s.workers.authenticate(ctx, s.policy)
	if err != nil {
		return out, err
	}
	err = bound.tx(ctx, s.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		parent, err := bound.current(ctx, tx, s.policy, p, s.authority, now)
		if err != nil {
			return err
		}
		children, err := nativeExecutionChildrenTx(ctx, tx, s.policy, parent)
		if err != nil {
			return err
		}
		a, err := nativeExecutionPending(children)
		if err != nil {
			return err
		}
		if a == nil {
			return sql.ErrNoRows
		}
		out = *a
		return nil
	})
	return out, err
}

// Renew preserves all immutable command/quote/qualification deadlines and
// refuses an expired parent. It never changes generation or fencing token.
func (s *NativeWorkerExecutionSession) Renew(ctx context.Context) error {
	if s == nil {
		return ErrCapacityDisabled
	}
	return s.workers.Renew(ctx, s.policy, s.authority)
}

func (s *NativeWorkerExecutionSession) Record(ctx context.Context, id uuid.UUID) (model.CapacityNativeWorkerAttempt, error) {
	if s == nil {
		return model.CapacityNativeWorkerAttempt{}, ErrCapacityDisabled
	}
	return s.workers.Record(ctx, s.policy, s.authority, id)
}

// Complete is a Native-only closure. It uses neither generic HPA Advance nor
// caller-supplied Healthy/Inflight/count. Market ledger and pool/birth proofs
// are rejoined inside the normal parent transaction before promotion.
func (s *NativeWorkerExecutionSession) Complete(ctx context.Context) (model.CapacityIntent, error) {
	if s == nil || s.workers.Capacity.MarketObserver == nil {
		return model.CapacityIntent{}, ErrCapacityDisabled
	}
	bound, err := s.workers.authenticate(ctx, s.policy)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	market, pool, err := bound.Capacity.MarketObserver(ctx, s.policy)
	if err != nil {
		return model.CapacityIntent{}, err
	}
	return bound.Capacity.transactionWithTx(ctx, s.policy, func(p model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time, tx *sql.Tx) (model.CapacityIntent, string, error) {
		if old == nil {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		parent, err := bound.current(ctx, tx, s.policy, p, s.authority, now)
		if err != nil {
			return model.CapacityIntent{}, "", err
		}
		children, err := nativeExecutionChildrenTx(ctx, tx, s.policy, parent)
		if err != nil {
			return model.CapacityIntent{}, "", err
		}
		pending, err := nativeExecutionPending(children)
		if err != nil || pending != nil {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		budget, err := nativeAttemptCreationBudget(parent, now)
		if err != nil || len(children) != budget {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		snapshot, err := nativeExecutionPoolTx(ctx, tx, s.policy, p, parent, children, pool, now)
		if err != nil || snapshot.Units != parent.Decision.Units {
			return model.CapacityIntent{}, "", ErrCapacityConflict
		}
		assessment := parent.Assessment
		assessment.Snapshot, assessment.NativeWorkerPool, assessment.Market = snapshot, pool, market
		if _, err = bound.Capacity.marketLedgerTx(ctx, tx, s.policy, p, assessment, now); err != nil {
			return model.CapacityIntent{}, "", err
		}
		next := parent
		next.Phase = "promoted"
		next.Assessment = assessment
		next.UpdatedAt = now
		next.LeaseOwner, next.LeaseExecutorID, next.LeaseExpiresAt = "", "", nil
		next.Decision.ExecutionPermitted = false
		next.Decision.Clock.LastActionAt = now
		next.Decision.Clock.UpSince, next.Decision.Clock.DownSince = time.Time{}, time.Time{}
		return next, "", nil
	})
}

// Mechanical extraction of Reserve's original transaction body. Both callers
// authenticate before tx; lookup/reservation now share the same parent lock.
func (s CapacityNativeWorkerStore) reserveNativeWorkerTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, authority model.CapacityNativeWorkerAuthority, now time.Time, out *model.CapacityNativeWorkerAttempt) error {
	parent, err := s.current(ctx, tx, policy, p, authority, now)
	if err != nil {
		return err
	}
	budget, err := nativeAttemptCreationBudget(parent, now)
	if err != nil {
		return err
	}
	count, err := nativeAttemptGenerationCountTx(ctx, tx, policy, parent.Generation)
	if err != nil {
		return err
	}
	// Even an absent/expired prior child consumes its original send budget.
	// Another attempt requires a genuinely new parent Claim/reservation.
	if count >= budget {
		return ErrCapacityConflict
	}
	var exec model.CapacityNativeWorkerExecutionProfile
	var profile model.CapacityProfile
	var bound model.CapacityMarketProfileBinding
	var native model.CapacityNativeWorkerProfileBinding
	var quote model.CapacityMarketProfileQuote
	for _, v := range p.NativeWorkerLifecycleBinding.Profiles {
		if v.Profile == parent.Decision.Profile {
			exec = v
		}
	}
	for _, v := range p.Profiles {
		if v.Name == parent.Decision.Profile {
			profile = v
		}
	}
	for _, v := range p.MarketBinding.Profiles {
		if v.Profile == profile.Name {
			bound = v
		}
	}
	for _, v := range p.NativeWorkerPoolBinding.Profiles {
		if v.Profile == profile.Name {
			native = v
		}
	}
	for _, v := range parent.Assessment.Market.Profiles {
		if v.Profile == profile.Name {
			quote = v
		}
	}
	if exec.Profile == "" || !quote.ValidUntil.After(now) {
		return ErrCapacityConflict
	}
	reservation, fixed, err := capacity.NativeWorkerUnitReservation(capacity.MarketProfile{Profile: profile, Quote: quote, Currency: p.Currency, HorizonSeconds: p.MarketBinding.HorizonSeconds, BudgetScope: p.MarketBinding.BudgetScope}, now)
	if err != nil {
		return err
	}
	ip, err := allocateNativeOverlayTx(ctx, tx, exec)
	if err != nil {
		return err
	}
	*out = model.CapacityNativeWorkerAttempt{ID: uuid.New(), PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: parent.Generation, FencingToken: parent.FencingToken, PoolUID: p.NativeWorkerPoolBinding.PoolUID, PoolEpoch: p.NativeWorkerPoolBinding.ExpectedPoolEpoch, Registry: p.NativeWorkerPoolBinding.RegistryRef, Profile: profile.Name, Provider: profile.Provider, Region: profile.Region, ProviderIDPrefix: native.ProviderIDPrefix, SourceCommit: p.NativeWorkerLifecycleBinding.SourceCommit, Execution: exec, NetworkBindingSHA256: bound.NetworkBindingSHA, PhysicalSpecSHA256: bound.PhysicalSpecSHA256, OverlayIPv4: ip, State: "reserved", Revision: 1, Reservation: reservation, GroupFixedCostMicros: fixed, CreatedAt: now, UpdatedAt: now}
	out.QualificationEvidenceSHA256 = quote.QualificationEvidenceSHA256
	out.QualificationValidUntil = quote.ValidationValidUntil
	out.IntentSHA256 = capacity.NativeWorkerIntentSHA(parent, out.PoolUID, out.PoolEpoch)
	prepared, err := s.Runtime.Prepare(*out) // Pure protected Source, explicitly no WAN.
	if err != nil {
		return ErrCapacityConflict
	}
	if err = capacity.ValidateNativeWorkerLaunch(*out, prepared); err != nil {
		return err
	}
	out.LaunchSHA256 = fmt.Sprintf("%x", sha256.Sum256(prepared.PublicJSON))
	if err = nativeAttemptWriteTx(ctx, tx, *out, nil, true, prepared.PublicJSON); err != nil {
		return err
	}
	return insertNativeWorkerCommandTx(ctx, tx, s, *out, parent)
}
