package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const failedExpansionTerminalReconcileSchema = "failed_expansion_terminal_readonly_reconcile_v1"

// The terminal read is historical provenance, not fresh capacity evidence.
// Every new epoch still obtains its own inventory and initial useful canaries.
func (s CapacityStore) failedExpansionTerminalReconcileTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, id string) (FailedUnwitnessedExpansionCleanup, FailedUnwitnessedExpansionCleanupEvent, string, error) {
	a, events, err := loadFailedExpansionTx(ctx, tx, id)
	if err != nil {
		return a, FailedUnwitnessedExpansionCleanupEvent{}, "", err
	}
	if len(events) == 0 {
		return a, FailedUnwitnessedExpansionCleanupEvent{}, "", ErrCapacityConflict
	}
	terminal := events[len(events)-1]
	if terminal.Stage != "terminal" || a.PolicyID == policy.ID.String() || a.Namespace != policy.Metadata.Namespace || a.Environment != p.Environment || a.Domain != p.Domain || a.Dimension != p.Dimension || a.WorkflowID != s.WorkflowID.String() || a.SurvivorCount < p.Floor || a.SurvivorCount != a.Slot-1 {
		return a, terminal, "", ErrCapacityConflict
	}
	if err = guestPolicyContinuityTx(ctx, tx, policy, p, a.PolicyID, a.PolicyChecksum); err != nil {
		return a, terminal, "", err
	}
	// Only the parent's typed terminal state changed. Its SDK, original failed
	// ACK, preregistration and absence of witness/enrollment remain exact.
	var good bool
	err = tx.QueryRowContext(ctx, `SELECT g.state='cleanup_closed' AND g.grant_record#>>'{grant,state}'='cleanup_closed' AND encode(sha256(convert_to(jsonb_set(g.grant_record,'{grant,state}','"settled"'::jsonb)::text,'UTF8')),'hex')=$2 AND encode(sha256(p.original_wire),'hex')=$3 AND encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')=$4 AND encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')=$5 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=p.id) AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=p.id) AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=p.id) AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=p.id) FROM (SELECT * FROM public.capacity_mutation_grants WHERE `+capacityGrantUndisposedSQL+`) g JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=$6 AND p.create_grant_id=g.id JOIN public.capacity_dispatch_jobs j ON j.id=$7 JOIN public.workflow_runs w ON w.id=j.run_id WHERE g.id=$1`, a.GrantID, a.OriginalGrantSHA256, a.OriginalPreregSHA256, a.OriginalDispatchSHA256, a.OriginalRunSHA256, a.PreregistrationID, a.JobID).Scan(&good)
	if err != nil {
		return a, terminal, "", err
	}
	if !good {
		return a, terminal, "", ErrCapacityConflict
	}
	child, err := failedExpansionChildTx(ctx, tx, a)
	if err != nil || child.Grant.State != "confirmed" {
		return a, terminal, "", ErrCapacityConflict
	}
	// The immutable observer receipt correctly retains SETTLED. Confirmation
	// changes only the actual child state; it does not remint that receipt.
	child.Grant.State = "settled"
	complete := false
	for i := len(events) - 2; i >= 0; i-- {
		if events[i].Stage != "absence_complete" {
			continue
		}
		var r FailedExpansionReadReturn
		if json.Unmarshal(events[i].Evidence, &r) != nil || !r.Complete || r.Pending || r.Receipt == nil || !reflect.DeepEqual(guestMutationReceiptV2(child), *r.Receipt) {
			return a, terminal, "", ErrCapacityConflict
		}
		proof, pending, e := failedExpansionReadContent(r, p, a)
		if e != nil || pending || !proof.ResourceAbsent || len(proof.AuxiliaryAbsent) != 2 {
			return a, terminal, "", ErrCapacityConflict
		}
		complete = true
		break
	}
	if !complete {
		return a, terminal, "", ErrCapacityConflict
	}
	if err = failedExpansionRosterCurrentTx(ctx, tx, a); err != nil {
		return a, terminal, "", err
	}
	var terminalSHA string
	if err = tx.QueryRowContext(ctx, `SELECT event_sha256 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=$1 AND sequence=$2 AND stage='terminal'`, a.ID, terminal.Sequence).Scan(&terminalSHA); err != nil {
		return a, terminal, "", err
	}
	return a, terminal, terminalSHA, nil
}

func bindFailedExpansionTerminalReconcile(s CapacityStore, m *model.CapacityFailedExpansionTerminalReconcile) CapacityStore {
	s.failedExpansionTerminalReconcile = m
	source := *s.guestReconcile
	source.mode = "provision" // Private canary/phase guards, never public provider mode.
	s.guestReconcile = &source
	return s
}

// This marker is a readonly ownership chain, never a successful old canary
// or a permission to resend a provider operation. Earlier immutable runs and
// canary rows stay in their original states.
func failedExpansionTerminalMarkerValid(m *model.CapacityFailedExpansionTerminalReconcile, current model.CapacityIntent) bool {
	if m == nil || m.Schema != failedExpansionTerminalReconcileSchema || m.TerminalGeneration < 1 || m.TerminalFence < 1 || m.ClaimGeneration != m.TerminalGeneration+1 || m.ClaimGeneration != current.Generation || m.ClaimFence != current.FencingToken || m.PreviousFence < m.TerminalFence || m.ClaimFence != m.PreviousFence+1 || !validCapacityExecutor(m.RunID) || !validCapacityExecutor(m.ExecutorID) {
		return false
	}
	if m.PreviousFence == m.TerminalFence {
		return m.PreviousRunID == "" && m.PreviousRunSHA256 == ""
	}
	return validCapacityExecutor(m.PreviousRunID) && m.PreviousRunID != m.RunID && capacity.ValidDigest(m.PreviousRunSHA256)
}

// A returned failure without its actual final ACK is still unclosed. Count
// every owning job first; a second malformed/unknown owner cannot be hidden by
// choosing the one row that happens to have a favorable returned shape.
func (s CapacityStore) failedExpansionTerminalFailedRunTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, runID string, now time.Time) ([]byte, error) {
	if !validCapacityExecutor(runID) {
		return nil, ErrCapacityConflict
	}
	rows, err := tx.QueryContext(ctx, `WITH jobs AS (SELECT * FROM public.capacity_dispatch_jobs WHERE run_id=$1::uuid) SELECT row_to_json(w)::text,w.result FROM public.workflow_runs w JOIN jobs j ON j.run_id=w.id WHERE (SELECT count(*) FROM jobs)=1 AND w.id=$1::uuid AND(w.workflow_id IS NULL OR w.workflow_id=$2) AND j.envelope::jsonb#>>'{workflow,id}'=$2::text AND w.status='failed' AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND w.finished_at=j.returned_at AND j.returned_at<=$3 AND j.finalization_ack_at>=j.returned_at AND j.finalization_ack_at<=$3 LIMIT 2`, runID, s.WorkflowID, now)
	if err != nil {
		return nil, err
	}
	var run, result []byte
	n := 0
	for rows.Next() {
		n++
		if err = rows.Scan(&run, &result); err != nil {
			rows.Close()
			return nil, err
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrCapacityConflict
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(runID), result); err != nil {
		return nil, err
	}
	return run, nil
}

func (s CapacityStore) failedExpansionTerminalClosedRunTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old model.CapacityIntent, now time.Time) ([]byte, error) {
	m := old.FailedExpansionTerminalReconcile
	if !failedExpansionTerminalMarkerValid(m, old) || m.RunID == s.OriginalRunID.String() {
		return nil, ErrCapacityConflict
	}
	run, err := s.failedExpansionTerminalFailedRunTx(ctx, tx, policy, p, m.RunID, now)
	if err != nil {
		return nil, err
	}
	// Expired old canaries remain accepted/held/unknown exactly as recorded.
	// New nonces never replay those requests or imply they had no effect. The
	// same publication budget/gap and Guest mutex are checked on every new Issue.
	var unsafe bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=$1 AND c.generation=$2 AND c.fence=$3 AND(c.original_deadline>=$4 OR c.executor_id<>$5 OR c.lease_owner<>$6 OR c.workflow_id<>$7))`, policy.ID, old.Generation, old.FencingToken, now, m.ExecutorID, old.LeaseOwner, s.WorkflowID).Scan(&unsafe)
	if err != nil {
		return nil, err
	}
	if unsafe {
		return nil, ErrCapacityConflict
	}
	return run, nil
}

// TryClaimFailedExpansionTerminalReconcile is called by the registered plan
// step only. An actual later compatible policy adopts the surviving roster;
// this is not Claim of the old failed expansion or a lease extension.
func (s CapacityStore) TryClaimFailedExpansionTerminalReconcile(ctx context.Context, policy model.Manifest, assessment model.CapacityAssessment) (CapacityStore, model.CapacityIntent, bool, error) {
	var zero model.CapacityIntent
	if s.OriginalRunID == uuid.Nil {
		return s, zero, false, nil
	}
	if s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || !validCapacityExecutor(s.ExecutorID) || !guestReconcileLive(ctx) {
		return s, zero, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, zero, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return s, zero, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return s, zero, false, err
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, p.MutationBindings); err != nil {
		return s, zero, false, err
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return s, zero, false, nil
	}
	if err != nil {
		return s, zero, false, err
	}
	// Ordinary/historical callers with neither typed selector do no M94 SQL.
	resuming := old.FailedExpansionTerminalReconcile != nil
	if !resuming && (old.FailedUnwitnessedExpansionCleanupID == "" || old.PolicyID == policy.ID) {
		return s, old, false, nil
	}
	if !s.ExecutionEnabled || !p.ExecutionEnabled || old.RecoveryOnly || old.FloorDegraded || old.OriginalNotifyWindow != nil || old.InstalledGuestReconcile != nil || old.Generation < 1 || old.Generation >= maxCapacityGeneration || old.FencingToken < 1 || old.FencingToken >= maxCapacityGeneration {
		return s, old, false, ErrCapacityConflict
	}
	if resuming {
		if !failedExpansionTerminalMarkerValid(old.FailedExpansionTerminalReconcile, old) || old.FailedUnwitnessedExpansionCleanupID != "" || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || (old.Phase != "preparing" && old.Phase != "prepared" && old.Phase != "canary") || old.LeaseOwner == "" || old.LeaseExecutorID != old.FailedExpansionTerminalReconcile.ExecutorID || old.LeaseExpiresAt == nil {
			return s, old, false, ErrCapacityConflict
		}
	} else if old.Phase != "hold" || old.LeaseOwner != "" || old.LeaseExecutorID != "" || old.LeaseExpiresAt != nil {
		return s, old, false, ErrCapacityConflict
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return s, old, false, err
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return s, old, false, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return s, old, false, err
	}
	cleanupID := old.FailedUnwitnessedExpansionCleanupID
	var previousRun []byte
	if resuming {
		if !now.After(*old.LeaseExpiresAt) {
			return s, old, false, ErrCapacityLease
		}
		previousRun, err = s.failedExpansionTerminalClosedRunTx(ctx, tx, policy, p, old, now)
		if err != nil {
			return s, old, false, err
		}
		cleanupID = old.FailedExpansionTerminalReconcile.CleanupID
	}
	a, terminal, terminalSHA, err := s.failedExpansionTerminalReconcileTx(ctx, tx, policy, p, cleanupID)
	if err != nil {
		return s, old, false, err
	}
	if old.Decision.Units != a.SurvivorCount {
		return s, old, false, ErrCapacityConflict
	}
	if resuming {
		m := old.FailedExpansionTerminalReconcile
		if m.TerminalEventSHA256 != terminalSHA || m.TerminalGeneration != terminal.Generation || m.TerminalFence != terminal.FencingToken || old.BaselineSnapshot.Units != a.SurvivorCount {
			return s, old, false, ErrCapacityConflict
		}
	} else if old.PolicyID.String() != a.PolicyID || old.PolicyChecksum != a.PolicyChecksum || old.Generation != terminal.Generation || old.FencingToken != terminal.FencingToken {
		return s, old, false, ErrCapacityConflict
	}
	if err = failedExpansionQuietTx(ctx, tx, a, s.OriginalRunID.String()); err != nil {
		return s, old, false, err
	}
	if err = capacity.ValidateAssessment(p, assessment, now); err != nil {
		return s, old, false, err
	}
	snapshot, err := capacity.GuestReconcileSnapshot(policy, p, s.guestReconcile.inventory, now)
	if err != nil || !reflect.DeepEqual(snapshot, assessment.Snapshot) || !sameCapacityResourceIdentity(old.Assessment.Snapshot, snapshot) || snapshot.Units != a.SurvivorCount {
		return s, old, false, ErrCapacityConflict
	}
	members, err := s.guestReconcileMembersTx(ctx, tx, policy, p, now, true)
	if err != nil || len(members) != a.SurvivorCount {
		return s, old, false, ErrCapacityConflict
	}
	decision, err := capacity.Assess(p, assessment, model.CapacityClockState{LastActionAt: old.Decision.Clock.LastActionAt}, now)
	if err != nil || decision.Action != "hold" || decision.Units != a.SurvivorCount || decision.Profile != snapshot.Profile || !capacityProfileCurrent(p, decision, now) {
		return s, old, false, ErrCapacityConflict
	}
	next := model.CapacityIntent{Namespace: policy.Metadata.Namespace, PolicyName: policy.Metadata.Name, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: old.Generation + 1, FencingToken: old.FencingToken + 1, Phase: "preparing", Decision: decision, Assessment: assessment, BaselineSnapshot: snapshot, UpdatedAt: now, LeaseOwner: uuid.NewString(), LeaseExecutorID: s.ExecutorID}
	expiry := now.Add(time.Duration(min(p.LeaseSeconds, 90)) * time.Second)
	next.LeaseExpiresAt = &expiry
	marker := &model.CapacityFailedExpansionTerminalReconcile{Schema: failedExpansionTerminalReconcileSchema, CleanupID: a.ID, TerminalEventSHA256: terminalSHA, TerminalGeneration: terminal.Generation, TerminalFence: terminal.FencingToken, ClaimGeneration: next.Generation, ClaimFence: next.FencingToken, PreviousFence: terminal.FencingToken, RunID: s.OriginalRunID.String(), ExecutorID: s.ExecutorID}
	if resuming {
		// Same real membership baseline/generation, new finite epoch. Preserve
		// the immediate genuine failed owner as lineage, never clear/rearm it.
		next = old
		next.Phase = "preparing"
		next.Assessment = assessment
		next.Decision = decision
		next.UpdatedAt = now
		next.FencingToken++
		next.LeaseOwner = uuid.NewString()
		next.LeaseExecutorID = s.ExecutorID
		next.LeaseExpiresAt = &expiry
		copied := *old.FailedExpansionTerminalReconcile
		copied.PreviousRunID = copied.RunID
		copied.PreviousRunSHA256 = capacity.BusinessCreationSHA256(previousRun)
		copied.PreviousFence = old.FencingToken
		copied.ClaimFence = next.FencingToken
		copied.RunID = s.OriginalRunID.String()
		copied.ExecutorID = s.ExecutorID
		marker = &copied
	}
	next.FailedExpansionTerminalReconcile = marker
	if err = persistRetirementForwardIntentTx(ctx, tx, old, next, "failed-expansion-terminal-reconcile:"+a.ID); err != nil {
		return s, old, false, err
	}
	if !guestReconcileLive(ctx) {
		return s, old, false, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return s, old, false, err
	}
	return bindFailedExpansionTerminalReconcile(s, marker), next, true, nil
}

// The finish step derives this private context again from the actual current
// marker, immutable terminal and same scheduler run. API mode alone grants none.
func (s CapacityStore) OriginalGuestFailedExpansionTerminalReconcileEpoch(ctx context.Context, policy model.Manifest) (CapacityStore, model.CapacityIntent, bool, error) {
	var current model.CapacityIntent
	if s.DB == nil || s.guestReconcile == nil || s.OriginalRunID == uuid.Nil || !guestReconcileLive(ctx) {
		return s, current, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, current, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return s, current, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return s, current, false, err
	}
	if err = lockRetirementForwardBindingsTx(ctx, tx, p.MutationBindings); err != nil {
		return s, current, false, err
	}
	current, err = loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return s, current, false, err
	}
	m := current.FailedExpansionTerminalReconcile
	if m == nil {
		return s, current, false, nil
	}
	if s.guestReconcile.step.Use.Operation != capacity.CompleteOriginalGuestOperation || !failedExpansionTerminalMarkerValid(m, current) || m.RunID != s.OriginalRunID.String() || m.ExecutorID != s.ExecutorID {
		return s, current, false, ErrCapacityConflict
	}
	bound := bindFailedExpansionTerminalReconcile(s, m)
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return s, current, false, err
	}
	if err = bound.checkLease(p, policy, &current, current.Generation, current.FencingToken, current.LeaseOwner, now); err != nil {
		return s, current, false, err
	}
	if err = bound.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return s, current, false, err
	}
	if err = bound.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return s, current, false, err
	}
	if m.PreviousRunID != "" {
		previous, e := bound.failedExpansionTerminalFailedRunTx(ctx, tx, policy, p, m.PreviousRunID, now)
		if e != nil {
			return s, current, false, e
		}
		if capacity.BusinessCreationSHA256(previous) != m.PreviousRunSHA256 {
			return s, current, false, ErrCapacityConflict
		}
	}
	a, terminal, terminalSHA, err := bound.failedExpansionTerminalReconcileTx(ctx, tx, policy, p, m.CleanupID)
	if err != nil || terminalSHA != m.TerminalEventSHA256 || terminal.Generation != m.TerminalGeneration || terminal.FencingToken != m.TerminalFence || current.Decision.Action != "hold" || current.Decision.Units != a.SurvivorCount || current.BaselineSnapshot.Units != a.SurvivorCount {
		return s, current, false, ErrCapacityConflict
	}
	if err = failedExpansionQuietTx(ctx, tx, a, s.OriginalRunID.String()); err != nil {
		return s, current, false, err
	}
	if err = tx.Commit(); err != nil {
		return s, current, false, err
	}
	return bound, current, true, nil
}
