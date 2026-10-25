//go:build linux && nativequalification

package main

import (
	"context"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

func (f *fixture) prepareOriginalRecoveryCleanupChronology(ctx context.Context, p model.CapacityPolicySpec, pre model.CapacityGuestOriginalProvisioningPreregistration) error {
	if !q.CanonicalSourceCompensationCase(f.request.NativeCase) || pre.Slot != 2 {
		return q.ErrOriginalUnknown
	}
	limit := pre.OriginalDeadline
	if f.request.OriginalContextDeadline.Before(limit) {
		limit = f.request.OriginalContextDeadline
	}
	if limit.IsZero() || !time.Now().UTC().Before(limit) {
		return q.ErrOriginalUnknown
	}
	original, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	ctx = original
	var raw []byte
	var before model.CapacityIntent
	if err := f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.namespace, p.Environment, p.Domain, p.Dimension).Scan(&raw); err != nil {
		return err
	}
	if json.Unmarshal(raw, &before) != nil || before.PolicyID != f.policy.ID || before.PolicyChecksum != f.policy.Checksum || before.RecoveryOnly || before.Generation != pre.Generation || before.FencingToken != pre.Fence || before.LeaseOwner != pre.LeaseOwner || before.LeaseExecutorID != pre.ExecutorID || before.LeaseExpiresAt == nil || !before.LeaseExpiresAt.Before(limit) {
		return q.ErrOriginalUnknown
	}
	if _, err := q.PublishBytes(ctx, filepath.Join(f.private, "canonical-recovery-original-intent.json"), raw); err != nil {
		return err
	}
	for {
		var now time.Time
		if err := f.db.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if !now.Before(*before.LeaseExpiresAt) {
			break
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	client, err := f.sourceClient(1)
	if err != nil {
		return err
	}
	defer client.Close()
	observed, err := f.realm.DiagnosticProbe(ctx, repository.CapacityStore{DB: f.db, WorkflowID: f.workflow.ID}, 1, f.corePrivate, client)
	if err != nil {
		return err
	}
	run, returns, err := f.originalRecoveryWorkflow(ctx, before.Generation, q.QualificationAssessment(p, 1, 0.9, observed.OriginalNativeAfterReturnedAt), pre.PreregistrationID)
	if err != nil || run.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "canonical-recovery-workflow-original-returns.json"), returns); err != nil {
		return err
	}
	session, err := f.realm.OriginalRecoveryCleanupSession(ctx)
	if err != nil || session.PreregistrationID != pre.PreregistrationID || session.Epoch.Generation != before.Generation || session.Epoch.FencingToken <= before.FencingToken || session.Epoch.LeaseOwner == before.LeaseOwner || session.Epoch.ExecutorID == before.LeaseExecutorID {
		return q.ErrOriginalUnknown
	}
	return nil
}

func (f *fixture) originalRecoveryWorkflow(ctx context.Context, generation int64, assessment model.CapacityAssessment, preID string) (model.WorkflowRunRecord, []originalPublicReturn, error) {
	var run model.WorkflowRunRecord
	var originals []originalPublicReturn
	request := model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: f.namespace, Name: f.workflow.Metadata.Name}, Inputs: map[string]any{"mode": "recovery_cleanup", "slot": 2, "generation": generation, "assessment": assessment, "preregistration_id": preID}, Metadata: map[string]any{"idempotency_key": uuid.NewString()}}
	var accepted struct {
		RunID    string                 `json:"run_id"`
		Status   string                 `json:"status"`
		Workflow model.ManifestSelector `json:"workflow"`
		Deduped  bool                   `json:"deduped,omitempty"`
	}
	returned, err := f.originalPublic(ctx, http.MethodPost, "/api/v1/workflow-runs", request, &accepted)
	originals = append(originals, returned)
	if err != nil || returned.Status != http.StatusAccepted || accepted.Status != "pending" || accepted.Deduped {
		return run, originals, q.ErrOriginalUnknown
	}
	parsed, err := uuid.Parse(accepted.RunID)
	if err != nil || parsed == uuid.Nil || parsed.String() != accepted.RunID {
		return run, originals, q.ErrOriginalUnknown
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		returned, err = f.originalPublic(ctx, http.MethodGet, "/api/v1/workflow-runs/"+accepted.RunID, nil, &run)
		originals = append(originals, returned)
		if err != nil || returned.Status != http.StatusOK || run.ID.String() != accepted.RunID {
			return run, originals, q.ErrOriginalUnknown
		}
		if run.Status == "succeeded" || run.Status == "failed" {
			if run.Result == nil || run.Result.Workflow.ID != f.workflow.ID {
				return run, originals, q.ErrOriginalUnknown
			}
			return run, originals, nil
		}
		select {
		case <-ctx.Done():
			return run, originals, q.ErrOriginalUnknown
		case <-ticker.C:
		}
	}
}

func (f *fixture) recoveryCleanupProof(ctx context.Context, p model.CapacityPolicySpec) (repository.CapacityStore, model.CapacityIntent, model.CapacityTransitionProof, error) {
	var noStore repository.CapacityStore
	var noIntent model.CapacityIntent
	var noProof model.CapacityTransitionProof
	session, err := f.realm.OriginalRecoveryCleanupSession(ctx)
	if err != nil {
		return noStore, noIntent, noProof, err
	}
	store := session.Store
	current, err := store.Observe(ctx, f.policy)
	if err != nil || !current.RecoveryOnly || current.Generation != session.Epoch.Generation || current.FencingToken != session.Epoch.FencingToken || current.LeaseOwner != session.Epoch.LeaseOwner || current.LeaseExecutorID != store.ExecutorID || current.LeaseExpiresAt == nil {
		return noStore, noIntent, noProof, q.ErrOriginalUnknown
	}
	client, err := f.sourceClient(1)
	if err != nil {
		return noStore, noIntent, noProof, err
	}
	defer client.Close()
	probe, err := f.realm.DiagnosticProbe(ctx, store, 1, f.corePrivate, client)
	if err != nil {
		return noStore, noIntent, noProof, err
	}
	binding, err := capacity.VMObservationBinding(p, f.binding.MutationBindingName)
	if err != nil {
		return noStore, noIntent, noProof, err
	}
	physical, err := f.realm.FreshNativeMember(ctx, 1, binding)
	if err != nil {
		return noStore, noIntent, noProof, err
	}
	var desired []byte
	for _, slot := range binding.Slots {
		if slot.Slot == 1 {
			desired, err = json.Marshal(slot.DesiredSpec)
		}
	}
	if err != nil || len(desired) == 0 {
		return noStore, noIntent, noProof, q.ErrOriginalUnknown
	}
	if err = store.RecordMutationSlot(ctx, f.policy, current.Generation, current.FencingToken, current.LeaseOwner, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: desired}, physical); err != nil {
		return noStore, noIntent, noProof, err
	}
	if err = store.CheckNativeMembershipCoverage(ctx, f.policy, binding, []model.CapacityMutationProof{physical}); err != nil {
		return noStore, noIntent, noProof, err
	}
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: q.QualificationAssessment(p, 1, 0.1, probe.OriginalNativeAfterReturnedAt), ObservedAt: probe.OriginalNativeAfterReturnedAt, ReceiptRef: "source-recovery-cleanup-current-baseline:" + capacity.GuestRetirementSHA(probe), Healthy: true, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants", MembershipComplete: true}
	return store, current, proof, nil
}

func (f *fixture) recoveryMutationState(ctx context.Context) (string, error) {
	var joined string
	for _, table := range []string{"capacity_intents", "capacity_mutation_grants", "capacity_resource_slots"} {
		var raw []byte
		if err := f.db.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM public.`+table+` x WHERE namespace=$1`, f.namespace).Scan(&raw); err != nil {
			return "", err
		}
		joined += capacity.BusinessCreationSHA256(raw)
	}
	return capacity.BusinessCreationSHA256([]byte(joined)), nil
}

func (f *fixture) assertOriginalRecoveryUnresolved(ctx context.Context, p model.CapacityPolicySpec, pre model.CapacityGuestOriginalProvisioningPreregistration, phase string) error {
	if phase != "parent" && phase != "child" {
		return q.ErrOriginalUnknown
	}
	store, current, proof, err := f.recoveryCleanupProof(ctx, p)
	if err != nil {
		return err
	}
	var count int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND state IN ('issued','redeemed','settled','compensating')`, f.namespace).Scan(&count); err != nil {
		return err
	}
	expected := 1
	if phase == "child" {
		expected = 2
	}
	if count != expected {
		return q.ErrOriginalUnknown
	}
	before, err := f.recoveryMutationState(ctx)
	if err != nil {
		return err
	}
	outcome := "reconciled_partial"
	if f.request.NativeCase == "canonical_failed_floor_recovery" {
		outcome = "reconciled_failed_floor"
	}
	if _, err = store.Reconcile(ctx, f.policy, current.Generation, current.FencingToken, current.LeaseOwner, outcome, proof); err == nil || !strings.Contains(err.Error(), "unresolved provider mutation authority") {
		return q.ErrOriginalUnknown
	}
	after, err := f.recoveryMutationState(ctx)
	if err != nil || after != before {
		return q.ErrOriginalUnknown
	}
	_, err = q.Publish(ctx, filepath.Join(f.private, "canonical-recovery-unresolved-"+phase+".json"), map[string]any{"schema": "source_recovery_unresolved_refusal_v1", "scope": "ACTUAL_CURRENT_RECOVERY_OWNER_NOT_TERMINAL_AUTHORITY", "case": f.request.NativeCase, "parent_grant_id": pre.OriginalCreateGrantID, "phase": phase, "outstanding": count, "before_sha256": before, "after_sha256": after, "native_qualified": false})
	return err
}

func (f *fixture) finishOriginalKnownRecoveryTerminal(ctx context.Context, p model.CapacityPolicySpec, pre model.CapacityGuestOriginalProvisioningPreregistration) error {
	store, current, proof, err := f.recoveryCleanupProof(ctx, p)
	if err != nil {
		return err
	}
	before, err := f.recoveryMutationState(ctx)
	if err != nil {
		return err
	}
	bad := proof
	bad.NoMutationVerified = true
	if _, err = store.Reconcile(ctx, f.policy, current.Generation, current.FencingToken, current.LeaseOwner, "aborted", bad); err == nil || !strings.Contains(err.Error(), "confirmed provider mutation cannot be certified as no mutation") {
		return q.ErrOriginalUnknown
	}
	after, err := f.recoveryMutationState(ctx)
	if err != nil || after != before {
		return q.ErrOriginalUnknown
	}
	terminal, err := store.Reconcile(ctx, f.policy, current.Generation, current.FencingToken, current.LeaseOwner, "reconciled_partial", proof)
	if err != nil || terminal.Phase != "reconciled_partial" || terminal.LeaseOwner != "" || terminal.LeaseExecutorID != "" || terminal.LeaseExpiresAt != nil || terminal.Assessment.Snapshot.Units != 1 {
		return q.ErrOriginalUnknown
	}
	_, err = q.Publish(ctx, filepath.Join(f.private, "canonical-recovery-known-terminal.json"), map[string]any{"schema": "canonical_source_known_recovery_terminal_v1", "scope": "ACTUAL_COMPENSATION_PARTIAL_TERMINAL_NOT_NO_MUTATION_OR_READINESS", "case": f.request.NativeCase, "core_source": capacity.CurrentGuestCoreSource(), "guest_source": f.request.SourceCommit, "parent_grant_id": pre.OriginalCreateGrantID, "terminal": terminal, "aborted_no_mutation_refused": true, "native_qualified": false})
	return err
}
