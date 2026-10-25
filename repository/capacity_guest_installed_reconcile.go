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

const installedGuestOriginalFailedRunQuery = `SELECT j.id::text,w.id::text,row_to_json(w)::text,w.result FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE (w.workflow_id IS NULL OR w.workflow_id=$1) AND j.envelope::jsonb #>> '{workflow,id}'=$1::text AND w.status='failed' AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND j.finalization_ack_at IS NOT NULL AND w.finished_at=j.returned_at AND j.returned_at<=$3 AND w.metadata->>'capacity_dispatch_job_id'=j.id::text AND w.metadata->>'triggered_by'='workflow_scheduler' AND w.result #>>'{steps,1,metadata,preregistration,preregistration_id}'=$2 AND w.id<>$4 LIMIT 2`

const installedGuestPreviousFailedRunQuery = `SELECT row_to_json(w)::text,w.result FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE w.id=$1 AND (w.workflow_id IS NULL OR w.workflow_id=$2) AND j.envelope::jsonb #>> '{workflow,id}'=$2::text AND w.status='failed' AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND j.finalization_ack_at IS NOT NULL AND w.finished_at=j.returned_at AND j.returned_at<=$3`

func installedGuestResumeCandidate(old *model.CapacityIntent, p model.CapacityPolicySpec, policy model.Manifest, now time.Time) bool {
	if old == nil || old.FailedInstalledDisposal != nil || old.RecoveryOnly || old.FloorDegraded || (old.Phase != "preparing" && old.Phase != "prepared" && old.Phase != "canary") || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.Generation <= 0 || old.FencingToken <= 0 || old.FencingToken >= maxCapacityGeneration || old.LeaseExpiresAt == nil || old.LeaseExpiresAt.After(now) || old.Decision.Units < p.Floor || old.Decision.Units > p.Ceiling {
		return false
	}
	m := old.InstalledGuestReconcile
	return m == nil || m.Schema == "installed_original_guest_readiness_reconcile_v1" && m.Attempt >= 1 && m.Attempt < 3 && m.NewFence == old.FencingToken && m.OriginalFence > 0 && m.OriginalGeneration == old.Generation && m.OriginalFailurePreserved && !m.OriginalQuiescenceOrNoEffectClaimed && validCapacityExecutor(m.NewRunID)
}

// Scheduled runs retain their original namespace/name/version selector; their
// optional workflow_id column is not populated by InsertWorkflowRunTx. The
// server-owned, immutable dispatch envelope pins the exact manifest revision.
func (s CapacityStore) installedGuestDispatchRunTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, runID uuid.UUID, result []byte) error {
	if tx == nil || s.guestReconcile == nil || runID == uuid.Nil {
		return ErrCapacityConflict
	}
	var jobID uuid.UUID
	var optionalWorkflowID uuid.NullUUID
	if err := tx.QueryRowContext(ctx, `SELECT j.id,w.workflow_id FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=$1`, runID).Scan(&jobID, &optionalWorkflowID); err != nil || optionalWorkflowID.Valid && optionalWorkflowID.UUID != s.WorkflowID {
		return ErrCapacityConflict
	}
	job, err := readCapacityDispatchJob(ctx, tx, jobID, false)
	wf := s.guestReconcile.workflow
	workflowPin := CapacityDispatchManifestPin{ID: wf.ID, Namespace: wf.Metadata.Namespace, Name: wf.Metadata.Name, Version: wf.Version, Checksum: wf.Checksum}
	policyPin := CapacityDispatchManifestPin{ID: policy.ID, Namespace: policy.Metadata.Namespace, Name: policy.Metadata.Name, Version: policy.Version, Checksum: policy.Checksum}
	if err != nil || job.Protocol != CapacityDispatchProtocol || job.RunID != runID || job.Workflow != workflowPin || job.Workflow.ID != s.WorkflowID || job.Policy != policyPin || job.Realm != policy.Metadata.Namespace || job.Environment != p.Environment || job.Domain != p.Domain || job.Dimension != p.Dimension || job.Metadata["triggered_by"] != "workflow_scheduler" || job.Metadata["capacity_dispatch_job_id"] != jobID.String() || checkCapacityDispatchOriginal(ctx, tx, job) != nil {
		return ErrCapacityConflict
	}
	if result == nil {
		if job.State != "started" || job.ReturnedAt != nil || job.FinalizationAckAt != nil {
			return ErrCapacityConflict
		}
		return nil
	}
	var returned struct {
		Workflow model.ManifestReference `json:"workflow"`
		Status   string                  `json:"status"`
	}
	expected := model.ManifestReference{ID: job.Workflow.ID, Kind: "workflow", Namespace: job.Workflow.Namespace, Name: job.Workflow.Name, Version: job.Workflow.Version}
	if job.State != "returned" || job.ReturnedAt == nil || job.FinalizationAckAt == nil || json.Unmarshal(result, &returned) != nil || returned.Status != "failed" || returned.Workflow != expected {
		return ErrCapacityConflict
	}
	return nil
}

// TryResumeInstalledGuest is called only by the actual scheduler's plan step.
// It neither allocates a provider grant nor reexecutes a provisioning step. The
// old failed run, its acknowledged return and every old canary remain intact.
func (s CapacityStore) TryResumeInstalledGuest(ctx context.Context, policy model.Manifest, assessment model.CapacityAssessment) (model.CapacityIntent, bool, error) {
	if s.OriginalRunID == uuid.Nil {
		return model.CapacityIntent{}, false, nil
	}
	if s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || s.OriginalRunID == uuid.Nil || !validCapacityExecutor(s.ExecutorID) || !guestReconcileLive(ctx) {
		return model.CapacityIntent{}, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return model.CapacityIntent{}, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return model.CapacityIntent{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return model.CapacityIntent{}, false, err
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return model.CapacityIntent{}, false, err
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return model.CapacityIntent{}, false, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return model.CapacityIntent{}, false, err
	}
	old, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if errors.Is(err, sql.ErrNoRows) {
		return old, false, nil
	}
	if err != nil {
		return old, false, err
	}
	if !installedGuestResumeCandidate(&old, p, policy, now) {
		return old, false, nil
	}
	if !capacityProfileCurrent(p, old.Decision, now) {
		return old, false, ErrCapacityConflict
	}
	originalFence := old.FencingToken
	if old.InstalledGuestReconcile != nil {
		originalFence = old.InstalledGuestReconcile.OriginalFence
	}
	if !sameCapacityResourceIdentity(old.Assessment.Snapshot, assessment.Snapshot) || assessment.Snapshot.Profile != old.Decision.Profile || assessment.Snapshot.Units != old.Decision.Units {
		return old, false, ErrCapacityConflict
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, s.OriginalRunID, nil); err != nil {
		return old, false, ErrCapacityConflict
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL AND NOT(grant_record ? 'authority_kind') AND state IN('issued','redeemed','settled','compensating')`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&pending); err != nil || pending != 0 {
		return old, false, ErrCapacityConflict
	}
	members, err := s.guestReconcileMembersTx(ctx, tx, policy, p, now, true)
	if err != nil {
		return old, false, err
	}
	if len(members) != old.Decision.Units {
		return old, false, ErrCapacityConflict
	}
	var selected *guestOriginalStored
	var selectedReceipt model.CapacityGuestOriginalProvisioningReceipt
	var installation model.CapacityGuestOriginalInstallationConfirmation
	for _, m := range members {
		stored, e := loadGuestOriginalTx(ctx, tx, m.PreregistrationID)
		if e != nil {
			return old, false, e
		}
		if stored.pre.Generation != old.Generation || stored.pre.Fence != originalFence {
			continue
		}
		if selected != nil {
			return old, false, ErrCapacityConflict
		}
		if e = loadGuestWitnessTx(ctx, tx, &stored); e != nil {
			return old, false, e
		}
		receipt, _, e := loadGuestReceiptTx(ctx, tx, m.PreregistrationID)
		if e != nil {
			return old, false, e
		}
		installed, e := loadGuestInstallationTx(ctx, tx, stored, receipt)
		if e != nil {
			return old, false, e
		}
		var state string
		if e = tx.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, stored.pre.OriginalCreateGrantID).Scan(&state); e != nil || state != "confirmed" {
			return old, false, ErrCapacityConflict
		}
		selected = &stored
		selectedReceipt = receipt
		installation = installed
	}
	if selected == nil {
		return old, false, nil
	}
	var jobID, runID string
	var runWire, result []byte
	rows, err := tx.QueryContext(ctx, installedGuestOriginalFailedRunQuery, s.WorkflowID, selected.pre.PreregistrationID, now, s.OriginalRunID)
	if err != nil {
		return old, false, err
	}
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&jobID, &runID, &runWire, &result); err != nil {
			_ = rows.Close()
			return old, false, err
		}
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	if rowErr != nil || closeErr != nil || count != 1 || !originalInstalledFailureResult(result, selected.pre, s.WorkflowID) {
		return old, false, ErrCapacityConflict
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(runID), result); err != nil {
		return old, false, err
	}
	previousResumeRun, previousResumeSHA := "", ""
	if old.InstalledGuestReconcile != nil {
		m := old.InstalledGuestReconcile
		if m.PreregistrationID != selected.pre.PreregistrationID || m.OriginalRunID != runID || m.OriginalRunSHA256 != capacity.BusinessCreationSHA256(runWire) {
			return old, false, ErrCapacityConflict
		}
		var lastWire, lastResult []byte
		err = tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, m.NewRunID, s.WorkflowID, now).Scan(&lastWire, &lastResult)
		if err != nil || !failedInstalledResumeResult(lastResult, old.Generation, old.FencingToken) {
			return old, false, ErrCapacityConflict
		}
		if err = s.installedGuestDispatchRunTx(ctx, tx, policy, p, uuid.MustParse(m.NewRunID), lastResult); err != nil {
			return old, false, err
		}
		previousResumeRun, previousResumeSHA = m.NewRunID, capacity.BusinessCreationSHA256(lastWire)
	}
	previous, err := previousInstalledCanariesTx(ctx, tx, policy, old, now)
	if err != nil {
		return old, false, err
	}
	attempt := 1
	if old.InstalledGuestReconcile != nil {
		attempt = old.InstalledGuestReconcile.Attempt + 1
		combined := append([]model.CapacityInstalledGuestPreviousCanary{}, old.InstalledGuestReconcile.PreviousCanaries...)
		seen := map[string]bool{}
		for _, v := range combined {
			seen[v.ChallengeID] = true
		}
		for _, v := range previous {
			if seen[v.ChallengeID] {
				return old, false, ErrCapacityConflict
			}
			seen[v.ChallengeID] = true
			combined = append(combined, v)
		}
		previous = combined
	}
	marker := &model.CapacityInstalledGuestReconcile{Attempt: attempt, PreviousFence: old.FencingToken, PreviousResumeRunID: previousResumeRun, PreviousResumeRunSHA256: previousResumeSHA, Schema: "installed_original_guest_readiness_reconcile_v1", OriginalJobID: jobID, OriginalRunID: runID, OriginalRunSHA256: capacity.BusinessCreationSHA256(runWire), PreregistrationID: selected.pre.PreregistrationID, EnrollmentSHA256: capacity.GuestRetirementSHA(selectedReceipt.Enrollment), InstallationSHA256: capacity.GuestRetirementSHA(installation), OriginalGeneration: old.Generation, OriginalFence: originalFence, NewFence: old.FencingToken + 1, NewRunID: s.OriginalRunID.String(), NewExecutorID: s.ExecutorID, PreviousCanaries: previous, OriginalFailurePreserved: true, OriginalQuiescenceOrNoEffectClaimed: false}
	next := old
	next.Phase = "preparing"
	next.InstalledGuestReconcile = marker
	next.FencingToken++
	next.LeaseOwner = uuid.NewString()
	next.LeaseExecutorID = s.ExecutorID
	expiry := now.Add(time.Duration(min(p.LeaseSeconds, 90)) * time.Second)
	next.LeaseExpiresAt = &expiry
	next.Assessment = assessment
	next.UpdatedAt = now
	if err = persistInstalledGuestResumeTx(ctx, tx, policy, p, old, next); err != nil {
		return old, false, err
	}
	markerWire, err := json.Marshal(marker)
	if err != nil {
		return old, false, err
	}
	if err = s.recordGuestAuthorityIssueTx(ctx, tx, policy, p, selected.binding, "installed_reconcile", s.OriginalRunID.String(), capacity.BusinessCreationSHA256(markerWire), markerWire); err != nil {
		return old, false, err
	}
	if !guestReconcileLive(ctx) {
		return old, false, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return old, false, err
	}
	return next, true, nil
}

// Closed old responses are retained as their actual outcomes. A held409 is not
// recast as no effect. A missing old response remains unknown. The distinct new
// ID pair is a periodic current test; expired kernel nonces and the existing
// runtime mutex/canaryPending serialize it without replaying the old request.
func previousInstalledCanariesTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, old model.CapacityIntent, now time.Time) ([]model.CapacityInstalledGuestPreviousCanary, error) {
	rows, err := tx.QueryContext(ctx, `SELECT c.id::text,c.phase,c.original_deadline,EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=c.id),COALESCE(r.outcome,''),r.original_transport FROM public.capacity_guest_notify_canary_challenges c LEFT JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id WHERE c.policy_id=$1 AND c.generation=$2 AND c.fence=$3 ORDER BY c.recorded_at,c.id LIMIT 257`, policy.ID, old.Generation, old.FencingToken)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.CapacityInstalledGuestPreviousCanary{}
	for rows.Next() {
		var row model.CapacityInstalledGuestPreviousCanary
		var deadline time.Time
		var transport []byte
		if err = rows.Scan(&row.ChallengeID, &row.Phase, &deadline, &row.PossibleSend, &row.Outcome, &transport); err != nil {
			return nil, err
		}
		if len(out) >= 256 || !deadline.Before(now) {
			return nil, ErrCapacityConflict
		}
		if len(transport) > 0 {
			var original capacity.GuestOriginalHTTPReturn
			if json.Unmarshal(transport, &original) != nil || original.PreflightFailed || original.DoFailed || original.ReadFailed || original.CloseFailed || original.OriginalContextFailed || original.ResponseBodyScope != capacity.GuestOriginalBodyCompleteRead || original.CloseReturnedAt.IsZero() || original.DriverReturnedAt.Before(original.CloseReturnedAt) {
				return nil, ErrCapacityConflict
			}
			row.ClosedHTTPStatus = original.Status
		}
		if row.Outcome == "" {
			row.Outcome = "unknown"
		}
		out = append(out, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	return out, nil
}

// OriginalGuestInstalledResumeEpoch recognizes only the actual new run and
// executor that won the source-owned CAS. An input mode or an expired old lease
// never becomes stable maintenance permission.
func (s CapacityStore) OriginalGuestInstalledResumeEpoch(ctx context.Context, policy model.Manifest) (CapacityStore, model.CapacityIntent, bool, error) {
	if s.OriginalRunID == uuid.Nil {
		return s, model.CapacityIntent{}, false, nil
	}
	if s.DB == nil || s.guestReconcile == nil || s.OriginalRunID == uuid.Nil || !guestReconcileLive(ctx) {
		return s, model.CapacityIntent{}, false, ErrCapacityConflict
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return s, model.CapacityIntent{}, false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return s, model.CapacityIntent{}, false, err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return s, model.CapacityIntent{}, false, err
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return s, current, false, err
	}
	m := current.InstalledGuestReconcile
	if m == nil || m.NewRunID != s.OriginalRunID.String() || m.NewExecutorID != s.ExecutorID {
		return s, current, false, nil
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return s, current, false, err
	}
	if m.Schema != "installed_original_guest_readiness_reconcile_v1" || m.Attempt < 1 || m.Attempt > 3 || m.NewFence != current.FencingToken || m.OriginalGeneration != current.Generation || !m.OriginalFailurePreserved || m.OriginalQuiescenceOrNoEffectClaimed || s.checkLease(p, policy, &current, current.Generation, current.FencingToken, current.LeaseOwner, now) != nil {
		return s, current, false, ErrCapacityConflict
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, p); err != nil {
		return s, current, false, err
	}
	if err = tx.Commit(); err != nil {
		return s, current, false, err
	}
	source := *s.guestReconcile
	source.mode = "provision"
	s.guestReconcile = &source
	return s, current, true, nil
}

// Keep JSON/SQL joins local to the source owner, rather than accepting a caller
// supplied healthy flag or reconstruction of an old failed original.
func originalInstalledFailureResult(raw []byte, pre model.CapacityGuestOriginalProvisioningPreregistration, workflowID uuid.UUID) bool {
	var r struct {
		Workflow model.ManifestReference       `json:"workflow"`
		Status   string                        `json:"status"`
		Steps    []model.WorkflowRunStepResult `json:"steps"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Workflow.ID != workflowID || r.Status != "failed" || len(r.Steps) != 7 {
		return false
	}
	by := map[string]model.WorkflowRunStepResult{}
	for _, step := range r.Steps {
		by[step.ID] = step
	}
	if by["plan-original-guest"].Status != "succeeded" || by["provision-original-notify"].Status != "succeeded" || by["complete-original-provision"].Status != "failed" {
		return false
	}
	for _, name := range []string{"retire-original-guest", "refresh-original-membership", "finish-original-retirement", "complete-original-retirement"} {
		if by[name].Status != "skipped" {
			return false
		}
	}
	b, _ := json.Marshal(by["provision-original-notify"].Metadata["preregistration"])
	var original model.CapacityGuestOriginalProvisioningPreregistration
	return json.Unmarshal(b, &original) == nil && reflect.DeepEqual(original, pre)
}

// The actual admission calls this under its scope lock, in the SAME transaction
// as the mandatory issuer audit. CAS prevents another original from replacing
// the epoch even if a future caller reaches this helper without that lock.
func persistInstalledGuestResumeTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, old, next model.CapacityIntent) error {
	m := next.InstalledGuestReconcile
	expectedAttempt := 1
	if old.InstalledGuestReconcile != nil {
		expectedAttempt = old.InstalledGuestReconcile.Attempt + 1
	}
	if m == nil || m.Attempt != expectedAttempt || m.Attempt > 3 || next.Generation != old.Generation || next.FencingToken != old.FencingToken+1 || m.PreviousFence != old.FencingToken || m.NewFence != next.FencingToken || next.Phase != "preparing" {
		return ErrCapacityConflict
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	before, err := json.Marshal(old)
	if err != nil {
		return err
	}
	changed, err := tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND (intent->>'generation')::bigint=$7 AND (intent->>'fencing_token')::bigint=$8 AND intent=$9::jsonb`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, raw, next.UpdatedAt, old.Generation, old.FencingToken, before)
	if err != nil {
		return err
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		return ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, next.Generation, next.FencingToken, next.Phase, "installed-original-reconcile:"+m.OriginalRunID+":"+m.NewRunID)
	return err
}

func failedInstalledResumeResult(raw []byte, generation, fence int64) bool {
	var r struct {
		Status string                        `json:"status"`
		Steps  []model.WorkflowRunStepResult `json:"steps"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Status != "failed" || len(r.Steps) != 7 {
		return false
	}
	by := map[string]model.WorkflowRunStepResult{}
	for _, v := range r.Steps {
		by[v.ID] = v
	}
	if by["plan-original-guest"].Status != "succeeded" || by["refresh-original-membership"].Status != "failed" {
		return false
	}
	var plan struct {
		Mode       string `json:"mode"`
		Reason     string `json:"reason"`
		Generation int64  `json:"generation"`
		Fence      int64  `json:"fencing_token"`
	}
	b, _ := json.Marshal(by["plan-original-guest"].Metadata)
	if json.Unmarshal(b, &plan) != nil || plan.Mode != "refresh" || plan.Reason != "installed_original_readiness_reconcile" || plan.Generation != generation || plan.Fence != fence {
		return false
	}
	for _, name := range []string{"provision-original-notify", "retire-original-guest", "complete-original-provision", "finish-original-retirement", "complete-original-retirement"} {
		if by[name].Status != "skipped" {
			return false
		}
	}
	return true
}
