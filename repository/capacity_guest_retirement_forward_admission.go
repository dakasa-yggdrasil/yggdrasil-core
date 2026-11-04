package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func forwardSourceOrigin(s CapacityStore, op string) bool {
	o := s.guestNotifyOrigin
	if op == capacity.RetireOriginalGuestOperation {
		o = s.guestRetirementOrigin
	}
	return o != nil && o.source == capacity.CurrentGuestCoreSource() && len(o.source) == 40 && o.step.Use.Kind == "yggdrasil" && o.step.Use.Operation == op
}
func forwardRecord(x retirementForwardSnapshot, s CapacityStore, mode, stage, issuer string) GuestRetirementForward {
	id := uuid.NewString()
	return GuestRetirementForward{Schema: GuestRetirementForwardSchema, ID: id, RootAdmissionID: id, Stage: stage, Mode: mode, PreregistrationID: x.original.Preregistration.PreregistrationID, RetirementRequestID: x.original.Request.Intent.RequestID, PrefixSHA256: retirementForwardEvidenceSHA(x.evidence), OriginalCallerSHA256: x.evidence.CallerSHA256, RecordedAt: x.now, Namespace: x.policy.Metadata.Namespace, Environment: x.spec.Environment, Domain: x.spec.Domain, Dimension: x.spec.Dimension, Issuer: issuer, ActualCoreSource: capacity.CurrentGuestCoreSource(), OriginalIntentWire: append([]byte(nil), x.intentWire...), OriginalIntentSHA256: capacity.BusinessCreationSHA256(x.intentWire), OriginalGeneration: int64(x.original.Request.Intent.Generation), OriginalFence: int64(x.original.Request.Intent.Fence), Generation: x.current.Generation, Fence: x.current.FencingToken, LeaseOwner: x.current.LeaseOwner, ExecutorID: x.current.LeaseExecutorID, RunID: s.OriginalRunID.String(), FailedRun: []byte{}, Original: x.original, Evidence: x.evidence}
}
func (s CapacityStore) AdmitGuestRetirementForwardLive(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id string) (GuestRetirementForward, error) {
	var r GuestRetirementForward
	if s.DB == nil || !forwardSourceOrigin(s, capacity.RetireOriginalGuestOperation) || s.OriginalRunID == uuid.Nil || ctx.Err() != nil {
		return r, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	x, err := s.retirementForwardSnapshotTx(ctx, tx, id)
	if err != nil {
		return r, err
	}
	if x.policy.ID != policy.ID || x.policy.Checksum != policy.Checksum || x.current.RetirementForward != nil || s.ExecutorID != x.original.ExecutorID || x.current.FencingToken != int64(x.original.Request.Intent.Fence) || s.checkLease(x.spec, policy, &x.current, generation, fence, owner, x.now) != nil {
		return r, ErrCapacityConflict
	}
	scoped := s
	scoped.guestReconcile = &guestReconcileSource{workflow: model.Manifest{ID: s.WorkflowID}}
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum FROM public.manifests WHERE id=$1`, s.WorkflowID).Scan(&scoped.guestReconcile.workflow.Metadata.Namespace, &scoped.guestReconcile.workflow.Metadata.Name, &scoped.guestReconcile.workflow.Version, &scoped.guestReconcile.workflow.Checksum); err != nil {
		return r, err
	}
	if err = scoped.installedGuestDispatchRunTx(ctx, tx, policy, x.spec, s.OriginalRunID, nil); err != nil {
		return r, err
	}
	if err = retirementForwardQuietTx(ctx, tx, x, s.OriginalRunID.String(), ""); err != nil {
		return r, err
	}
	r = forwardRecord(x, s, "live", "admitted", "source:ordinary-retirement")
	if _, err = insertRetirementForwardTx(ctx, tx, r); err != nil {
		return r, err
	}
	next := x.current
	next.RetirementForward = retirementForwardMarker(r)
	next.UpdatedAt = x.now
	if err = persistRetirementForwardIntentTx(ctx, tx, x.current, next, "retirement-forward:"+r.ID+":admitted"); err != nil {
		return r, err
	}
	if ctx.Err() != nil {
		return r, ErrCapacityLease
	}
	err = tx.Commit()
	return r, err
}

func (s CapacityStore) RequestGuestRetirementForwardHistorical(ctx context.Context, req model.CapacityGuestRetirementForwardRequest, issuer string, barrier CapacityDispatchExecutorBarrier, revalidate func(context.Context) error) (GuestRetirementForward, error) {
	var r GuestRetirementForward
	if s.DB == nil || revalidate == nil || issuer == "" || len(issuer) > 256 || !validCapacityExecutor(req.PreregistrationID) || !validCapacityExecutor(req.RetirementRequestID) || !validCapacityExecutor(req.PolicyID) || !capacity.ValidDigest(req.PolicyChecksum) || !capacity.ValidDigest(req.IntentSHA256) || req.Generation < 1 || req.FencingToken < 1 || !validCapacityDispatchExecutorBarrier(barrier) || barrier.SourceCommit != capacity.CurrentGuestCoreSource() {
		return r, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	x, err := s.retirementForwardSnapshotTx(ctx, tx, req.RetirementRequestID)
	if err != nil {
		return r, err
	}
	i := x.original.Request.Intent
	if x.original.Preregistration.PreregistrationID != req.PreregistrationID || x.policy.ID.String() != req.PolicyID || x.policy.Checksum != req.PolicyChecksum || x.current.Generation != req.Generation || x.current.FencingToken != req.FencingToken || capacity.BusinessCreationSHA256(x.intentWire) != req.IntentSHA256 || x.current.LeaseExpiresAt == nil || x.current.LeaseExpiresAt.After(x.now) || !barrier.ProcessStartedAt.After(*x.current.LeaseExpiresAt) || !barrier.ProcessStartedAt.After(i.OriginalDeadline) || barrier.ProcessStartedAt.After(x.now) {
		return r, ErrCapacityConflict
	}
	var originalContextDeadline time.Time
	if err = tx.QueryRowContext(ctx, `SELECT original_context_deadline FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, i.RequestID).Scan(&originalContextDeadline); err != nil || !barrier.ProcessStartedAt.After(originalContextDeadline) {
		return r, ErrCapacityConflict
	}
	// Match the actual failed scheduled run's exact plan epoch, not a caller ID
	// nor the newest run. More than one matching original is a HOLD.
	rows, err := tx.QueryContext(ctx, `SELECT w.id::text FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE j.envelope::jsonb#>>'{workflow,id}'=$1 AND w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND j.finalization_ack_at IS NOT NULL AND w.result#>>'{steps,0,metadata,generation}'=$2 AND w.result#>>'{steps,0,metadata,fencing_token}'=$3 AND w.result#>>'{steps,0,metadata,lease_owner}'=$4 ORDER BY w.id LIMIT 2`, i.WorkflowID, x.current.Generation, x.current.FencingToken, x.current.LeaseOwner)
	if err != nil {
		return r, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return r, err
		}
		ids = append(ids, id)
	}
	er, cl := rows.Err(), rows.Close()
	if er != nil {
		return r, er
	}
	if cl != nil {
		return r, cl
	}
	if len(ids) != 1 {
		return r, ErrCapacityConflict
	}
	run, err := s.failedForwardRetirementRunTx(ctx, tx, x, ids[0])
	if err != nil {
		return r, err
	}
	adoptedDestroy, err := forwardAdoptableDestroyTx(ctx, tx, x)
	if err != nil {
		return r, err
	}
	if err = retirementForwardQuietTx(ctx, tx, x, "", adoptedDestroy); err != nil {
		return r, err
	}
	r = forwardRecord(x, s, "historical", "requested", issuer)
	r.RunID = ""
	r.FailedRun = []byte(run)
	r.Barrier = barrier
	r.DestroyGrantID = adoptedDestroy
	if x.current.RetirementForward != nil {
		m := x.current.RetirementForward
		if m.RetirementRequestID != req.RetirementRequestID || m.Stage == "requested" || m.Stage == "terminal" {
			return r, ErrCapacityConflict
		}
		parent, sha, e := loadRetirementForwardTx(ctx, tx, m.ID, m.Stage)
		if e != nil || parent.RetirementRequestID != r.RetirementRequestID || !reflect.DeepEqual(parent.Evidence, x.evidence) {
			return r, ErrCapacityConflict
		}

		r.RootAdmissionID = parent.RootAdmissionID
		r.ParentAdmissionID = parent.ID
		r.ParentAdmissionSHA256 = sha
	}
	if err = revalidate(ctx); err != nil {
		return r, err
	}
	if _, err = insertRetirementForwardTx(ctx, tx, r); err != nil {
		return r, err
	}
	next := x.current
	next.RetirementForward = retirementForwardMarker(r)
	next.UpdatedAt = x.now
	if err = persistRetirementForwardIntentTx(ctx, tx, x.current, next, "retirement-forward:"+r.ID+":requested"); err != nil {
		return r, err
	}
	if err = revalidate(ctx); err != nil || ctx.Err() != nil {
		return r, ErrCapacityConflict
	}
	err = tx.Commit()
	return r, err
}

func (s CapacityStore) TryClaimGuestRetirementForward(ctx context.Context, policy model.Manifest) (model.CapacityIntent, string, string, bool, error) {
	var zero model.CapacityIntent
	if s.DB == nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || s.OriginalRunID == uuid.Nil || !validCapacityExecutor(s.ExecutorID) || !guestReconcileLive(ctx) {
		return zero, "", "", false, ErrCapacityConflict
	}
	pending, found, err := s.GuestRetirementForwardWaiting(ctx, policy)
	if err != nil || !found {
		return zero, "", "", false, err
	}
	if pending.Stage != "requested" {
		return zero, "", "", true, ErrCapacityLease
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return zero, "", "", false, err
	}
	defer tx.Rollback()
	x, err := s.retirementForwardSnapshotTx(ctx, tx, pending.RetirementRequestID)
	if err != nil {
		return zero, "", "", false, err
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, x.spec); err != nil {
		return zero, "", "", false, err
	}
	r, _, err := loadRetirementForwardTx(ctx, tx, pending.ID, "requested")
	if err != nil {
		return zero, "", "", false, err
	}
	if x.current.RetirementForward == nil || *x.current.RetirementForward != *retirementForwardMarker(r) || x.current.LeaseExpiresAt == nil || x.current.LeaseExpiresAt.After(x.now) || !reflect.DeepEqual(r.Evidence, x.evidence) || r.Fence != x.current.FencingToken || r.Fence >= maxCapacityGeneration || r.ActualCoreSource != capacity.CurrentGuestCoreSource() {
		return zero, "", "", false, ErrCapacityConflict
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, x.spec, s.OriginalRunID, nil); err != nil {
		return zero, "", "", false, err
	}
	if err = retirementForwardQuietTx(ctx, tx, x, s.OriginalRunID.String(), r.DestroyGrantID); err != nil {
		return zero, "", "", false, err
	}
	// Requested original bytes + the one requested marker/updated_at are the
	// entire permitted delta; no shadow assessment or counter is synthesized.
	var baseline model.CapacityIntent
	if decodeFailedServingIntent(r.OriginalIntentWire, &baseline) != nil {
		return zero, "", "", false, ErrCapacityConflict
	}
	baseline.RetirementForward = x.current.RetirementForward
	baseline.UpdatedAt = x.current.UpdatedAt
	if !reflect.DeepEqual(baseline, x.current) {
		return zero, "", "", false, ErrCapacityConflict
	}
	r.Stage = "admitted"
	r.RecordedAt = x.now
	r.Fence++
	r.LeaseOwner = uuid.NewString()
	r.ExecutorID = s.ExecutorID
	r.RunID = s.OriginalRunID.String()
	next := x.current
	next.FencingToken = r.Fence
	next.LeaseOwner = r.LeaseOwner
	next.LeaseExecutorID = s.ExecutorID
	expires := x.now.Add(time.Duration(x.spec.LeaseSeconds) * time.Second)
	next.LeaseExpiresAt = &expires
	next.UpdatedAt = x.now
	next.RetirementForward = retirementForwardMarker(r)
	if _, err = insertRetirementForwardTx(ctx, tx, r); err != nil {
		return zero, "", "", false, err
	}
	if err = persistRetirementForwardIntentTx(ctx, tx, x.current, next, "retirement-forward:"+r.ID+":admitted"); err != nil {
		return zero, "", "", false, err
	}
	if !guestReconcileLive(ctx) {
		return zero, "", "", false, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return zero, "", "", false, err
	}
	return next, r.PreregistrationID, r.RetirementRequestID, true, nil
}

func (s CapacityStore) retirementForwardCurrentTx(ctx context.Context, tx *sql.Tx, id string) (retirementForwardSnapshot, GuestRetirementForward, string, error) {
	x, err := s.retirementForwardSnapshotTx(ctx, tx, id)
	var r GuestRetirementForward
	if err != nil {
		return x, r, "", err
	}
	m := x.current.RetirementForward
	if m == nil || m.RetirementRequestID != id || (m.Stage != "admitted" && m.Stage != "off_qualified") {
		return x, r, "", ErrCapacityConflict
	}
	r, sha, err := loadRetirementForwardTx(ctx, tx, m.ID, "admitted")
	if err != nil {
		return x, r, "", err
	}
	if r.ActualCoreSource != capacity.CurrentGuestCoreSource() || r.Generation != x.current.Generation || r.Fence != x.current.FencingToken || r.LeaseOwner != x.current.LeaseOwner || r.RunID != s.OriginalRunID.String() || r.ExecutorID != s.ExecutorID || r.ExecutorID != x.current.LeaseExecutorID || s.WorkflowID.String() != r.Original.Request.Intent.WorkflowID || !reflect.DeepEqual(r.Evidence, x.evidence) || s.checkLease(x.spec, x.policy, &x.current, r.Generation, r.Fence, r.LeaseOwner, x.now) != nil {
		return x, r, "", ErrCapacityConflict
	}
	return x, r, sha, nil
}
func (s CapacityStore) GuestRetirementForwardOriginal(ctx context.Context, policy model.Manifest, generation, fence int64, owner, id string) (GuestRetirementOriginalV2, GuestRetirementForward, bool, error) {
	var orig GuestRetirementOriginalV2
	var r GuestRetirementForward
	pending, found, err := s.GuestRetirementForwardWaiting(ctx, policy)
	if err != nil || !found {
		return orig, r, false, err
	}
	if id != pending.RetirementRequestID {
		return orig, r, true, ErrCapacityConflict
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return orig, r, true, err
	}
	defer tx.Rollback()
	x, r, _, err := s.retirementForwardCurrentTx(ctx, tx, id)
	if err != nil {
		return orig, r, true, err
	}
	if policy.ID != x.policy.ID || policy.Checksum != x.policy.Checksum || generation != r.Generation || fence != r.Fence || owner != r.LeaseOwner {
		return orig, r, true, ErrCapacityConflict
	}
	if !forwardSourceOrigin(s, capacity.RetireOriginalGuestOperation) && !forwardSourceOrigin(s, "capacity.finish_original_guest_retirement") {
		return orig, r, true, ErrCapacityConflict
	}
	return x.original, r, true, nil
}

// The original retirement may have failed in retire itself, or in finish after
// the live admission was retained. Neither old run is rewritten as success.
func (s CapacityStore) failedForwardRetirementRunTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, id string) (string, error) {
	var wire, result []byte
	forwardInspectionStage(ctx, "failed_run_original")
	if err := tx.QueryRowContext(ctx, installedGuestPreviousFailedRunQuery, id, uuid.MustParse(x.original.Request.Intent.WorkflowID), x.now).Scan(&wire, &result); err != nil {
		return "", err
	}
	var out struct {
		Status string                        `json:"status"`
		Steps  []model.WorkflowRunStepResult `json:"steps"`
	}
	forwardInspectionStage(ctx, "failed_run_shape")
	if json.Unmarshal(result, &out) != nil || out.Status != "failed" || len(out.Steps) != 7 {
		return "", ErrCapacityConflict
	}
	steps := map[string]model.WorkflowRunStepResult{}
	for _, step := range out.Steps {
		if _, exists := steps[step.ID]; exists {
			return "", ErrCapacityConflict
		}
		steps[step.ID] = step
	}
	forwardInspectionStage(ctx, "failed_run_steps")
	for _, id := range []string{"provision-original-notify", "complete-original-provision", "refresh-original-membership"} {
		if steps[id].Status != "skipped" {
			return "", ErrCapacityConflict
		}
	}
	if steps["plan-original-guest"].Status != "succeeded" || steps["complete-original-retirement"].Status != "skipped" {
		return "", ErrCapacityConflict
	}
	retire, finish := steps["retire-original-guest"], steps["finish-original-retirement"]
	if retire.Status == "failed" {
		if finish.Status != "skipped" {
			return "", ErrCapacityConflict
		}
	} else if retire.Status == "succeeded" && finish.Status == "failed" {
		if x.current.RetirementForward == nil || retire.Metadata["retirement_forward_id"] != x.current.RetirementForward.ID || retire.Metadata["request_id"] != x.original.Request.Intent.RequestID {
			return "", ErrCapacityConflict
		}
	} else {
		return "", ErrCapacityConflict
	}
	wf := model.Manifest{ID: uuid.MustParse(x.original.Request.Intent.WorkflowID)}
	forwardInspectionStage(ctx, "failed_run_workflow")
	if err := tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum FROM public.manifests WHERE id=$1 AND active`, wf.ID).Scan(&wf.Metadata.Namespace, &wf.Metadata.Name, &wf.Version, &wf.Checksum); err != nil {
		return "", err
	}
	own := s
	own.WorkflowID = wf.ID
	own.guestReconcile = &guestReconcileSource{workflow: wf}
	forwardInspectionStage(ctx, "failed_run_dispatch_original")
	if err := own.installedGuestDispatchRunTx(ctx, tx, x.policy, x.spec, uuid.MustParse(id), result); err != nil {
		return "", err
	}
	return string(wire), nil
}
