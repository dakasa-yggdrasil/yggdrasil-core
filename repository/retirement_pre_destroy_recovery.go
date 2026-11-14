package repository

import (
	"context"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestRetirementForwardPreDestroyRecoveryMode = "pre_destroy_recovery"
const GuestRetirementForwardPreDestroyRecoverySchema = "original_closed_pre_destroy_recovery_v1"

// These immutable references close one failed owner. They provide no native
// mutation permission: the new owner must obtain fresh OFF/inventory/floor.
type GuestRetirementForwardPreDestroyRecoveryProof struct {
	Schema                  string    `json:"schema"`
	RequestingRunID         string    `json:"requesting_run_id"`
	FailedRunID             string    `json:"failed_run_id"`
	FailedRunSHA256         string    `json:"failed_run_sha256"`
	DispatchID              string    `json:"dispatch_id"`
	DispatchSHA256          string    `json:"dispatch_sha256"`
	NativeOffReadID         string    `json:"native_off_read_id"`
	NativeOffPreparedSHA256 string    `json:"native_off_prepared_sha256"`
	NativeOffReturnSHA256   string    `json:"native_off_return_sha256"`
	OriginalContextDeadline time.Time `json:"original_context_deadline"`
	OriginalLeaseExpiresAt  time.Time `json:"original_lease_expires_at"`
}

// A scope/native-profile lock serializes this absence proof with IssueMutation
// and redemption. A committed old permission is a HOLD in ANY state. With none,
// ordinary TryClaim supplies a new fence; a delayed old caller cannot issue.
// Existing historical/normal/settled admission rules are not reinterpreted.
func (s CapacityStore) TryRequestGuestRetirementForwardPreDestroyRecovery(ctx context.Context, policy model.Manifest) (bool, error) {
	if s.DB == nil || s.OriginalRunID == uuid.Nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || !guestReconcileLive(ctx) {
		return false, ErrCapacityConflict
	}
	pending, found, err := s.GuestRetirementForwardWaiting(ctx, policy)
	if err != nil || !found {
		return false, err
	}
	if pending.Stage != "off_qualified" || (pending.Mode != "live" && pending.Mode != GuestRetirementForwardPreDestroyRecoveryMode) {
		return false, nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	x, err := s.retirementForwardSnapshotTx(ctx, tx, pending.RetirementRequestID)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	if x.policy.ID != policy.ID || x.policy.Checksum != policy.Checksum || x.current.RetirementForward == nil || *x.current.RetirementForward != *retirementForwardMarker(pending) || x.current.LeaseExpiresAt == nil || !x.now.After(*x.current.LeaseExpiresAt) || !x.now.After(x.original.Request.Intent.OriginalDeadline) {
		return false, nil
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, x.spec); err != nil {
		return false, err
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, x.spec, s.OriginalRunID, nil); err != nil {
		return false, err
	}
	parent, parentSHA, err := loadRetirementForwardTx(ctx, tx, pending.ID, pending.Stage)
	if err != nil {
		return false, err
	}
	admitted, admittedSHA, err := loadRetirementForwardTx(ctx, tx, parent.ID, "admitted")
	if err != nil {
		return false, err
	}
	if parent.Generation != x.current.Generation || parent.Fence != x.current.FencingToken || parent.LeaseOwner != x.current.LeaseOwner || parent.ExecutorID != x.current.LeaseExecutorID || parent.RunID == "" || parent.DestroyGrantID != "" || !reflect.DeepEqual(parent.Evidence, x.evidence) {
		return false, nil
	}
	var absent bool
	if err = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_pre_destroy_authority_absent103($1)`, parent.RetirementRequestID).Scan(&absent); err != nil {
		return false, err
	}
	if !absent {
		return false, nil
	}
	// OriginalContextDeadline is the retained ROOT Guest context. The failed
	// parent is independently closed by its actual dispatch ACK, own OFF return
	// and CURRENT parent lease below; no child finish deadline is invented.
	proof := &GuestRetirementForwardPreDestroyRecoveryProof{Schema: GuestRetirementForwardPreDestroyRecoverySchema, RequestingRunID: s.OriginalRunID.String(), FailedRunID: parent.RunID, OriginalLeaseExpiresAt: *x.current.LeaseExpiresAt}
	if err = tx.QueryRowContext(ctx, `SELECT original_context_deadline FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=$1`, parent.RetirementRequestID).Scan(&proof.OriginalContextDeadline); err != nil {
		return false, continuationEligibilityError(err)
	}
	if !x.now.After(proof.OriginalContextDeadline) {
		return false, nil
	}
	failed, err := s.failedForwardRetirementRunTx(ctx, tx, x, parent.RunID)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	proof.FailedRunSHA256 = capacity.BusinessCreationSHA256([]byte(failed))
	var dispatch []byte
	err = tx.QueryRowContext(ctx, `SELECT j.id::text,to_jsonb(j)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
 WHERE j.run_id=$1 AND (SELECT count(*) FROM public.capacity_dispatch_jobs z WHERE z.run_id=j.run_id)=1
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(w.result->'steps') v WHERE v->>'id'='finish-original-retirement' AND v->>'status'='failed')
 AND j.state='returned' AND j.return_status='failed' AND w.status='failed' AND w.finished_at=j.returned_at
 AND j.returned_at IS NOT NULL AND j.finalization_ack_at>=j.returned_at
 AND j.envelope::jsonb#>>'{workflow,id}'=$2 AND w.result#>>'{steps,0,metadata,generation}'=$3
 AND w.result#>>'{steps,0,metadata,fencing_token}'=$4 AND w.result#>>'{steps,0,metadata,lease_owner}'=$5`, parent.RunID, x.original.Request.Intent.WorkflowID, parent.Generation, parent.Fence, parent.LeaseOwner).Scan(&proof.DispatchID, &dispatch)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	proof.DispatchSHA256 = capacity.BusinessCreationSHA256(dispatch)
	var open bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads p WHERE p.retirement_request_id=$1 AND p.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.id=p.id AND v.stage='returned'))`, parent.RetirementRequestID).Scan(&open); err != nil {
		return false, err
	}
	if open {
		return false, nil
	}
	// Do not filter for OFF or successful returns: the absolute latest record
	// must itself be this parent's complete positive OFF, with no later doubt.
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_retirement_forward_reads WHERE retirement_request_id=$1 AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1`, parent.RetirementRequestID).Scan(&proof.NativeOffReadID); err != nil {
		return false, continuationEligibilityError(err)
	}
	off, _, offSHA, err := loadForwardReadReturnTx(ctx, tx, proof.NativeOffReadID)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	if off.Schema != GuestRetirementForwardReadReturnSchema || off.Read.Schema != GuestRetirementForwardReadSchema || !x.now.After(off.Read.OriginalDeadlineCore) || off.Status != "observed" || off.CallFailed || off.OriginalContextFailed || off.Read.DestroyGrantID != "" || off.Observation != nil || off.OriginalDestroyReceipt != nil || off.ObserverSourceCommit != "" || len(off.OriginalObserverReturn) != 0 || off.StartedAtCore.Before(off.Read.IssuedAtCore) || off.OriginalReturnedAtCore.Before(off.StartedAtCore) || !off.OriginalReturnedAtCore.Before(off.Read.OriginalDeadlineCore) || !off.Read.OriginalDeadlineCore.After(off.Read.IssuedAtCore) || off.Read.OriginalDeadlineCore.Sub(off.Read.IssuedAtCore) > 5*time.Second || off.Read.Kind != "off" || off.Read.AdmissionID != admitted.ID || off.Read.AdmissionSHA256 != admittedSHA || off.Read.ReadID != parent.NativeOffReadID || offSHA != parent.NativeOffSHA256 || off.Read.RetirementRequestID != parent.RetirementRequestID || off.Read.PrefixSHA256 != parent.PrefixSHA256 || off.Read.OriginalCallerSHA256 != parent.OriginalCallerSHA256 || off.Read.Tuple != x.original.Request.Intent.Tuple || off.Read.AdapterSourceCommit != x.binding.OriginalProviderSourceCommit || off.Read.MutationBindingSHA256 != capacity.GuestRetirementSHA(x.binding) || off.Plan == nil {
		return false, nil
	}
	create, err := guestOriginalCreateReceiptV2Tx(ctx, tx, x.original)
	if err != nil || capacity.GuestRetirementV2NativeOffPlanContent(x.spec, x.binding, *off.Plan, create) != nil {
		return false, continuationEligibilityError(err)
	}
	proof.NativeOffReturnSHA256 = offSHA
	if err = tx.QueryRowContext(ctx, `SELECT record_sha256 FROM public.capacity_guest_retirement_forward_reads WHERE id=$1 AND stage='prepared'`, proof.NativeOffReadID).Scan(&proof.NativeOffPreparedSHA256); err != nil {
		return false, err
	}
	if err = retirementForwardContinuationQuietTx(ctx, tx, x, "", s.OriginalRunID.String()); err != nil {
		return false, continuationEligibilityError(err)
	}
	r := forwardRecord(x, s, GuestRetirementForwardPreDestroyRecoveryMode, "requested", "source:pre-destroy-recovery")
	r.RootAdmissionID, r.ParentAdmissionID, r.ParentAdmissionSHA256 = parent.RootAdmissionID, parent.ID, parentSHA
	r.RunID, r.FailedRun, r.PreDestroyRecovery = "", []byte(failed), proof
	if _, err = insertRetirementForwardTx(ctx, tx, r); err != nil {
		return false, err
	}
	next := x.current
	next.RetirementForward, next.UpdatedAt = retirementForwardMarker(r), x.now
	if err = persistRetirementForwardIntentTx(ctx, tx, x.current, next, "retirement-forward:"+r.ID+":requested"); err != nil {
		return false, err
	}
	if !guestReconcileLive(ctx) {
		return false, ErrCapacityLease
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
