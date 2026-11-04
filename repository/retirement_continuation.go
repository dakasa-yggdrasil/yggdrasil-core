package repository

import (
	"context"
	"database/sql"
	"errors"
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestRetirementForwardContinuationMode = "settled_absence_continuation"
const GuestRetirementForwardContinuationSchema = "original_settled_absence_continuation_v1"

// This records a closed failed owner and its last authenticated Pending read.
// It is neither absence, a new mutation permission, nor a process replacement.
// Parent/root and the immutable DELETE authority stay in the enclosing frame.
type GuestRetirementForwardContinuationProof struct {
	RequestingRunID         string `json:"requesting_run_id"`
	Schema                  string `json:"schema"`
	FailedRunID             string `json:"failed_run_id"`
	FailedRunSHA256         string `json:"failed_run_sha256"`
	DispatchID              string `json:"dispatch_id"`
	DispatchSHA256          string `json:"dispatch_sha256"`
	DestroyGrantSHA256      string `json:"destroy_grant_sha256"`
	DeleteEligibilitySHA256 string `json:"delete_eligibility_sha256"`
	PendingReadID           string `json:"pending_read_id"`
	PendingReadSHA256       string `json:"pending_read_sha256"`
}

// TryRequestGuestRetirementForwardContinuation is available only to the actual
// scheduler plan Source. Each tick can append one requested child, and ordinary
// TryClaim supplies a NEW fenced owner/lease. No previous deadline is renewed.
// An ineligible original is a HOLD; storage failures remain errors.
func (s CapacityStore) TryRequestGuestRetirementForwardContinuation(ctx context.Context, policy model.Manifest) (bool, error) {
	if s.DB == nil || s.OriginalRunID == uuid.Nil || s.guestReconcile == nil || s.guestReconcile.step.Use.Operation != capacity.PlanOriginalGuestOperation || !guestReconcileLive(ctx) {
		return false, ErrCapacityConflict
	}
	pending, found, err := s.GuestRetirementForwardWaiting(ctx, policy)
	if err != nil || !found {
		return false, err
	}
	if pending.Stage != "admitted" && pending.Stage != "off_qualified" {
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
	if x.policy.ID != policy.ID || x.policy.Checksum != policy.Checksum || x.current.RetirementForward == nil || x.current.RetirementForward.ID != pending.ID || x.current.RetirementForward.Stage != pending.Stage || x.current.LeaseExpiresAt == nil || x.current.LeaseExpiresAt.After(x.now) {
		return false, nil
	}
	if err = s.guestReconcileSourceTx(ctx, tx, policy, x.spec); err != nil {
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
	if parent.Generation != x.current.Generation || parent.Fence != x.current.FencingToken || parent.LeaseOwner != x.current.LeaseOwner || parent.ExecutorID != x.current.LeaseExecutorID || !reflect.DeepEqual(parent.Evidence, x.evidence) || parent.Stage == "terminal" || parent.RunID == "" {
		return false, nil
	}
	failed, err := s.failedForwardRetirementRunTx(ctx, tx, x, parent.RunID)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	proof := &GuestRetirementForwardContinuationProof{RequestingRunID: s.OriginalRunID.String(), Schema: GuestRetirementForwardContinuationSchema, FailedRunID: parent.RunID, FailedRunSHA256: capacity.BusinessCreationSHA256([]byte(failed))}
	// The entire actual dispatch (including its ACK) is pinned. No run inferred
	// from a timestamp or newest-success filter can substitute for this owner.
	var dispatchWire []byte
	err = tx.QueryRowContext(ctx, `SELECT j.id::text,to_jsonb(j)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=$1 AND (SELECT count(*) FROM public.capacity_dispatch_jobs z WHERE z.run_id=j.run_id)=1 AND EXISTS(SELECT 1 FROM jsonb_array_elements(w.result->'steps') step WHERE step->>'id'='finish-original-retirement' AND step->>'status'='failed') AND j.state='returned' AND j.return_status='failed' AND w.status='failed' AND w.finished_at=j.returned_at AND j.finalization_ack_at IS NOT NULL AND j.finalization_ack_at>=j.returned_at AND j.envelope::jsonb#>>'{workflow,id}'=$2 AND w.result#>>'{steps,0,metadata,generation}'=$3 AND w.result#>>'{steps,0,metadata,fencing_token}'=$4 AND w.result#>>'{steps,0,metadata,lease_owner}'=$5`, parent.RunID, x.original.Request.Intent.WorkflowID, parent.Generation, parent.Fence, parent.LeaseOwner).Scan(&proof.DispatchID, &dispatchWire)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	proof.DispatchSHA256 = capacity.BusinessCreationSHA256(dispatchWire)
	var destroy string
	err = tx.QueryRowContext(ctx, `SELECT b.destroy_grant_id::text,b.eligibility_sha256,encode(digest(g.grant_record::text,'sha256'),'hex') FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id WHERE b.intent_id=$1 AND `+capacityGrantUndisposedSQL+` AND g.state='settled'`, parent.RetirementRequestID).Scan(&destroy, &proof.DeleteEligibilitySHA256, &proof.DestroyGrantSHA256)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	original, err := retirementForwardDestroyRecordTx(ctx, tx, admitted, destroy)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	if original.Grant.State != "settled" || original.Settlement == nil || original.Settlement.Outcome != "accepted" || !original.Settlement.TransportCompleted || !original.Settlement.AuxiliaryInventoryComplete {
		return false, nil
	}
	// Never filter out a later malformed/failed read, or an unfinished challenge.
	var open bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads p WHERE p.retirement_request_id=$1 AND p.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.id=p.id AND v.stage='returned'))`, parent.RetirementRequestID).Scan(&open)
	if err != nil {
		return false, err
	}
	if open {
		return false, nil
	}
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_retirement_forward_reads WHERE retirement_request_id=$1 AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1`, parent.RetirementRequestID).Scan(&proof.PendingReadID)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	read, _, readSHA, err := loadForwardReadReturnTx(ctx, tx, proof.PendingReadID)
	if err != nil {
		return false, continuationEligibilityError(err)
	}
	proof.PendingReadSHA256 = readSHA
	if read.Read.AdmissionID != admitted.ID || read.Read.AdmissionSHA256 != admittedSHA || read.Read.Kind != "absence" || read.Read.RetirementRequestID != parent.RetirementRequestID || read.Read.DestroyGrantID != destroy || read.Read.PrefixSHA256 != parent.PrefixSHA256 || read.Read.OriginalCallerSHA256 != parent.OriginalCallerSHA256 || read.Read.Tuple != x.original.Request.Intent.Tuple || read.Read.AdapterSourceCommit != x.binding.OriginalProviderSourceCommit || read.Read.MutationBindingSHA256 != capacity.GuestRetirementSHA(x.binding) || !retirementForwardAbsenceReceiptValid(read, original) || !retirementForwardObserverValid(read, true, RetirementReadonlyAWSObserverSource()) {
		return false, nil
	}
	if read.Read.Tuple.Provider == "aws" {
		if !guestForwardAWSAbsencePending(*read.Observation, *read.OriginalDestroyReceipt) {
			return false, nil
		}
	} else if !guestForwardHetznerAbsencePending(*read.Observation, *read.OriginalDestroyReceipt) {
		return false, nil
	}
	// Keep the pending observation within its real original owner, before that
	// owner's returned failed run; old Pending is not a fresh success claim.
	var timeline bool
	err = tx.QueryRowContext(ctx, `SELECT v.recorded_at<=j.returned_at AND v.recorded_at>=$3 AND v.recorded_at>=p.recorded_at AND v.recorded_at-p.recorded_at+interval '5 seconds'<=$4::int*interval '1 second' AND (v.original_record->>'original_returned_at_core')::timestamptz<=j.returned_at FROM public.capacity_guest_retirement_forward_reads v JOIN public.capacity_guest_retirement_forward_reads p ON p.id=v.id AND p.stage='prepared' JOIN public.capacity_dispatch_jobs j ON j.run_id=$2 WHERE v.id=$1 AND v.stage='returned'`, proof.PendingReadID, parent.RunID, admitted.RecordedAt, x.spec.MaxEvidenceAgeSeconds).Scan(&timeline)
	if err != nil {
		return false, err
	}
	if !timeline {
		return false, nil
	}
	if err = s.installedGuestDispatchRunTx(ctx, tx, policy, x.spec, s.OriginalRunID, nil); err != nil {
		return false, err
	}
	if err = retirementForwardContinuationQuietTx(ctx, tx, x, destroy, s.OriginalRunID.String()); err != nil {
		return false, continuationEligibilityError(err)
	}
	r := forwardRecord(x, s, GuestRetirementForwardContinuationMode, "requested", "source:settled-absence-continuation")
	r.RootAdmissionID = parent.RootAdmissionID
	r.ParentAdmissionID = parent.ID
	r.ParentAdmissionSHA256 = parentSHA
	r.RunID = ""
	r.FailedRun = []byte(failed)
	r.DestroyGrantID = destroy
	r.Continuation = proof
	if _, err = insertRetirementForwardTx(ctx, tx, r); err != nil {
		return false, err
	}
	next := x.current
	next.RetirementForward = retirementForwardMarker(r)
	next.UpdatedAt = x.now
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

func continuationEligibilityError(err error) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrCapacityConflict) || errors.Is(err, ErrCapacityLease) {
		return nil
	}
	return err
}

func retirementForwardContinuationQuietTx(ctx context.Context, tx *sql.Tx, x retirementForwardSnapshot, destroy, ownRun string) error {
	// Retained disposition terminals stay terminal; UNKNOWN and an unacknowledged
	// returned job never become quiet just because their workflow ended.
	var busy int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_dispatch_jobs j WHERE j.run_id::text IS DISTINCT FROM $3 AND ((j.envelope::jsonb#>>'{workflow,namespace}'=$1 AND j.envelope::jsonb#>>'{workflow,name}'=$2) OR j.envelope::jsonb#>>'{workflow,id}' IN(SELECT id::text FROM public.manifests WHERE kind='workflow' AND namespace=$1 AND name=$2)) AND ((j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed')) OR j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL))`, x.spec.Workflow.Namespace, x.spec.Workflow.Name, ownRun).Scan(&busy)
	if err != nil {
		return err
	}
	if busy != 0 {
		return ErrCapacityConflict
	}
	return retirementForwardQuietTx(ctx, tx, x, ownRun, destroy)
}
