package repository

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const GuestRetirementForwardContinuationMode = "settled_absence_continuation"
const GuestRetirementForwardContinuationSchema = "original_settled_absence_continuation_v1"
const GuestRetirementForwardPreReadContinuationSchema = "original_settled_absence_pre_read_continuation_v1"

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
	if parent.Mode == GuestRetirementForwardContinuationMode && read.Read.AdmissionID != admitted.ID {
		eligible, e := s.retirementForwardPreReadContinuationTx(ctx, tx, parent, read, readSHA, original, proof)
		if e != nil || !eligible {
			return false, continuationEligibilityError(e)
		}
		proof.Schema = GuestRetirementForwardPreReadContinuationSchema
	} else {
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

// A failed read-only continuation may have spent its original inventory/floor
// budget before it could prepare even one absence read. Its own failure/ACK and
// expired lease are checked by the caller; an ancestor's immutable Pending is
// only a read/confirm anchor, never fresh absence or a renewed old invocation.
func (s CapacityStore) retirementForwardPreReadContinuationTx(ctx context.Context, tx *sql.Tx, parent GuestRetirementForward, read GuestRetirementForwardReadReturn, readSHA string, original capacityMutationRecord, proof *GuestRetirementForwardContinuationProof) (bool, error) {
	if parent.Mode != GuestRetirementForwardContinuationMode || parent.Stage != "admitted" || parent.Continuation == nil || parent.DestroyGrantID == "" || parent.DestroyGrantID != original.Grant.GrantID || (parent.Continuation.Schema != GuestRetirementForwardContinuationSchema && parent.Continuation.Schema != GuestRetirementForwardPreReadContinuationSchema) {
		return false, nil
	}
	var own int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_retirement_forward_reads WHERE admission_id=$1`, parent.ID).Scan(&own); err != nil {
		return false, err
	}
	if own != 0 || parent.Continuation.PendingReadID != read.Read.ReadID || parent.Continuation.PendingReadSHA256 != readSHA || parent.Continuation.DestroyGrantSHA256 != proof.DestroyGrantSHA256 || parent.Continuation.DeleteEligibilitySHA256 != proof.DeleteEligibilitySHA256 {
		return false, nil
	}
	requested, _, err := loadRetirementForwardTx(ctx, tx, parent.ID, "requested")
	if err != nil {
		return false, err
	}
	if requested.Mode != parent.Mode || requested.RootAdmissionID != parent.RootAdmissionID || requested.ParentAdmissionID != parent.ParentAdmissionID || requested.ParentAdmissionSHA256 != parent.ParentAdmissionSHA256 || requested.RetirementRequestID != parent.RetirementRequestID || requested.DestroyGrantID != parent.DestroyGrantID || !reflect.DeepEqual(requested.Continuation, parent.Continuation) || !reflect.DeepEqual(requested.Evidence, parent.Evidence) || requested.RecordedAt.After(parent.RecordedAt) {
		return false, nil
	}
	anchor, anchorSHA, err := loadRetirementForwardTx(ctx, tx, read.Read.AdmissionID, "admitted")
	if err != nil {
		return false, err
	}
	if anchor.ID == parent.ID || anchor.RootAdmissionID != parent.RootAdmissionID || anchor.RetirementRequestID != parent.RetirementRequestID || anchor.PrefixSHA256 != parent.PrefixSHA256 || anchor.OriginalCallerSHA256 != parent.OriginalCallerSHA256 || !reflect.DeepEqual(anchor.Evidence, parent.Evidence) || !anchor.RecordedAt.Before(parent.RecordedAt) || !read.OriginalReturnedAtCore.Before(parent.RecordedAt) || read.Read.AdmissionSHA256 != anchorSHA || read.Read.Kind != "absence" || read.Read.RetirementRequestID != parent.RetirementRequestID || read.Read.DestroyGrantID != parent.DestroyGrantID || read.Read.PrefixSHA256 != parent.PrefixSHA256 || read.Read.OriginalCallerSHA256 != parent.OriginalCallerSHA256 || read.Read.Tuple != parent.Original.Request.Intent.Tuple || read.Read.AdapterSourceCommit != original.Binding.OriginalProviderSourceCommit || read.Read.MutationBindingSHA256 != capacity.GuestRetirementSHA(original.Binding) || !retirementForwardAbsenceReceiptValid(read, original) || !retirementForwardObserverValid(read, true, RetirementReadonlyAWSObserverSource()) {
		return false, nil
	}
	if read.Read.Tuple.Provider == "aws" {
		if !guestForwardAWSAbsencePending(*read.Observation, *read.OriginalDestroyReceipt) {
			return false, nil
		}
	} else if !guestForwardHetznerAbsencePending(*read.Observation, *read.OriginalDestroyReceipt) {
		return false, nil
	}
	// Exactly one real classic request authenticated this anchor. Later typed
	// pre-read children keep the same anchor; no recursive lineage traversal or
	// newest-success selection can hide a later failed/malformed read.
	rows, err := tx.QueryContext(ctx, `SELECT id::text FROM public.capacity_guest_retirement_forwards WHERE retirement_request_id=$1 AND stage='requested' AND original_record->>'mode'=$2 AND original_record#>>'{continuation,schema}'=$3 AND original_record#>>'{continuation,pending_read_id}'=$4 AND original_record#>>'{continuation,pending_read_sha256}'=$5 AND original_record->>'parent_admission_id'=$6 AND original_record->>'root_admission_id'=$7 ORDER BY id LIMIT 2`, parent.RetirementRequestID, GuestRetirementForwardContinuationMode, GuestRetirementForwardContinuationSchema, read.Read.ReadID, readSHA, anchor.ID, parent.RootAdmissionID)
	if err != nil {
		return false, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		ids = append(ids, id)
	}
	er, cl := rows.Err(), rows.Close()
	if er != nil {
		return false, er
	}
	if cl != nil {
		return false, cl
	}
	if len(ids) != 1 {
		return false, nil
	}
	classic, _, err := loadRetirementForwardTx(ctx, tx, ids[0], "requested")
	if err != nil {
		return false, err
	}
	if classic.Continuation == nil || classic.Continuation.Schema != GuestRetirementForwardContinuationSchema || classic.DestroyGrantID != parent.DestroyGrantID || !reflect.DeepEqual(classic.Evidence, parent.Evidence) {
		return false, nil
	}
	// Revalidate the complete historical classic proof under this NEW actual
	// requester's quiet predicate. The stored request, old failure, read clocks,
	// ACK and SDK are not changed; the old requester need not be live again.
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT public.retirement_forward_continuation_valid(jsonb_set(original_record,'{continuation,requesting_run_id}',to_jsonb($2::text)),retirement_request_id) FROM public.capacity_guest_retirement_forwards WHERE id=$1 AND stage='requested'`, classic.ID, proof.RequestingRunID).Scan(&valid)
	return valid, err
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
	rows, err := tx.QueryContext(ctx, `SELECT j.id,j.state,j.updated_at FROM public.capacity_dispatch_jobs j WHERE j.run_id::text IS DISTINCT FROM $3 AND ((j.envelope::jsonb#>>'{workflow,namespace}'=$1 AND j.envelope::jsonb#>>'{workflow,name}'=$2) OR j.envelope::jsonb#>>'{workflow,id}' IN(SELECT id::text FROM public.manifests WHERE kind='workflow' AND namespace=$1 AND name=$2)) AND ((j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed')) OR j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL))`, x.spec.Workflow.Namespace, x.spec.Workflow.Name, ownRun)
	if err != nil {
		return err
	}
	type candidate struct {
		id        uuid.UUID
		state     sql.NullString
		updatedAt time.Time
	}
	var candidates []candidate
	for rows.Next() {
		var job candidate
		if err = rows.Scan(&job.id, &job.state, &job.updatedAt); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, job)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	// Read complete immutable receipts only for the two new terminal states.
	// Older schemas never query ledgers that do not exist in their prefix.
	for _, job := range candidates {
		if err = retirementContinuationTerminalReceiptTx(ctx, tx, job.id, job.state.String, job.updatedAt); err != nil {
			return err
		}
	}
	return retirementForwardQuietTx(ctx, tx, x, ownRun, destroy)
}

func retirementContinuationTerminalReceiptTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, state string, updatedAt time.Time) error {
	var recordedAt time.Time
	switch state {
	case CapacityDispatchInstalledProvisionTimeoutState:
		receipt, err := readInstalledProvisionTimeoutDisposition(ctx, tx, id)
		if err != nil {
			return err
		}
		recordedAt = receipt.RecordedAt
	case CapacityDispatchPreActionPlanState:
		receipt, err := readPreActionPlanDisposition(ctx, tx, id)
		if err != nil {
			return err
		}
		recordedAt = receipt.RecordedAt
	default:
		return ErrCapacityConflict
	}
	if !updatedAt.Equal(recordedAt) {
		return ErrCapacityConflict
	}
	return nil
}
