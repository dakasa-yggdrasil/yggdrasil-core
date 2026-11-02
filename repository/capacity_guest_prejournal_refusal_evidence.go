package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This is a causal proof of a specific548 refusal, not an assertion that the
// installed application has no prior effects. The original POST remains sent.
type RetirementPrejournalRefusalEvidence struct {
	CausalGuestSource           string `json:"causal_guest_source"`
	SourceOrder                 string `json:"source_order"`
	OriginalCallerSHA256        string `json:"original_caller_sha256"`
	AuthorityReadID             string `json:"authority_read_id"`
	SnapshotChallengeSHA256     string `json:"snapshot_challenge_sha256"`
	SnapshotTransportSHA256     string `json:"snapshot_transport_sha256"`
	AuthenticatedSnapshotSHA256 string `json:"authenticated_snapshot_sha256"`
}

// The metadata schema is the exact original V1 RecordGuestAuthorityTransport
// producer. The signed reply stays private and is independently revalidated.
type prejournalSnapshotTransport struct {
	ReadID                string    `json:"read_id"`
	Stage                 string    `json:"native_stage"`
	OriginalDeadline      time.Time `json:"original_deadline"`
	StartedAt             time.Time `json:"started_at"`
	DoStartedAt           time.Time `json:"do_started_at"`
	DoReturnedAt          time.Time `json:"do_returned_at"`
	ReadReturnedAt        time.Time `json:"read_returned_at"`
	CloseReturnedAt       time.Time `json:"close_returned_at"`
	DriverReturnedAt      time.Time `json:"driver_returned_at"`
	Status                int       `json:"status"`
	ResponseSHA256        string    `json:"response_sha256"`
	ReceivedBodyBytes     int       `json:"received_body_bytes"`
	ResponseBodyScope     string    `json:"response_body_scope"`
	RetainedPrefixBytes   int       `json:"retained_prefix_bytes"`
	RetainedPrefixSHA256  string    `json:"retained_prefix_sha256"`
	PreflightFailed       bool      `json:"preflight_failed"`
	DoFailed              bool      `json:"do_failed"`
	ReadFailed            bool      `json:"read_failed"`
	CloseFailed           bool      `json:"close_failed"`
	OriginalContextFailed bool      `json:"original_context_failed"`
}

func decodePrejournalOriginal(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrCapacityConflict
	}
	b, err := json.Marshal(v)
	if err != nil || !bytes.Equal(b, raw) {
		return ErrCapacityConflict
	}
	return nil
}

func prejournalCallerClosedRefusal(c GuestOriginalCallerReturn, i model.CapacityGuestRetirementIntent) bool {
	// These are the exact548 nativeHandler.problem bytes for Retire's error.
	// A generic HTTP409 or an incomplete/unknown response is never equivalent.
	body, err := json.Marshal(struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}{"guest_retirement.original_attempt_held", 409, "Guest retirement held", "The original Guest retirement requires its enrolled authority and complete original results."})
	body = append(body, '\n')
	digest := capacity.BusinessCreationSHA256(body)
	return err == nil && c.RequestID == i.RequestID && c.AttemptID == i.AttemptID && c.OriginalDeadline.Equal(i.OriginalDeadline) && c.Status == 409 && !c.BodyPersisted && len(c.Body) == 0 && !c.PreflightFailed && !c.DoFailed && !c.ReadFailed && !c.CloseFailed && !c.OriginalContextFailed && c.ResponseBodyScope == capacity.GuestOriginalBodyCompleteRead && c.ReceivedBodyBytes == len(body) && c.RetainedPrefixBytes == len(body) && c.ResponseSHA256 == digest && c.RetainedPrefixSHA256 == digest && GuestOriginalCallerBodyFactsValid(c) && !c.StartedAt.Before(i.IssuedAt) && !c.DoStartedAt.Before(c.StartedAt) && !c.DoReturnedAt.Before(c.DoStartedAt) && !c.ReadReturnedAt.Before(c.DoReturnedAt) && !c.CloseReturnedAt.Before(c.ReadReturnedAt) && !c.DriverReturnedAt.Before(c.CloseReturnedAt) && c.DriverReturnedAt.Before(i.OriginalDeadline)
}

func prejournalSnapshotClosed(t prejournalSnapshotTransport, reply []byte, c GuestOriginalCallerReturn, readID string, possible, deadline time.Time) bool {
	digest := capacity.BusinessCreationSHA256(reply)
	return t.ReadID == readID && t.Stage == "snapshot" && t.OriginalDeadline.Equal(deadline) && t.Status == 200 && !t.PreflightFailed && !t.DoFailed && !t.ReadFailed && !t.CloseFailed && !t.OriginalContextFailed && t.ResponseBodyScope == capacity.GuestOriginalBodyCompleteRead && len(reply) > 0 && len(reply) <= capacity.GuestBootstrapLimit && t.ReceivedBodyBytes == len(reply) && t.RetainedPrefixBytes == len(reply) && t.ResponseSHA256 == digest && t.RetainedPrefixSHA256 == digest && !possible.Before(c.DoStartedAt) && !t.StartedAt.Before(possible) && !t.DoStartedAt.Before(t.StartedAt) && !t.DoReturnedAt.Before(t.DoStartedAt) && !t.ReadReturnedAt.Before(t.DoReturnedAt) && !t.CloseReturnedAt.Before(t.ReadReturnedAt) && !t.DriverReturnedAt.Before(t.CloseReturnedAt) && !t.DriverReturnedAt.After(c.DoReturnedAt) && t.DriverReturnedAt.Before(deadline) && !deadline.After(c.OriginalDeadline)
}

// Caller and authority-qualifying callbacks hold the same mutation-scope lock. Once the
// original deadline has expired, no late callback can qualify that operation.
func retirementPrejournalRefusedTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) (RetirementPrejournalRefusalEvidence, error) {
	var out RetirementPrejournalRefusalEvidence
	i := stored.Request.Intent
	if stored.Binding.GuestSourceCommit != failedInstalledLegacyGuestSource || stored.Receipt.Enrollment.Statement.Actor.SourceCommit != failedInstalledLegacyGuestSource || stored.Receipt.Enrollment.Statement.Runtime.SourceCommit != failedInstalledLegacyGuestSource {
		return out, ErrCapacityConflict
	}
	var deadline time.Time
	var canonicalDeadline string
	if err := tx.QueryRowContext(ctx, `SELECT original_deadline,intent_record->>'original_deadline' FROM public.capacity_vm_retirement_intents WHERE id=$1 FOR UPDATE`, i.RequestID).Scan(&deadline, &canonicalDeadline); err != nil {
		return out, err
	}
	original, err := time.Parse(time.RFC3339Nano, canonicalDeadline)
	if err != nil || deadline.After(now) || original.After(now) || !original.Equal(i.OriginalDeadline) {
		return out, ErrCapacityConflict
	}
	var attempts, callers, reads, challenges, transports, forbidden, otherRecovery int
	err = tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns t JOIN public.capacity_guest_original_authority_reads r ON r.id=t.read_id WHERE r.intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_returns s JOIN public.capacity_guest_runtime_snapshot_challenges c ON c.id=s.challenge_id WHERE c.intent_id=$1)+
 (SELECT count(*) FROM public.capacity_guest_original_authority_returns a JOIN public.capacity_guest_original_authority_reads r ON r.id=a.read_id WHERE r.intent_id=$1)+
 (SELECT count(*) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)+
 (SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_presend_retirement_recoveries WHERE preregistration_id=$2)`, i.RequestID, stored.Preregistration.PreregistrationID).Scan(&attempts, &callers, &reads, &challenges, &transports, &forbidden, &otherRecovery)
	if err != nil {
		return out, err
	}
	if attempts != 1 || callers != 1 || reads != 1 || challenges != 1 || transports != 1 || forbidden != 0 || otherRecovery != 0 {
		return out, ErrCapacityConflict
	}
	var callerWire, challengeWire, transportWire, snapshotWire []byte
	var callerSHA, attempt, readID, phase, challengeSHA, transportSHA string
	var possible, readDeadline time.Time
	var ordinal int
	var consistent bool
	err = tx.QueryRowContext(ctx, `SELECT c.original_wire,c.return_sha256,a.attempt_id::text,r.id::text,r.phase,r.ordinal,r.possible_read_at,r.original_deadline,s.original_wire,s.challenge_sha256,t.original_wire,t.return_sha256,t.original_reply_wire,
 c.original_record=convert_from(c.original_wire,'UTF8')::jsonb AND s.original_record=convert_from(s.original_wire,'UTF8')::jsonb AND t.original_record=convert_from(t.original_wire,'UTF8')::jsonb AND r.original_deadline=(s.original_record->>'original_deadline')::timestamptz AND r.original_deadline=(t.original_record->>'original_deadline')::timestamptz
 FROM public.capacity_guest_original_caller_returns c JOIN public.capacity_guest_original_caller_attempts a ON a.intent_id=c.intent_id
 JOIN public.capacity_guest_original_authority_reads r ON r.intent_id=c.intent_id
 JOIN public.capacity_guest_runtime_snapshot_challenges s ON s.intent_id=r.intent_id AND s.phase=r.phase AND s.ordinal=r.ordinal
 JOIN public.capacity_guest_original_authority_transport_returns t ON t.read_id=r.id AND t.native_stage='snapshot'
 WHERE c.intent_id=$1`, i.RequestID).Scan(&callerWire, &callerSHA, &attempt, &readID, &phase, &ordinal, &possible, &readDeadline, &challengeWire, &challengeSHA, &transportWire, &transportSHA, &snapshotWire, &consistent)
	if err != nil {
		return out, err
	}
	var caller GuestOriginalCallerReturn
	var challenge model.CapacityGuestRuntimeSnapshotChallenge
	var transport prejournalSnapshotTransport
	var snapshot model.CapacityGuestRuntimeSnapshot
	if !consistent || attempt != i.AttemptID || phase != "before_start" || ordinal != 1 || capacity.BusinessCreationSHA256(callerWire) != callerSHA || capacity.BusinessCreationSHA256(challengeWire) != challengeSHA || capacity.BusinessCreationSHA256(transportWire) != transportSHA || decodePrejournalOriginal(callerWire, &caller) != nil || capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || decodePrejournalOriginal(transportWire, &transport) != nil || capacity.DecodeGuestLifecycle(snapshotWire, &snapshot) != nil || !prejournalCallerClosedRefusal(caller, i) || !prejournalSnapshotClosed(transport, snapshotWire, caller, readID, possible, challenge.OriginalDeadline) || challenge.ChallengeID != snapshot.ChallengeID || challenge.Phase != phase || capacity.GuestRetirementSHA(challenge) != challengeSHA || capacity.GuestRuntimeSnapshot(challenge, stored.Receipt.Enrollment, i, snapshot, transport.DriverReturnedAt) != nil {
		return out, ErrCapacityConflict
	}
	// In exact548, an existing journal goes straight to Observe with no authority
	// read. For a new attempt, first live(before_start) must receive Core200 before
	// Journal.Reserve, Runs.begin or Driver.Retire. No authority-return row means
	// this first Core read could not have produced its authorized200 response.
	return RetirementPrejournalRefusalEvidence{CausalGuestSource: failedInstalledLegacyGuestSource, SourceOrder: "guest548_first_authority_before_journal_v1", OriginalCallerSHA256: callerSHA, AuthorityReadID: readID, SnapshotChallengeSHA256: challengeSHA, SnapshotTransportSHA256: transportSHA, AuthenticatedSnapshotSHA256: capacity.BusinessCreationSHA256(snapshotWire)}, nil
}
