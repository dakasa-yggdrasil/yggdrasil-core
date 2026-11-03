package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Historical authenticated facts, never a claim that the original poweroff
// command returned or that the original caller succeeded.
type PartialNativeOffEvidence struct {
	GuestSource             string    `json:"guest_source"`
	SourceOrder             string    `json:"source_order"`
	CallerSHA256            string    `json:"caller_sha256"`
	ObservationSHA256       [3]string `json:"observation_sha256"`
	AuthoritySHA256         [4]string `json:"authority_sha256"`
	TransportSHA256         [5]string `json:"transport_sha256"`
	SnapshotChallengeSHA256 [2]string `json:"snapshot_challenge_sha256"`
	SnapshotReturnSHA256    [2]string `json:"snapshot_return_sha256"`
}

func partialNativeTransportClosed(t prejournalSnapshotTransport, stage string, reply []byte, caller GuestOriginalCallerReturn, id string, possible, deadline time.Time) bool {
	digest := capacity.BusinessCreationSHA256(reply)
	return t.ReadID == id && t.Stage == stage && t.OriginalDeadline.Equal(deadline) && t.Status == 200 && !t.PreflightFailed && !t.DoFailed && !t.ReadFailed && !t.CloseFailed && !t.OriginalContextFailed && t.ResponseBodyScope == capacity.GuestOriginalBodyCompleteRead && len(reply) > 0 && len(reply) <= capacity.GuestBootstrapLimit && t.ReceivedBodyBytes == len(reply) && t.RetainedPrefixBytes == len(reply) && t.ResponseSHA256 == digest && t.RetainedPrefixSHA256 == digest && !possible.Before(caller.DoStartedAt) && !t.StartedAt.Before(possible) && !t.DoStartedAt.Before(t.StartedAt) && !t.DoReturnedAt.Before(t.DoStartedAt) && !t.ReadReturnedAt.Before(t.DoReturnedAt) && !t.CloseReturnedAt.Before(t.ReadReturnedAt) && !t.DriverReturnedAt.Before(t.CloseReturnedAt) && !t.DriverReturnedAt.After(caller.DoReturnedAt) && t.DriverReturnedAt.Before(deadline) && !deadline.After(caller.OriginalDeadline)
}

// All callbacks use the same scope lock and a shared parent63 lock. The caller
// holds the scope lock; FOR UPDATE serializes this snapshot with late retention.
func partialNativeOffEvidenceTx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) (PartialNativeOffEvidence, error) {
	var out PartialNativeOffEvidence
	i := stored.Request.Intent
	if stored.Binding.GuestSourceCommit != failedInstalledLegacyGuestSource || stored.Receipt.Enrollment.Statement.Actor.SourceCommit != failedInstalledLegacyGuestSource || stored.Receipt.Enrollment.Statement.Runtime.SourceCommit != failedInstalledLegacyGuestSource {
		return out, ErrCapacityConflict
	}
	var deadline time.Time
	if err := tx.QueryRowContext(ctx, `SELECT original_deadline FROM public.capacity_vm_retirement_intents WHERE id=$1 FOR UPDATE`, i.RequestID).Scan(&deadline); err != nil {
		return out, err
	}
	if deadline.After(now) || i.OriginalDeadline.After(now) {
		return out, ErrCapacityConflict
	}
	var counts [9]int
	err := tx.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_returns v JOIN public.capacity_guest_runtime_snapshot_challenges r ON r.id=v.challenge_id WHERE r.intent_id=$1),
 (SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=$1),
 (SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=$1)+(SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=$1)`, i.RequestID).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5], &counts[6], &counts[7], &counts[8])
	if err != nil {
		return out, err
	}
	if counts != [9]int{1, 1, 3, 4, 4, 2, 2, 5, 0} {
		return out, ErrCapacityConflict
	}
	var caller GuestOriginalCallerReturn
	var callerWire []byte
	var consistent bool
	var attempt string
	if err = tx.QueryRowContext(ctx, `SELECT c.original_wire,c.return_sha256,c.original_record=convert_from(c.original_wire,'UTF8')::jsonb,a.attempt_id::text FROM public.capacity_guest_original_caller_returns c JOIN public.capacity_guest_original_caller_attempts a ON a.intent_id=c.intent_id WHERE c.intent_id=$1`, i.RequestID).Scan(&callerWire, &out.CallerSHA256, &consistent, &attempt); err != nil {
		return out, err
	}
	if !consistent || attempt != i.AttemptID || capacity.BusinessCreationSHA256(callerWire) != out.CallerSHA256 || decodePrejournalOriginal(callerWire, &caller) != nil || !prejournalCallerClosedRefusal(caller, i) {
		return out, ErrCapacityConflict
	}
	var observations [3]model.CapacityGuestRetirementObservation
	var observationWires [3][]byte
	for n := range observations {
		var sequence int
		var kind string
		if err = tx.QueryRowContext(ctx, `SELECT sequence,kind,original_wire,return_sha256,original_return_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 AND sequence=$2`, i.RequestID, n+1).Scan(&sequence, &kind, &observationWires[n], &out.ObservationSHA256[n], &consistent); err != nil {
			return out, err
		}
		o := &observations[n]
		if !consistent || capacity.DecodeGuestLifecycle(observationWires[n], o) != nil || o.Record.Sequence != n+1 || sequence != n+1 || kind != []string{"possible_start", "quiescent", "poweroff_possible_start"}[n] || o.Record.State != kind || o.RecordSHA256 != out.ObservationSHA256[n] || !capacity.GuestRetirementObservedReturnAuthentic(*o, stored.Receipt.Enrollment, i, now) {
			return out, ErrCapacityConflict
		}
		if n > 0 && !capacity.GuestRetirementRecordSuccessor(observations[n-1].Record, o.Record) {
			return out, ErrCapacityConflict
		}
	}
	transportIndex := 0
	var previous time.Time
	for n := 0; n < 4; n++ {
		phase, ordinal := "before_start", n+1
		if n >= 2 {
			phase, ordinal = "before_poweroff", n-1
		}
		var id string
		var possible, readDeadline, recorded time.Time
		var wire []byte
		if err = tx.QueryRowContext(ctx, `SELECT r.id::text,r.possible_read_at,r.original_deadline,v.original_wire,v.authority_sha256,v.recorded_at,v.original_record=convert_from(v.original_wire,'UTF8')::jsonb FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=$1 AND r.phase=$2 AND r.ordinal=$3`, i.RequestID, phase, ordinal).Scan(&id, &possible, &readDeadline, &wire, &out.AuthoritySHA256[n], &recorded, &consistent); err != nil {
			return out, err
		}
		var a model.CapacityGuestRetirementAuthority
		if !consistent || capacity.DecodeGuestLifecycle(wire, &a) != nil || capacity.BusinessCreationSHA256(wire) != out.AuthoritySHA256[n] || a.Schema != capacity.GuestRetirementSchema || a.Purpose != capacity.GuestRetirementPurpose || a.Phase != phase || a.State != "authorized" || a.IntentSHA256 != capacity.GuestRetirementSHA(i) || a.AttemptID != i.AttemptID || a.NonceSHA256 != i.NonceSHA256 || a.EnrollmentSHA256 != i.EnrollmentSHA256 || a.SourceCommit != stored.Binding.CoreAuthoritySourceCommit || !a.OriginalDeadline.Equal(i.OriginalDeadline) || a.ObservedAt.Before(possible) || a.ObservedAt.After(recorded) || !recorded.Before(readDeadline) || possible.Before(previous) || possible.Before(caller.DoStartedAt) || recorded.After(caller.DoReturnedAt) {
			return out, ErrCapacityConflict
		}
		previous = recorded
		stages := []string{"journal"}
		if phase == "before_start" {
			stages = []string{"snapshot"}
			if ordinal == 2 {
				stages = append(stages, "journal")
			}
		}
		var originalReadDeadline time.Time
		for _, stage := range stages {
			var transportWire, reply []byte
			var transport prejournalSnapshotTransport
			if err = tx.QueryRowContext(ctx, `SELECT original_wire,return_sha256,original_reply_wire,original_record=convert_from(original_wire,'UTF8')::jsonb AND (original_record->>'original_deadline')::timestamptz=$3::timestamptz FROM public.capacity_guest_original_authority_transport_returns WHERE read_id=$1 AND native_stage=$2`, id, stage, readDeadline).Scan(&transportWire, &out.TransportSHA256[transportIndex], &reply, &consistent); err != nil {
				return out, err
			}
			if !consistent || capacity.BusinessCreationSHA256(transportWire) != out.TransportSHA256[transportIndex] || decodePrejournalOriginal(transportWire, &transport) != nil {
				return out, ErrCapacityConflict
			}
			// The immutable original wire retains nanoseconds; timestamptz is
			// only its checked PostgreSQL projection. Keep the original deadline
			// for exact timing and require sibling stages of this read to match.
			if originalReadDeadline.IsZero() {
				originalReadDeadline = transport.OriginalDeadline
			}
			if !partialNativeTransportClosed(transport, stage, reply, caller, id, possible, originalReadDeadline) || transport.DriverReturnedAt.After(recorded) {
				return out, ErrCapacityConflict
			}
			transportIndex++
			if stage == "snapshot" {
				var challengeWire, snapshotWire []byte
				var challenge model.CapacityGuestRuntimeSnapshotChallenge
				var snapshot model.CapacityGuestRuntimeSnapshot
				k := ordinal - 1
				if err = tx.QueryRowContext(ctx, `SELECT c.original_wire,c.challenge_sha256,v.original_wire,v.return_sha256,c.original_record=convert_from(c.original_wire,'UTF8')::jsonb AND v.original_record=convert_from(v.original_wire,'UTF8')::jsonb FROM public.capacity_guest_runtime_snapshot_challenges c JOIN public.capacity_guest_runtime_snapshot_returns v ON v.challenge_id=c.id WHERE c.intent_id=$1 AND c.phase=$2 AND c.ordinal=$3`, i.RequestID, phase, ordinal).Scan(&challengeWire, &out.SnapshotChallengeSHA256[k], &snapshotWire, &out.SnapshotReturnSHA256[k], &consistent); err != nil {
					return out, err
				}
				if !consistent || capacity.DecodeGuestLifecycle(challengeWire, &challenge) != nil || capacity.DecodeGuestLifecycle(snapshotWire, &snapshot) != nil || capacity.BusinessCreationSHA256(challengeWire) != out.SnapshotChallengeSHA256[k] || capacity.BusinessCreationSHA256(snapshotWire) != out.SnapshotReturnSHA256[k] || !bytes.Equal(reply, snapshotWire) || !challenge.OriginalDeadline.Equal(originalReadDeadline) || capacity.GuestRuntimeSnapshot(challenge, stored.Receipt.Enrollment, i, snapshot, transport.DriverReturnedAt) != nil {
					return out, ErrCapacityConflict
				}
			} else {
				k := 0
				if phase == "before_poweroff" {
					k = ordinal
				}
				// Complete original validator at the retained original transport instant,
				// not a fabricated fresh epoch or a weakened current-time comparison.
				if !bytes.Equal(reply, observationWires[k]) || capacity.GuestRetirementObservation(observations[k], stored.Receipt.Enrollment, i, transport.DriverReturnedAt, true) != nil {
					return out, ErrCapacityConflict
				}
			}
		}
	}
	if transportIndex != 5 {
		return out, ErrCapacityConflict
	}
	out.GuestSource = failedInstalledLegacyGuestSource
	out.SourceOrder = "guest548_quiescent_then_poweroff_possible_v1"
	return out, nil
}

func partialEvidenceSHA(e PartialNativeOffEvidence) string {
	b, _ := json.Marshal(e)
	return capacity.BusinessCreationSHA256(b)
}
