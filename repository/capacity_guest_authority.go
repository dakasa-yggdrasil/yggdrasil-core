package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This is an internal ORIGINAL caller receipt, authored by the actual source
// HTTP driver after Do/Read/Close return. No HTTP callback accepts these flags.
type GuestOriginalCallerReturn struct {
	RequestID             string    `json:"request_id"`
	AttemptID             string    `json:"attempt_id"`
	StartedAt             time.Time `json:"started_at"`
	DoStartedAt           time.Time `json:"do_started_at"`
	DriverReturnedAt      time.Time `json:"driver_returned_at"`
	PreflightFailed       bool      `json:"preflight_failed"`
	DoReturnedAt          time.Time `json:"do_returned_at"`
	ReadReturnedAt        time.Time `json:"read_returned_at"`
	CloseReturnedAt       time.Time `json:"close_returned_at"`
	OriginalDeadline      time.Time `json:"original_deadline"`
	Status                int       `json:"status"`
	Body                  []byte    `json:"body"`
	ReceivedBodyBytes     int       `json:"received_body_bytes"`
	BodyPersisted         bool      `json:"body_persisted"`
	ResponseSHA256        string    `json:"response_sha256"`
	ResponseBodyScope     string    `json:"response_body_scope"`
	RetainedPrefixBytes   int       `json:"retained_prefix_bytes"`
	RetainedPrefixSHA256  string    `json:"retained_prefix_sha256"`
	DoFailed              bool      `json:"do_failed"`
	ReadFailed            bool      `json:"read_failed"`
	CloseFailed           bool      `json:"close_failed"`
	OriginalContextFailed bool      `json:"original_context_failed"`
}

func GuestOriginalCallerBodyFactsValid(result GuestOriginalCallerReturn) bool {
	return capacity.GuestOriginalHTTPBodyFactsValid(result.ResponseBodyScope, result.ReadReturnedAt, result.ReceivedBodyBytes, result.ResponseSHA256, result.RetainedPrefixBytes, result.RetainedPrefixSHA256, result.ReadFailed) && ((!result.BodyPersisted && len(result.Body) == 0) || (result.BodyPersisted && result.ResponseBodyScope == capacity.GuestOriginalBodyCompleteRead && result.ReceivedBodyBytes == len(result.Body) && result.RetainedPrefixBytes == len(result.Body) && result.ResponseSHA256 == capacity.BusinessCreationSHA256(result.Body) && result.RetainedPrefixSHA256 == result.ResponseSHA256 && !result.PreflightFailed && !result.DoFailed && !result.ReadFailed && !result.CloseFailed && !result.OriginalContextFailed && result.Status == 200))
}

func (s CapacityStore) RecordGuestCallerReturn(ctx context.Context, result GuestOriginalCallerReturn) error {
	return s.guestRetirementTransaction(ctx, result.RequestID, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		i := stored.Request.Intent
		if result.AttemptID != i.AttemptID || !result.OriginalDeadline.Equal(i.OriginalDeadline) || result.StartedAt.Before(i.IssuedAt) || result.DriverReturnedAt.Before(result.StartedAt) || result.DriverReturnedAt.After(now) || !GuestOriginalCallerBodyFactsValid(result) {
			return ErrCapacityConflict
		}
		if result.PreflightFailed {
			if !result.DoStartedAt.IsZero() || !result.DoReturnedAt.IsZero() || !result.ReadReturnedAt.IsZero() || !result.CloseReturnedAt.IsZero() || result.Status != 0 || len(result.Body) != 0 {
				return ErrCapacityConflict
			}
		} else if result.DoStartedAt.Before(result.StartedAt) || result.DoReturnedAt.Before(result.DoStartedAt) || result.DoReturnedAt.After(result.DriverReturnedAt) || (!result.CloseReturnedAt.IsZero() && (result.CloseReturnedAt.Before(result.DoReturnedAt) || result.CloseReturnedAt.After(result.DriverReturnedAt))) || (!result.ReadReturnedAt.IsZero() && (result.ReadReturnedAt.Before(result.DoReturnedAt) || result.CloseReturnedAt.Before(result.ReadReturnedAt) || result.CloseReturnedAt.After(result.DriverReturnedAt))) || (!result.DoFailed && (result.ReadReturnedAt.IsZero() || result.CloseReturnedAt.IsZero())) {
			return ErrCapacityConflict
		}
		var attempt string
		if err := tx.QueryRowContext(ctx, `SELECT attempt_id::text FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, result.RequestID).Scan(&attempt); err != nil || attempt != result.AttemptID {
			return ErrCapacityConflict
		}
		if !result.BodyPersisted {
			result.Body = []byte{}
		}
		wire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_caller_returns(intent_id,return_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5)`, result.RequestID, capacity.GuestRetirementSHA(result), wire, string(wire), now)
		return err
	})
}

type GuestOriginalAuthorityRead struct {
	ReadID    string
	Ordinal   int
	Phase     string
	Deadline  time.Time
	Original  GuestRetirementOriginal
	Challenge *model.CapacityGuestRuntimeSnapshotChallenge
}

// The ORIGINAL read identity and challenge are committed BEFORE the GET.
// The first pre-Reserve read uses the separate snapshot. Every subsequent
// read must join the actual signed journal and currently active attempt.
func (s CapacityStore) ReserveGuestAuthorityRead(ctx context.Context, principal, id, intentSHA, phase string, intentKey ed25519.PrivateKey) (GuestOriginalAuthorityRead, error) {
	var result GuestOriginalAuthorityRead
	err := s.guestRetirementTransaction(ctx, id, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		if principal != stored.Member.ActorClientPrincipal || intentSHA != capacity.GuestRetirementSHA(stored.Request.Intent) || (phase != "before_start" && phase != "before_poweroff") || !capacity.GuestLifecycleKeyMatches(intentKey, stored.Receipt.Enrollment.Statement.CoreIntentPublicKey) {
			return ErrCapacityMutationAuthorization
		}
		_, _, current, err := s.guestRetirementCurrentTx(ctx, tx, stored, now, true)
		if err != nil {
			return err
		}
		var attempt string
		if err = tx.QueryRowContext(ctx, `SELECT attempt_id::text FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, id).Scan(&attempt); err != nil || attempt != stored.Request.Intent.AttemptID {
			return ErrCapacityConflict
		}
		deadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || !deadline.After(now) || current.LeaseExpiresAt == nil {
			return ErrCapacityConflict
		}
		for _, bound := range []time.Time{stored.Request.Intent.OriginalDeadline, *current.LeaseExpiresAt, now.Add(time.Duration(stored.Binding.MaxEvidenceAgeSeconds) * time.Second)} {
			if bound.Before(deadline) {
				deadline = bound
			}
		}
		var ordinal int
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max(ordinal),0)+1 FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1 AND phase=$2`, id, phase).Scan(&ordinal); err != nil {
			return err
		}
		if ordinal > 2 {
			return fmt.Errorf("%w: original authority read already reserved; recover by GET", ErrCapacityConflict)
		}
		result = GuestOriginalAuthorityRead{ReadID: uuid.NewString(), Ordinal: ordinal, Phase: phase, Deadline: deadline, Original: stored}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_reads(id,intent_id,phase,ordinal,original_deadline,possible_read_at) VALUES($1,$2,$3,$4,$5,$6)`, result.ReadID, id, phase, ordinal, deadline, now)
		if err != nil {
			return err
		}
		if phase == "before_start" {
			i := stored.Request.Intent
			challenge := model.CapacityGuestRuntimeSnapshotChallenge{Schema: capacity.GuestSnapshotSchema, Purpose: capacity.GuestSnapshotPurpose, ChallengeID: uuid.NewString(), BindingName: i.BindingName, Slot: i.Slot, PreregistrationID: stored.Preregistration.PreregistrationID, PreregistrationNonceSHA256: stored.Preregistration.NonceSHA256, OriginalRegistrationSHA256: stored.RegistrationSHA, OriginalCreateWitnessSHA256: stored.WitnessSHA, EnrollmentSHA256: i.EnrollmentSHA256, ProfileManifestSHA256: stored.Binding.ProfileManifestSHA256, Tuple: i.Tuple, RequestID: i.RequestID, AttemptID: i.AttemptID, IntentSHA256: intentSHA, Phase: phase, PolicyID: i.PolicyID, PolicyChecksum: i.PolicyChecksum, WorkflowID: i.WorkflowID, WorkflowChecksum: i.WorkflowChecksum, Generation: i.Generation, Fence: i.Fence, LeaseOwner: i.LeaseOwner, CoreSourceCommit: stored.Binding.CoreAuthoritySourceCommit, IssuedAt: now, OriginalDeadline: deadline}
			challenge.Signature, err = capacity.GuestLifecycleSignature(intentKey, challenge)
			if err != nil {
				return err
			}
			wire, err := json.Marshal(challenge)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_runtime_snapshot_challenges(id,intent_id,phase,ordinal,challenge_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`, challenge.ChallengeID, id, phase, ordinal, capacity.GuestRetirementSHA(challenge), wire, string(wire), deadline, now)
			result.Challenge = &challenge
		}
		return err
	})
	return result, err
}

func (s CapacityStore) RecordGuestSnapshot(ctx context.Context, read GuestOriginalAuthorityRead, snapshot model.CapacityGuestRuntimeSnapshot) error {
	return s.guestRetirementTransaction(ctx, read.Original.Request.Intent.RequestID, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		if read.Challenge == nil || read.Phase != "before_start" || ctx.Err() != nil || !now.Before(read.Deadline) {
			return ErrCapacityConflict
		}
		if _, _, _, err := s.guestRetirementCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		var wire []byte
		var digest string
		if err := tx.QueryRowContext(ctx, `SELECT original_wire,challenge_sha256 FROM public.capacity_guest_runtime_snapshot_challenges WHERE id=$1 AND intent_id=$2 AND phase=$3 AND ordinal=$4`, read.Challenge.ChallengeID, stored.Request.Intent.RequestID, read.Phase, read.Ordinal).Scan(&wire, &digest); err != nil {
			return err
		}
		var challenge model.CapacityGuestRuntimeSnapshotChallenge
		if capacity.DecodeGuestLifecycle(wire, &challenge) != nil || capacity.GuestRetirementSHA(challenge) != digest || challenge != *read.Challenge || capacity.GuestRuntimeSnapshot(challenge, stored.Receipt.Enrollment, stored.Request.Intent, snapshot, now) != nil {
			return ErrCapacityConflict
		}
		wire, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_runtime_snapshot_returns(challenge_id,return_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5)`, challenge.ChallengeID, capacity.GuestRetirementSHA(snapshot), wire, string(wire), now)
		return err
	})
}

// This is called only after the source transport's full original Read/Close
// return. Both phases recheck current authority AFTER every external read.
func (s CapacityStore) FinishGuestAuthorityRead(ctx context.Context, read GuestOriginalAuthorityRead, observation *model.CapacityGuestRetirementObservation) (model.CapacityGuestRetirementAuthority, error) {
	var result model.CapacityGuestRetirementAuthority
	err := s.guestRetirementTransaction(ctx, read.Original.Request.Intent.RequestID, func(tx *sql.Tx, stored GuestRetirementOriginal, now time.Time) error {
		if ctx.Err() != nil || !now.Before(read.Deadline) || stored.Request.Intent != read.Original.Request.Intent {
			return ErrCapacityConflict
		}
		if _, _, _, err := s.guestRetirementCurrentTx(ctx, tx, stored, now, true); err != nil {
			return err
		}
		var phase string
		var ordinal int
		var deadline time.Time
		if err := tx.QueryRowContext(ctx, `SELECT phase,ordinal,original_deadline FROM public.capacity_guest_original_authority_reads WHERE id=$1 AND intent_id=$2`, read.ReadID, stored.Request.Intent.RequestID).Scan(&phase, &ordinal, &deadline); err != nil || phase != read.Phase || ordinal != read.Ordinal {
			return ErrCapacityConflict
		}
		// Compare in PostgreSQL's OWN representation; never Round or tolerate
		// a different signed instant to make it match the native timestamp.
		var deadlineMatches bool
		if err := tx.QueryRowContext(ctx, `SELECT original_deadline=$2::timestamptz FROM public.capacity_guest_original_authority_reads WHERE id=$1`, read.ReadID, read.Deadline).Scan(&deadlineMatches); err != nil || !deadlineMatches {
			return ErrCapacityConflict
		}
		if phase == "before_start" {
			if read.Challenge == nil {
				return ErrCapacityConflict
			}
			var wire []byte
			if err := tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_runtime_snapshot_returns WHERE challenge_id=$1`, read.Challenge.ChallengeID).Scan(&wire); err != nil {
				return ErrCapacityConflict
			}
			var snapshot model.CapacityGuestRuntimeSnapshot
			if capacity.DecodeGuestLifecycle(wire, &snapshot) != nil || capacity.GuestRuntimeSnapshot(*read.Challenge, stored.Receipt.Enrollment, stored.Request.Intent, snapshot, now) != nil {
				return ErrCapacityConflict
			}
		}
		if phase == "before_poweroff" || ordinal > 1 {
			if observation == nil || capacity.GuestRetirementObservation(*observation, stored.Receipt.Enrollment, stored.Request.Intent, now, true) != nil || (phase == "before_start" && observation.Record.Sequence != 1) || (phase == "before_poweroff" && (observation.Record.Sequence != ordinal+1 || !observation.Record.WriterQuiescenceEvidence)) {
				return ErrCapacityConflict
			}
			var digest string
			if err := tx.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 AND sequence=$2`, stored.Request.Intent.RequestID, observation.Record.Sequence).Scan(&digest); err != nil || digest != observation.RecordSHA256 {
				return ErrCapacityConflict
			}
		}
		i := stored.Request.Intent
		state := "authorized"
		if phase == "before_poweroff" {
			state = "authorized"
		}
		result = model.CapacityGuestRetirementAuthority{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, Phase: phase, IntentSHA256: capacity.GuestRetirementSHA(i), AttemptID: i.AttemptID, NonceSHA256: i.NonceSHA256, EnrollmentSHA256: i.EnrollmentSHA256, State: state, SourceCommit: stored.Binding.CoreAuthoritySourceCommit, OriginalDeadline: i.OriginalDeadline, ObservedAt: now}
		wire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_returns(read_id,authority_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5)`, read.ReadID, capacity.GuestRetirementSHA(result), wire, string(wire), now)
		return err
	})
	return result, err
}
