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

type GuestOriginalAuthorityReadV2 struct {
	ReadID    string
	Ordinal   int
	Phase     string
	StartedAt time.Time
	Deadline  time.Time
	Original  GuestRetirementOriginalV2
}

func (s CapacityStore) ReserveGuestAuthorityReadV2(ctx context.Context, principal, id, intentSHA, phase string) (GuestOriginalAuthorityReadV2, error) {
	var out GuestOriginalAuthorityReadV2
	err := s.guestRetirementV2Transaction(ctx, id, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		if principal != stored.Member.ActorClientPrincipal || intentSHA != capacity.GuestRetirementSHA(stored.Request.Intent) || (phase != "before_start" && phase != "before_poweroff") {
			return ErrCapacityMutationAuthorization
		}
		_, _, current, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, nowPG, true)
		if err != nil {
			return err
		}
		var attempt, requestSHA string
		if err = tx.QueryRowContext(ctx, `SELECT attempt_id::text,request_sha256 FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, id).Scan(&attempt, &requestSHA); err != nil || attempt != stored.Request.Intent.AttemptID || requestSHA != stored.RequestSHA256 {
			return ErrCapacityConflict
		}
		originalDeadline, ok := ctx.Deadline()
		if !ok || ctx.Err() != nil || current.LeaseExpiresAt == nil {
			return ErrCapacityConflict
		}
		sampleStarted := time.Now()
		var leaseNow time.Time
		if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&leaseNow); err != nil {
			return err
		}
		started := time.Now()
		budget := min(5*time.Second, originalDeadline.Sub(started), stored.Request.Intent.OriginalDeadline.Sub(started), current.LeaseExpiresAt.Sub(leaseNow)-started.Sub(sampleStarted))
		if budget <= 0 {
			return ErrCapacityLease
		}
		deadline := started.Add(budget).UTC()
		started = started.UTC()
		var ordinal int
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max(ordinal),0)+1 FROM public.capacity_guest_original_authority_reads WHERE intent_id=$1 AND phase=$2`, id, phase).Scan(&ordinal); err != nil {
			return err
		}
		if ordinal > 2 {
			return ErrCapacityConflict
		}
		out = GuestOriginalAuthorityReadV2{ReadID: uuid.NewString(), Ordinal: ordinal, Phase: phase, StartedAt: started, Deadline: deadline, Original: stored}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_reads(id,intent_id,phase,ordinal,original_deadline,possible_read_at) VALUES($1,$2,$3,$4,$5,$6)`, out.ReadID, id, phase, ordinal, deadline, started)
		return err
	})
	return out, err
}

func (s CapacityStore) RecordGuestAuthorityTransportV2(ctx context.Context, read GuestOriginalAuthorityReadV2, returned capacity.GuestOriginalHTTPReturn) error {
	if returned.StartedAt.Before(read.StartedAt) || returned.DriverReturnedAt.Before(returned.StartedAt) || !capacity.GuestOriginalHTTPBodyFactsValid(returned.ResponseBodyScope, returned.ReadReturnedAt, returned.ReceivedBodyBytes, returned.ResponseSHA256, returned.RetainedPrefixBytes, returned.RetainedPrefixSHA256, returned.ReadFailed) || returned.RetainedPrefixBytes != len(returned.Body) || returned.RetainedPrefixSHA256 != capacity.BusinessCreationSHA256(returned.Body) {
		return ErrCapacityConflict
	}
	wire, err := guestAuthorityTransportDiagnosticV2(returned)
	if err != nil {
		return err
	}
	var reply []byte
	var observed model.CapacityGuestRetirementObservationV2
	if capacity.GuestOriginalHTTPDecode(returned, &observed) == nil && capacity.GuestRetirementV2ObservedReturnAuthentic(observed, read.Original.Receipt.Enrollment, read.Original.Request.Intent) {
		reply = returned.Body
	}
	result, err := s.DB.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_transport_returns(read_id,native_stage,return_sha256,original_wire,original_record,original_reply_wire,recorded_at) SELECT id,'journal',$2,$3,$4::jsonb,$9,clock_timestamp() FROM public.capacity_guest_original_authority_reads WHERE id=$1 AND intent_id=$5 AND phase=$6 AND ordinal=$7 AND original_deadline=$8::timestamptz`, read.ReadID, capacity.BusinessCreationSHA256(wire), wire, string(wire), read.Original.Request.Intent.RequestID, read.Phase, read.Ordinal, read.Deadline, reply)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrCapacityConflict
	}
	return nil
}

func guestAuthorityTransportDiagnosticV2(returned capacity.GuestOriginalHTTPReturn) ([]byte, error) {
	diagnostic := returned
	// The actual accepted body has separate original_reply_wire custody.
	// Preserve all original metadata and an explicit empty byte-string marker
	// so its closed diagnostic can be decoded BEFORE that body is rehydrated.
	diagnostic.Body = []byte{}
	return json.Marshal(diagnostic)
}

func (s CapacityStore) FinishGuestAuthorityReadV2(ctx context.Context, read GuestOriginalAuthorityReadV2, observation *model.CapacityGuestRetirementObservationV2) (model.CapacityGuestRetirementAuthorityV2, error) {
	var out model.CapacityGuestRetirementAuthorityV2
	err := s.guestRetirementV2Transaction(ctx, read.Original.Request.Intent.RequestID, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		if ctx.Err() != nil || !time.Now().Before(read.Deadline) || !reflect.DeepEqual(stored.Request, read.Original.Request) {
			return ErrCapacityConflict
		}
		if _, _, _, err := s.guestRetirementV2CurrentTx(ctx, tx, stored, nowPG, true); err != nil {
			return err
		}
		var originalMatches bool
		if err := tx.QueryRowContext(ctx, `SELECT phase=$3 AND ordinal=$4 AND original_deadline=$5::timestamptz AND possible_read_at=$6::timestamptz FROM public.capacity_guest_original_authority_reads WHERE id=$1 AND intent_id=$2`, read.ReadID, stored.Request.Intent.RequestID, read.Phase, read.Ordinal, read.Deadline, read.StartedAt).Scan(&originalMatches); err != nil || !originalMatches {
			return ErrCapacityConflict
		}
		// The first pre-start read is anchored by the actual original monotonic
		// Guest nonce return. Subsequent reads must join the same active journal.
		if read.Phase == "before_poweroff" || read.Ordinal > 1 {
			expected := 1
			if read.Phase == "before_poweroff" {
				expected = read.Ordinal + 1
			}
			if observation == nil || capacity.GuestRetirementV2Observation(*observation, stored.Receipt.Enrollment, stored.Request.Intent, true) != nil || observation.Record.Sequence != expected || (read.Phase == "before_poweroff" && !observation.Record.WriterQuiescenceEvidence) {
				return ErrCapacityConflict
			}
			var wire, body []byte
			var digest string
			if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_reply_wire,return_sha256 FROM public.capacity_guest_original_authority_transport_returns WHERE read_id=$1 AND native_stage='journal'`, read.ReadID).Scan(&wire, &body, &digest); err != nil || capacity.BusinessCreationSHA256(wire) != digest {
				return ErrCapacityConflict
			}
			var returned capacity.GuestOriginalHTTPReturn
			var actual model.CapacityGuestRetirementObservationV2
			if capacity.DecodeGuestLifecycle(wire, &returned) != nil || returned.StartedAt.Before(read.StartedAt) || !returned.DriverReturnedAt.Before(read.Deadline) {
				return ErrCapacityConflict
			}
			returned.Body = body
			if capacity.GuestOriginalHTTPDecode(returned, &actual) != nil || !reflect.DeepEqual(actual, *observation) {
				return ErrCapacityConflict
			}
			var retainedSHA string
			if err := tx.QueryRowContext(ctx, `SELECT return_sha256 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 AND sequence=$2 AND kind=$3`, stored.Request.Intent.RequestID, observation.Record.Sequence+1, "production_retirement_v2:"+observation.Record.State).Scan(&retainedSHA); err != nil || retainedSHA != observation.RecordSHA256 {
				return ErrCapacityConflict
			}
		} else if read.Phase != "before_start" || read.Ordinal != 1 || observation != nil {
			return ErrCapacityConflict
		}
		i := stored.Request.Intent
		out = model.CapacityGuestRetirementAuthorityV2{Schema: capacity.GuestRetirementV2AuthoritySchema, Purpose: capacity.GuestRetirementV2Purpose, Phase: read.Phase, IntentSHA256: capacity.GuestRetirementSHA(i), AttemptID: i.AttemptID, NonceSHA256: i.NonceSHA256, EnrollmentSHA256: i.EnrollmentSHA256, State: "authorized", SourceCommit: stored.Binding.CoreAuthoritySourceCommit, OriginalDeadline: i.OriginalDeadline, ObservedAt: time.Now().UTC(), GuestNonceSHA256: capacity.GuestRetirementSHA(i.GuestNonce), GuestExpiresMonotonicNS: i.GuestExpiresMonotonicNS}
		wire, err := json.Marshal(out)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_returns(read_id,authority_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5)`, read.ReadID, capacity.GuestRetirementSHA(out), wire, string(wire), nowPG)
		return err
	})
	return out, err
}
