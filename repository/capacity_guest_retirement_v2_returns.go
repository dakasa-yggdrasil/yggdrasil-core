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
)

func (s CapacityStore) ReserveGuestCallerV2(original *capacity.GuestRetirementV2OriginalOwner) error {
	request, _, _, err := original.NonceExchange()
	if err != nil {
		return err
	}
	return s.guestRetirementV2Transaction(original.Context(), request.Intent.RequestID, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		public := request
		public.Nonce = ""
		if stored.ExecutorID != s.ExecutorID || !reflect.DeepEqual(public, stored.Request) || capacity.GuestRetirementSHA(request) != stored.RequestSHA256 || capacity.ValidateGuestRetirementV2Request(request, stored.Receipt.Enrollment, time.Now().UTC(), true) != nil {
			return ErrCapacityConflict
		}
		if _, _, _, err := s.guestRetirementV2CurrentTx(original.Context(), tx, stored, nowPG, true); err != nil {
			return err
		}
		_, err := tx.ExecContext(original.Context(), `INSERT INTO public.capacity_guest_original_caller_attempts(intent_id,attempt_id,request_sha256,principal_id,possible_send_at,original_deadline) VALUES($1,$2,$3,$4,$5,$6)`, request.Intent.RequestID, request.Intent.AttemptID, stored.RequestSHA256, stored.Member.ActorClientPrincipal, time.Now().UTC(), request.Intent.OriginalDeadline)
		return err
	})
}

func (s CapacityStore) GuestRetirementOriginalV2(ctx context.Context, principal, id, intentSHA string) (GuestRetirementOriginalV2, error) {
	var out GuestRetirementOriginalV2
	err := s.guestRetirementV2Transaction(ctx, id, true, func(_ *sql.Tx, stored GuestRetirementOriginalV2, _ time.Time) error {
		if principal != stored.Member.ActorClientPrincipal || intentSHA != capacity.GuestRetirementSHA(stored.Request.Intent) {
			return ErrCapacityMutationAuthorization
		}
		out = stored
		return nil
	})
	return out, err
}

func (s CapacityStore) RecordGuestObservationV2(ctx context.Context, id string, observed model.CapacityGuestRetirementObservationV2) error {
	return s.guestRetirementV2Transaction(ctx, id, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		if !capacity.GuestRetirementV2ObservedReturnAuthentic(observed, stored.Receipt.Enrollment, stored.Request.Intent) {
			return ErrCapacityConflict
		}
		var oldWire []byte
		var lastSequence int
		var kind string
		err := tx.QueryRowContext(ctx, `SELECT sequence,kind,original_wire FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence DESC LIMIT 1 FOR SHARE`, id).Scan(&lastSequence, &kind, &oldWire)
		if err != nil {
			return err
		}
		if lastSequence == 1 {
			if kind != guestRetirementV2NonceKind || observed.Record.Sequence != 1 {
				return ErrCapacityConflict
			}
		} else {
			var old model.CapacityGuestRetirementObservationV2
			if capacity.DecodeGuestLifecycle(oldWire, &old) != nil || lastSequence != old.Record.Sequence+1 || kind != "production_retirement_v2:"+old.Record.State {
				return ErrCapacityConflict
			}
			if lastSequence == observed.Record.Sequence+1 && old.RecordSHA256 == observed.RecordSHA256 {
				return nil
			}
			if !capacity.GuestRetirementV2RecordSuccessor(old.Record, observed.Record) {
				return ErrCapacityConflict
			}
		}
		wire, err := json.Marshal(observed)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_vm_retirement_original_returns(intent_id,sequence,kind,previous_sha256,return_sha256,original_return_record,recorded_at,original_wire) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`, id, observed.Record.Sequence+1, "production_retirement_v2:"+observed.Record.State, observed.Record.PreviousSHA256, observed.RecordSHA256, string(wire), nowPG, wire)
		return err
	})
}

func (s CapacityStore) RecordGuestCallerReturnV2(ctx context.Context, result GuestOriginalCallerReturn) error {
	return s.guestRetirementV2Transaction(ctx, result.RequestID, true, func(tx *sql.Tx, stored GuestRetirementOriginalV2, nowPG time.Time) error {
		i := stored.Request.Intent
		if result.AttemptID != i.AttemptID || !result.OriginalDeadline.Equal(i.OriginalDeadline) || result.StartedAt.Before(i.IssuedAt) || result.DriverReturnedAt.Before(result.StartedAt) || result.DriverReturnedAt.After(time.Now().UTC()) || !GuestOriginalCallerBodyFactsValid(result) {
			return ErrCapacityConflict
		}
		if result.PreflightFailed {
			if !result.DoStartedAt.IsZero() || !result.DoReturnedAt.IsZero() || !result.ReadReturnedAt.IsZero() || !result.CloseReturnedAt.IsZero() || result.Status != 0 || len(result.Body) != 0 {
				return ErrCapacityConflict
			}
		} else if result.DoStartedAt.Before(result.StartedAt) || result.DoReturnedAt.Before(result.DoStartedAt) || result.DoReturnedAt.After(result.DriverReturnedAt) || (!result.CloseReturnedAt.IsZero() && (result.CloseReturnedAt.Before(result.DoReturnedAt) || result.CloseReturnedAt.After(result.DriverReturnedAt))) || (!result.ReadReturnedAt.IsZero() && (result.ReadReturnedAt.Before(result.DoReturnedAt) || result.CloseReturnedAt.Before(result.ReadReturnedAt) || result.CloseReturnedAt.After(result.DriverReturnedAt))) || (!result.DoFailed && (result.ReadReturnedAt.IsZero() || result.CloseReturnedAt.IsZero())) {
			return ErrCapacityConflict
		}
		var attempt, requestSHA string
		var possibleCore time.Time
		if err := tx.QueryRowContext(ctx, `SELECT attempt_id::text,request_sha256,possible_send_at FROM public.capacity_guest_original_caller_attempts WHERE intent_id=$1`, result.RequestID).Scan(&attempt, &requestSHA, &possibleCore); err != nil || attempt != i.AttemptID || requestSHA != stored.RequestSHA256 || result.StartedAt.Before(possibleCore) {
			return ErrCapacityConflict
		}
		if result.BodyPersisted {
			var body model.CapacityGuestRetirementObservationV2
			if capacity.DecodeGuestLifecycle(result.Body, &body) != nil || !capacity.GuestRetirementV2ObservedReturnAuthentic(body, stored.Receipt.Enrollment, i) {
				return ErrCapacityConflict
			}
		} else {
			result.Body = []byte{}
		}
		wire, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_caller_returns(intent_id,return_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4::jsonb,$5)`, result.RequestID, capacity.GuestRetirementSHA(result), wire, string(wire), nowPG)
		return err
	})
}

func guestQuiescentProofV2Tx(ctx context.Context, tx *sql.Tx, stored GuestRetirementOriginalV2) (model.CapacityGuestRetirementObservationV2, error) {
	var result model.CapacityGuestRetirementObservationV2
	rows, err := tx.QueryContext(ctx, `SELECT sequence,kind,original_wire,previous_sha256,return_sha256,original_return_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_vm_retirement_original_returns WHERE intent_id=$1 ORDER BY sequence`, stored.Request.Intent.RequestID)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var sequence int
		var kind, previous, digest string
		var raw []byte
		var consistent bool
		if err = rows.Scan(&sequence, &kind, &raw, &previous, &digest, &consistent); err != nil {
			return result, err
		}
		if !consistent || sequence != count+1 {
			return result, ErrCapacityConflict
		}
		if count == 0 {
			var nonce guestRetirementV2NonceReturn
			if kind != guestRetirementV2NonceKind || previous != "" || capacity.DecodeGuestLifecycle(raw, &nonce) != nil || capacity.GuestRetirementSHA(nonce) != digest || !guestRetirementV2NonceJoin(nonce, stored) {
				return result, ErrCapacityConflict
			}
			count++
			continue
		}
		var observed model.CapacityGuestRetirementObservationV2
		if capacity.DecodeGuestLifecycle(raw, &observed) != nil || capacity.GuestRetirementV2Observation(observed, stored.Receipt.Enrollment, stored.Request.Intent, false) != nil || observed.Record.Sequence != count || kind != "production_retirement_v2:"+observed.Record.State || previous != observed.Record.PreviousSHA256 || digest != observed.RecordSHA256 || (count > 1 && !capacity.GuestRetirementV2RecordSuccessor(result.Record, observed.Record)) {
			return result, ErrCapacityConflict
		}
		result = observed
		count++
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if err = rows.Close(); err != nil {
		return result, err
	}
	if count != 5 || result.Record.State != "poweroff_command_returned" {
		return result, ErrCapacityConflict
	}
	var wire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_original_caller_returns WHERE intent_id=$1`, stored.Request.Intent.RequestID).Scan(&wire); err != nil {
		return result, ErrCapacityConflict
	}
	var caller GuestOriginalCallerReturn
	var original model.CapacityGuestRetirementObservationV2
	i := stored.Request.Intent
	if capacity.DecodeGuestLifecycle(wire, &caller) != nil || !GuestOriginalCallerBodyFactsValid(caller) || caller.RequestID != i.RequestID || caller.AttemptID != i.AttemptID || !caller.OriginalDeadline.Equal(i.OriginalDeadline) || caller.StartedAt.Before(i.IssuedAt) || !caller.BodyPersisted || caller.PreflightFailed || caller.DoFailed || caller.ReadFailed || caller.CloseFailed || caller.OriginalContextFailed || caller.Status != 200 || caller.DoStartedAt.Before(caller.StartedAt) || caller.DoReturnedAt.Before(caller.DoStartedAt) || caller.ReadReturnedAt.Before(caller.DoReturnedAt) || caller.CloseReturnedAt.Before(caller.ReadReturnedAt) || caller.DriverReturnedAt.Before(caller.CloseReturnedAt) || !caller.DriverReturnedAt.Before(i.OriginalDeadline) || capacity.DecodeGuestLifecycle(caller.Body, &original) != nil || capacity.GuestRetirementV2Observation(original, stored.Receipt.Enrollment, i, false) != nil || original.RecordSHA256 != result.RecordSHA256 {
		return result, ErrCapacityConflict
	}
	return result, nil
}

// Distinct schema dispatch is explicit. V1 loaders never filter away the nonce
// row or reinterpret signed V2 records as a four-row legacy authority.
func guestRetirementV2KindTx(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var schema string
	err := tx.QueryRowContext(ctx, `SELECT intent_record->>'schema' FROM public.capacity_vm_retirement_intents WHERE id=$1`, id).Scan(&schema)
	if errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return schema == capacity.GuestRetirementV2IntentSchema, err
}
