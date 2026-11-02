package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Each stored GET was reserved before the native call. Its actual return is
// retained even when the original context/Read/Close failed. Unknown response
// prefixes, private nonce, raw errors and transport credentials are never saved.
func (s CapacityStore) RecordGuestAuthorityTransport(ctx context.Context, read GuestOriginalAuthorityRead, stage string, returned capacity.GuestOriginalHTTPReturn) error {
	if (stage != "snapshot" && stage != "journal") || returned.StartedAt.IsZero() || returned.DriverReturnedAt.Before(returned.StartedAt) || len(returned.Body) > capacity.GuestBootstrapLimit || !capacity.GuestOriginalHTTPBodyFactsValid(returned.ResponseBodyScope, returned.ReadReturnedAt, returned.ReceivedBodyBytes, returned.ResponseSHA256, returned.RetainedPrefixBytes, returned.RetainedPrefixSHA256, returned.ReadFailed) || returned.RetainedPrefixBytes != len(returned.Body) || returned.RetainedPrefixSHA256 != capacity.BusinessCreationSHA256(returned.Body) {
		return ErrCapacityConflict
	}
	record := struct {
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
	}{read.ReadID, stage, read.Deadline, returned.StartedAt, returned.DoStartedAt, returned.DoReturnedAt, returned.ReadReturnedAt, returned.CloseReturnedAt, returned.DriverReturnedAt, returned.Status, returned.ResponseSHA256, returned.ReceivedBodyBytes, returned.ResponseBodyScope, returned.RetainedPrefixBytes, returned.RetainedPrefixSHA256, returned.PreflightFailed, returned.DoFailed, returned.ReadFailed, returned.CloseFailed, returned.OriginalContextFailed}
	wire, err := json.Marshal(record)
	if err != nil {
		return err
	}
	var reply []byte
	if stage == "snapshot" && read.Challenge != nil {
		var snapshot model.CapacityGuestRuntimeSnapshot
		if capacity.GuestOriginalHTTPDecode(returned, &snapshot) == nil && capacity.GuestRuntimeSnapshot(*read.Challenge, read.Original.Receipt.Enrollment, read.Original.Request.Intent, snapshot, returned.DriverReturnedAt) == nil {
			reply = returned.Body
		}
	} else if stage == "journal" {
		var observation model.CapacityGuestRetirementObservation
		if capacity.GuestOriginalHTTPDecode(returned, &observation) == nil && capacity.GuestRetirementObservedReturnAuthentic(observation, read.Original.Receipt.Enrollment, read.Original.Request.Intent, returned.DriverReturnedAt) {
			reply = returned.Body
		}
	}
	result, err := s.DB.ExecContext(ctx, `INSERT INTO public.capacity_guest_original_authority_transport_returns(read_id,native_stage,return_sha256,original_wire,original_record,original_reply_wire,recorded_at) SELECT id,$2,$3,$4,$5::jsonb,$10,clock_timestamp() FROM public.capacity_guest_original_authority_reads WHERE id=$1 AND intent_id=$6 AND phase=$7 AND ordinal=$8 AND original_deadline=$9::timestamptz`, read.ReadID, stage, capacity.GuestRetirementSHA(record), wire, string(wire), read.Original.Request.Intent.RequestID, read.Phase, read.Ordinal, read.Deadline, reply)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrCapacityConflict
	}
	return nil
}
