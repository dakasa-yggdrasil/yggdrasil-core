package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func guestNotifyHTTPWithin(c model.CapacityGuestNotifyCanaryChallenge, r capacity.GuestOriginalHTTPReturn) bool {
	return !r.StartedAt.IsZero() && !r.StartedAt.Before(c.IssuedAt) && !r.DriverReturnedAt.IsZero() && r.DriverReturnedAt.Before(c.OriginalDeadline) && r.CloseReturnedAt.Before(c.OriginalDeadline) && r.ReadReturnedAt.Before(c.OriginalDeadline) && !r.OriginalContextFailed
}

// The transport owns the original challenge clock. Retaining a completed
// response may outlive that clock; the current scope/lease transaction remains
// independent. Every original read/close/driver and canonical signed envelope
// must still pass before the response can reach the business join.
func guestNotifyClosedOriginalEnvelope(c model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, returned capacity.GuestOriginalHTTPReturn, out *model.CapacityGuestNotifyCanaryRead) string {
	if !guestNotifyHTTPWithin(c, returned) {
		return "original_transport"
	}
	if capacity.GuestOriginalHTTPDecode(returned, out) != nil {
		return "original_body_decode"
	}
	if capacity.ValidateGuestNotifyCanaryEnvelope(c, e, *out, returned.DriverReturnedAt) != nil {
		return "original_envelope"
	}
	return ""
}

// The response wire/hash and transport fields remain exact. Only a closed
// Source stage is added to the diagnostic JSON; arbitrary response bytes stay
// erased. Existing transport readers use json.Unmarshal and ignore this field.
func guestNotifyReturnDiagnostic(returned capacity.GuestOriginalHTTPReturn, stage string) ([]byte, error) {
	returned.Body = nil
	return json.Marshal(struct {
		capacity.GuestOriginalHTTPReturn
		CanaryReturnValidationStage string `json:"CanaryReturnValidationStage"`
	}{returned, stage})
}

func loadGuestNotifyPublicationTx(ctx context.Context, tx *sql.Tx, read model.CapacityGuestNotifyCanaryChallenge, e model.CapacityGuestRetirementEnrollment, p model.CapacityPolicySpec) (capacity.GuestNotifyPublicationReply, model.CapacityGuestNotifyCanaryChallenge, error) {
	var out capacity.GuestNotifyPublicationReply
	c, err := loadGuestNotifyChallengeTx(ctx, tx, read.RecordChallengeID)
	if err != nil || !capacity.GuestNotifyCausalPair(c, read) || c.EnrollmentSHA256 != capacity.GuestRetirementSHA(e) {
		return out, c, ErrCapacityConflict
	}
	var sameExecutor bool
	if err = tx.QueryRowContext(ctx, `SELECT p.executor_id=r.executor_id FROM public.capacity_guest_notify_canary_challenges p JOIN public.capacity_guest_notify_canary_challenges r ON r.id=$2 WHERE p.id=$1`, c.ChallengeID, read.ChallengeID).Scan(&sameExecutor); err != nil || !sameExecutor {
		return out, c, ErrCapacityConflict
	}
	var wire, transport []byte
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT original_wire,original_transport,return_sha256 FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=$1 AND outcome='accepted'`, c.ChallengeID).Scan(&wire, &transport, &digest)
	if err != nil {
		return out, c, err
	}
	var original capacity.GuestOriginalHTTPReturn
	var r model.CapacityGuestNotifyCanaryRead
	if json.Unmarshal(transport, &original) != nil || capacity.BusinessCreationSHA256(wire) != digest || capacity.DecodeGuestLifecycle(wire, &r) != nil || !guestNotifyHTTPWithin(c, original) || original.DriverReturnedAt.After(read.IssuedAt) {
		return out, c, ErrCapacityConflict
	}
	original.Body = wire
	if capacity.GuestOriginalHTTPDecode(original, &r) != nil || capacity.ValidateGuestNotifyCanaryEnvelope(c, e, r, original.DriverReturnedAt) != nil {
		return out, c, ErrCapacityConflict
	}
	out, err = capacity.GuestNotifyPublicationFacts(p, c, e, r)
	return out, c, err
}

// Retain one exact completed original transport. Unknown/error body bytes are
// never persisted as business proof. A held result commits its immutable
// diagnostic metadata but cannot count as useful capacity or free inventory.
func (s CapacityStore) RecordGuestNotifyCanaryReturn(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, c model.CapacityGuestNotifyCanaryChallenge, returned capacity.GuestOriginalHTTPReturn) (model.CapacityGuestNotifyBusinessObservation, error) {
	var business model.CapacityGuestNotifyBusinessObservation
	accepted := false
	err := s.guestNotifyTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		_, receipt, err := s.guestNotifyStoredTx(ctx, tx, policy, p, c.PreregistrationID)
		if err != nil {
			return err
		}
		stored, err := loadGuestNotifyChallengeTx(ctx, tx, c.ChallengeID)
		if err != nil || !reflect.DeepEqual(stored, c) || c.PolicyID != policy.ID.String() || c.PolicyChecksum != policy.Checksum || c.WorkflowID != s.WorkflowID.String() || c.Generation != uint64(generation) || c.Fence != uint64(fence) || c.LeaseOwner != owner || current.RecoveryOnly {
			return ErrCapacityConflict
		}
		var possible time.Time
		var requestSHA string
		if err = tx.QueryRowContext(ctx, `SELECT possible_send_at,request_sha256 FROM public.capacity_guest_notify_canary_sends WHERE challenge_id=$1`, c.ChallengeID).Scan(&possible, &requestSHA); err != nil {
			return err
		}
		request, _ := json.Marshal(model.CapacityGuestNotifyCanaryRequest{Challenge: c})
		if requestSHA != capacity.BusinessCreationSHA256(request) || returned.StartedAt.Before(possible) {
			return ErrCapacityConflict
		}
		outcome := "held"
		var retained []byte
		var observation any
		var r model.CapacityGuestNotifyCanaryRead
		validationStage := guestNotifyClosedOriginalEnvelope(c, receipt.Enrollment, returned, &r)
		if validationStage == "" {
			if capacity.GuestNotifyCanaryPublication(c) {
				validationStage = "publication_facts"
				fact, e := capacity.GuestNotifyPublicationFacts(p, c, receipt.Enrollment, r)
				if e == nil {
					accepted = true
					observation = fact
				}
			} else {
				validationStage = "load_original_publication"
				publication, pubChallenge, e := loadGuestNotifyPublicationTx(ctx, tx, c, receipt.Enrollment, p)
				if e == nil {
					validationStage = "business_join"
					business, e = capacity.JoinGuestNotifyBusiness(p, c, receipt.Enrollment, r, publication, pubChallenge, returned.DriverReturnedAt)
					if e == nil {
						accepted = true
						observation = business
					}
				}
			}
		}
		if accepted {
			validationStage = "accepted"
			outcome = "accepted"
			retained = append([]byte(nil), returned.Body...)
		}
		// Preserve the actual body hash/count/times; erase arbitrary response bytes
		// from diagnostic metadata. Accepted canonical bytes are stored separately.
		diagnostic, err := guestNotifyReturnDiagnostic(returned, validationStage)
		if err != nil {
			return err
		}
		var observed []byte
		if observation != nil {
			observed, err = json.Marshal(observation)
			if err != nil {
				return err
			}
		}
		var dbObserved any
		if observed != nil {
			dbObserved = string(observed)
		}
		returnDigest := returned.ResponseSHA256
		if !capacity.ValidDigest(returnDigest) {
			returnDigest = capacity.BusinessCreationSHA256(diagnostic)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_returns(challenge_id,outcome,return_sha256,original_wire,original_transport,business_observation,recorded_at)VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7)`, c.ChallengeID, outcome, returnDigest, retained, string(diagnostic), dbObserved, now)
		return err
	})
	if err != nil {
		return business, err
	}
	if !accepted {
		return business, ErrCapacityConflict
	}
	return business, nil
}
