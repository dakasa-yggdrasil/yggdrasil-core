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

func loadGuestNotifyPublicationTx(ctx context.Context, tx *sql.Tx, id string, e model.CapacityGuestRetirementEnrollment, p model.CapacityPolicySpec) (capacity.GuestNotifyPublicationReply, error) {
	var out capacity.GuestNotifyPublicationReply
	c, err := loadGuestNotifyChallengeTx(ctx, tx, id)
	if err != nil || !capacity.GuestNotifyCanaryPublication(c) || c.EnrollmentSHA256 != capacity.GuestRetirementSHA(e) {
		return out, ErrCapacityConflict
	}
	var wire, transport []byte
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT original_wire,original_transport,return_sha256 FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=$1 AND outcome='accepted'`, id).Scan(&wire, &transport, &digest)
	if err != nil {
		return out, err
	}
	var original capacity.GuestOriginalHTTPReturn
	var r model.CapacityGuestNotifyCanaryRead
	if json.Unmarshal(transport, &original) != nil || capacity.BusinessCreationSHA256(wire) != digest || capacity.DecodeGuestLifecycle(wire, &r) != nil || !guestNotifyHTTPWithin(c, original) {
		return out, ErrCapacityConflict
	}
	original.Body = wire
	if capacity.GuestOriginalHTTPDecode(original, &r) != nil || capacity.ValidateGuestNotifyCanaryEnvelope(c, e, r, original.DriverReturnedAt) != nil {
		return out, ErrCapacityConflict
	}
	return capacity.GuestNotifyPublicationFacts(p, c, e, r)
}

// Retain one exact completed original transport. Unknown/error body bytes are
// never persisted as business proof. A held result commits its immutable
// diagnostic metadata but cannot count as useful capacity or free inventory.
func (s CapacityStore) RecordGuestNotifyCanaryReturn(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, c model.CapacityGuestNotifyCanaryChallenge, returned capacity.GuestOriginalHTTPReturn) (model.CapacityGuestNotifyBusinessObservation, error) {
	var business model.CapacityGuestNotifyBusinessObservation
	accepted := false
	err := s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
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
		if guestNotifyHTTPWithin(c, returned) && capacity.GuestOriginalHTTPDecode(returned, &r) == nil && capacity.ValidateGuestNotifyCanaryEnvelope(c, receipt.Enrollment, r, time.Now().UTC()) == nil {
			if capacity.GuestNotifyCanaryPublication(c) {
				fact, e := capacity.GuestNotifyPublicationFacts(p, c, receipt.Enrollment, r)
				if e == nil {
					accepted = true
					observation = fact
				}
			} else {
				publication, e := loadGuestNotifyPublicationTx(ctx, tx, c.RecordChallengeID, receipt.Enrollment, p)
				if e == nil {
					business, e = capacity.JoinGuestNotifyBusiness(p, c, receipt.Enrollment, r, publication, time.Now().UTC())
					if e == nil {
						accepted = true
						observation = business
					}
				}
			}
		}
		if accepted {
			outcome = "accepted"
			retained = append([]byte(nil), returned.Body...)
		}
		// Preserve the actual body hash/count/times; erase arbitrary response bytes
		// from diagnostic metadata. Accepted canonical bytes are stored separately.
		transport := returned
		transport.Body = nil
		diagnostic, err := json.Marshal(transport)
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
