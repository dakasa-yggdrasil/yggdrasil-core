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

func loadGuestNotifyChallengeTx(ctx context.Context, tx *sql.Tx, id string) (model.CapacityGuestNotifyCanaryChallenge, error) {
	pre, err := loadGuestNotifyPreflightTx(ctx, tx, id)
	if err != nil {
		return pre, err
	}
	var wire, nonceWire []byte
	var digest string
	err = tx.QueryRowContext(ctx, `SELECT final_challenge_wire,nonce_wire,final_challenge_sha256 FROM public.capacity_guest_notify_canary_nonces WHERE challenge_id=$1`, id).Scan(&wire, &nonceWire, &digest)
	var final model.CapacityGuestNotifyCanaryChallenge
	var nonce model.CapacityGuestNotifyCanaryNonce
	if err != nil {
		return final, err
	}
	if capacity.DecodeGuestLifecycle(wire, &final) != nil || capacity.DecodeGuestLifecycle(nonceWire, &nonce) != nil || capacity.GuestRetirementSHA(final) != digest || final.GuestNonce != nonce || capacity.GuestNotifyPreflightSHA(final) != capacity.GuestNotifyPreflightSHA(pre) {
		return final, ErrCapacityConflict
	}
	return final, nil
}
func (s CapacityStore) FinalizeGuestNotifyCanaryNonce(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, c model.CapacityGuestNotifyCanaryChallenge, returned capacity.GuestOriginalHTTPReturn) error {
	return s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		_, receipt, err := s.guestNotifyStoredTx(ctx, tx, policy, p, c.PreregistrationID)
		if err != nil {
			return err
		}
		pre, err := loadGuestNotifyPreflightTx(ctx, tx, c.ChallengeID)
		if err != nil || current.RecoveryOnly || c.Generation != uint64(generation) || c.Fence != uint64(fence) || c.LeaseOwner != owner || capacity.GuestNotifyPreflightSHA(pre) != capacity.GuestNotifyPreflightSHA(c) || capacity.ValidateGuestNotifyCanaryPreflight(pre, receipt.Enrollment, time.Now().UTC()) != nil || capacity.ValidateGuestNotifyCanaryChallenge(c, receipt.Enrollment, time.Now().UTC()) != nil || !guestNotifyHTTPWithin(c, returned) {
			return ErrCapacityConflict
		}
		var nonce model.CapacityGuestNotifyCanaryNonce
		if capacity.GuestOriginalHTTPDecode(returned, &nonce) != nil || !reflect.DeepEqual(nonce, c.GuestNonce) {
			return ErrCapacityConflict
		}
		wire, err := json.Marshal(c)
		if err != nil {
			return err
		}
		diagnostic := returned
		diagnostic.Body = nil
		transport, err := json.Marshal(diagnostic)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_notify_canary_nonces(challenge_id,guest_nonce_sha256,nonce_wire,final_challenge_wire,final_challenge_sha256,original_transport,recorded_at)VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, c.ChallengeID, c.GuestNonce.NonceSHA256, returned.Body, wire, capacity.GuestRetirementSHA(c), string(transport), now)
		return err
	})
}

func (s CapacityStore) GuestNotifyCanaryEnrollment(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID string) (model.CapacityGuestRetirementEnrollment, error) {
	var e model.CapacityGuestRetirementEnrollment
	err := s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, _ model.CapacityIntent, _ time.Time) error {
		_, receipt, err := s.guestNotifyStoredTx(ctx, tx, policy, p, preID)
		if err != nil {
			return err
		}
		e = receipt.Enrollment
		return nil
	})
	return e, err
}
