//go:build linux && nativequalification

package repository

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Qualification-only recovery echo protocol. Original production/phase methods
// remain byte-exact. Historical lease admission additionally requires RecoveryOnly.
func (s CapacityStore) ReserveGuestQualificationFloorProbe(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID string, requestWire []byte) error {
	var request guestQualificationRequest
	if !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || capacity.DecodeGuestLifecycle(requestWire, &request) != nil {
		return ErrCapacityConflict
	}
	return s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if !current.RecoveryOnly {
			return ErrCapacityConflict
		}
		stored, err := loadGuestOriginalTx(ctx, tx, preID)
		if err != nil {
			return err
		}
		if err = sourceFloorBridgeTx(ctx, tx, policy, p, stored); err != nil {
			return err
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
		if err != nil {
			return err
		}
		if _, err = loadGuestInstallationTx(ctx, tx, stored, receipt); err != nil {
			return err
		}
		c := request.Challenge
		e := receipt.Enrollment.Statement
		if p.GuestRetirementBinding == nil || !reflect.DeepEqual(stored.binding, *p.GuestRetirementBinding) || !capacity.GuestOriginalProfileEnabled(p, stored.binding, "native-qemu") || stored.pre.WorkflowID != s.WorkflowID.String() || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || capacity.ValidateQualificationProbeNonce(c, receipt.Enrollment) != nil || c.Schema != "original_qualification_serving_probe_v2" || c.Purpose != "same_original_admitted_writer_useful_echo" || !validCapacityExecutor(c.ChallengeID) || c.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || c.Tuple != e.Tuple || c.Actor != e.Actor || c.Runtime != e.Runtime || len(e.Writers) != 1 || c.Writer != e.Writers[0] || !capacity.ValidDigest(c.NonceSHA256) || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !now.Before(c.OriginalDeadline) || c.OriginalDeadline.Sub(c.IssuedAt) > 5*time.Second || !c.OriginalDeadline.After(c.IssuedAt) || current.LeaseExpiresAt == nil || c.OriginalDeadline.After(*current.LeaseExpiresAt) || validateStoredQualificationEnrollment(p, stored, receipt.Enrollment) != nil {
			return ErrCapacityConflict
		}
		deadline, exists := ctx.Deadline()
		if !exists || c.OriginalDeadline.After(deadline) || ctx.Err() != nil {
			return ErrCapacityConflict
		}
		public, e1 := base64.StdEncoding.DecodeString(e.CoreIntentPublicKey)
		signature, e2 := base64.StdEncoding.DecodeString(request.Signature)
		body, _ := json.Marshal(c)
		if e1 != nil || e2 != nil || len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), body, signature) {
			return ErrCapacityConflict
		}
		var unresolved int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_floor_source_challenges c WHERE c.preregistration_id=$1 AND c.usage_class='capacity_floor_source' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_qualification_floor_source_returns r WHERE r.preregistration_id=c.preregistration_id AND r.native_stage='floor_serving_probe' AND r.original_record->>'challenge_sha256'=c.challenge_sha256)`, preID).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved != 0 {
			return ErrCapacityConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_qualification_floor_source_challenges(challenge_id,preregistration_id,challenge_sha256,original_wire,original_record,original_deadline,recorded_at,usage_class) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,'capacity_floor_source')`, c.ChallengeID, preID, capacity.GuestRetirementSHA(c), requestWire, string(requestWire), c.OriginalDeadline, now)
		return err
	})
}

func (s CapacityStore) FinishGuestQualificationFloorProbe(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID string, wire []byte) error {
	var header struct {
		Schema                        string    `json:"schema"`
		ChallengeSHA256               string    `json:"challenge_sha256"`
		EnrollmentSHA256              string    `json:"enrollment_sha256"`
		OriginalRegistrationSHA256    string    `json:"original_registration_sha256"`
		OriginalNativeAfterReturnedAt time.Time `json:"original_native_after_returned_at"`
	}
	if !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || json.Unmarshal(wire, &header) != nil || header.Schema != "original_qualification_serving_probe_v2" || !capacity.ValidDigest(header.ChallengeSHA256) {
		return ErrCapacityConflict
	}
	return s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if !current.RecoveryOnly {
			return ErrCapacityConflict
		}
		stored, err := loadGuestOriginalTx(ctx, tx, preID)
		if err != nil {
			return err
		}
		if err = sourceFloorBridgeTx(ctx, tx, policy, p, stored); err != nil {
			return err
		}
		receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
		if err != nil {
			return err
		}
		if p.GuestRetirementBinding == nil || !reflect.DeepEqual(stored.binding, *p.GuestRetirementBinding) || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || !capacity.GuestOriginalProfileEnabled(p, stored.binding, "native-qemu") || header.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || header.OriginalRegistrationSHA256 != receipt.OriginalProvisioningSHA256 {
			return ErrCapacityConflict
		}
		var challengeWire []byte
		if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_floor_source_challenges WHERE preregistration_id=$1 AND challenge_sha256=$2 AND usage_class='capacity_floor_source'`, preID, header.ChallengeSHA256).Scan(&challengeWire); err != nil {
			return err
		}
		var request guestQualificationRequest
		if capacity.DecodeGuestLifecycle(challengeWire, &request) != nil || !now.Before(request.Challenge.OriginalDeadline) || ctx.Err() != nil {
			return ErrCapacityConflict
		}
		var originalRequest capacity.QualificationProbeRequest
		var originalReturn capacity.QualificationProbeReceipt
		if capacity.DecodeGuestLifecycle(challengeWire, &originalRequest) != nil || capacity.DecodeGuestLifecycle(wire, &originalReturn) != nil || capacity.ValidateProbeReturn(originalRequest, originalReturn, receipt.Enrollment, receipt.OriginalProvisioningSHA256, now) != nil {
			return ErrCapacityConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_qualification_floor_source_returns(id,preregistration_id,native_stage,return_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,'floor_serving_probe',$3,$4,$5::jsonb,$6)`, uuid.New(), preID, capacity.BusinessCreationSHA256(wire), wire, string(wire), now)
		return err
	})
}
