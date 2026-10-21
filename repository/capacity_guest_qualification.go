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

// This internal qualification protocol is deliberately outside shared9/3/16.
// Production has no compiled native-QEMU source registry and cannot reserve it.
type guestQualificationChallenge = capacity.QualificationProbeChallenge
type guestQualificationRequest struct {
	Challenge guestQualificationChallenge `json:"challenge"`
	Signature string                      `json:"signature"`
}

func (s CapacityStore) ReserveGuestQualificationProbe(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID string, requestWire []byte) error {
	var request guestQualificationRequest
	if capacity.DecodeGuestLifecycle(requestWire, &request) != nil {
		return ErrCapacityConflict
	}
	return s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		stored, err := loadGuestOriginalTx(ctx, tx, preID)
		if err != nil {
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
		if p.GuestRetirementBinding == nil || !reflect.DeepEqual(stored.binding, *p.GuestRetirementBinding) || !capacity.GuestOriginalProfileEnabled(p, stored.binding, "native-qemu") || stored.pre.PolicyID != policy.ID.String() || stored.pre.PolicyChecksum != policy.Checksum || stored.pre.WorkflowID != s.WorkflowID.String() || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || capacity.ValidateQualificationProbeNonce(c, receipt.Enrollment) != nil || c.Schema != "original_qualification_serving_probe_v2" || c.Purpose != "same_original_admitted_writer_useful_echo" || !validCapacityExecutor(c.ChallengeID) || c.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || c.Tuple != e.Tuple || c.Actor != e.Actor || c.Runtime != e.Runtime || len(e.Writers) != 1 || c.Writer != e.Writers[0] || !capacity.ValidDigest(c.NonceSHA256) || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !now.Before(c.OriginalDeadline) || c.OriginalDeadline.Sub(c.IssuedAt) > 5*time.Second || !c.OriginalDeadline.After(c.IssuedAt) || current.LeaseExpiresAt == nil || c.OriginalDeadline.After(*current.LeaseExpiresAt) || validateStoredQualificationEnrollment(p, stored, receipt.Enrollment) != nil {
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
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_probe_challenges c WHERE c.preregistration_id=$1 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_qualification_native_source_returns r WHERE r.preregistration_id=c.preregistration_id AND r.native_stage='serving_probe' AND r.original_record->>'challenge_sha256'=c.challenge_sha256)`, preID).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved != 0 {
			return ErrCapacityConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_qualification_probe_challenges(challenge_id,preregistration_id,challenge_sha256,original_wire,original_record,original_deadline,recorded_at) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7)`, c.ChallengeID, preID, capacity.GuestRetirementSHA(c), requestWire, string(requestWire), c.OriginalDeadline, now)
		return err
	})
}

// Only the source controller/native realm calls this; no external HTTP
// endpoint accepts a supplied native return or a completeness Boolean.
func (s CapacityStore) RecordGuestQualificationSourceReturn(ctx context.Context, preID, stage string, wire []byte) error {
	if !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") || (stage != "native_read" && stage != "serving_probe" && stage != "source_refusal" && stage != "diagnostic_serving_probe" && stage != "diagnostic_native_read") || len(wire) < 1 || len(wire) > capacity.GuestBootstrapLimit || !json.Valid(wire) {
		return ErrCapacityConflict
	}
	var typed struct {
		Schema          string `json:"schema"`
		ChallengeSHA256 string `json:"challenge_sha256"`
	}
	if json.Unmarshal(wire, &typed) != nil {
		return ErrCapacityConflict
	}
	if ((stage == "native_read" || stage == "diagnostic_native_read") && typed.Schema != "core_independent_original_qemu_read_v1") || ((stage == "serving_probe" || stage == "diagnostic_serving_probe") && (typed.Schema != "original_qualification_serving_probe_v2" || !capacity.ValidDigest(typed.ChallengeSHA256))) || (stage == "source_refusal" && typed.Schema != "original_qualification_failed_owner_returns_v1") {
		return ErrCapacityConflict
	}
	return s.guestStoredTransaction(ctx, preID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		if stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || stored.pre.WorkflowID != s.WorkflowID.String() {
			return ErrCapacityConflict
		}
		if stage == "serving_probe" || stage == "diagnostic_serving_probe" {
			var challenge string
			usage := "capacity_phase"
			if stage == "diagnostic_serving_probe" {
				usage = "diagnostic_only"
			}
			if err := tx.QueryRowContext(ctx, `SELECT challenge_id::text FROM public.capacity_guest_qualification_probe_challenges WHERE preregistration_id=$1 AND challenge_sha256=$2 AND usage_class=$3`, preID, typed.ChallengeSHA256, usage).Scan(&challenge); err != nil {
				return ErrCapacityConflict
			}
			var challengeWire []byte
			var request capacity.QualificationProbeRequest
			var returned capacity.QualificationProbeReceipt
			receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
			if err != nil {
				return err
			}
			if tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_probe_challenges WHERE challenge_id=$1`, challenge).Scan(&challengeWire) != nil || capacity.DecodeGuestLifecycle(challengeWire, &request) != nil || capacity.DecodeGuestLifecycle(wire, &returned) != nil || capacity.ValidateProbeReturn(request, returned, receipt.Enrollment, receipt.OriginalProvisioningSHA256, now) != nil {
				return ErrCapacityConflict
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_qualification_native_source_returns(id,preregistration_id,native_stage,return_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)`, uuid.New(), preID, stage, capacity.BusinessCreationSHA256(wire), wire, string(wire), now)
		return err
	})
}

// A diagnostic challenge is a bounded observational read of an existing
// enrolled original. It never renews a workflow lease, qualifies a phase or
// supplies the serving_probe rows consumed by the native useful floor.
func (s CapacityStore) ReserveGuestQualificationDiagnosticProbe(ctx context.Context, preID string, wire []byte) error {
	var request guestQualificationRequest
	if capacity.DecodeGuestLifecycle(wire, &request) != nil || !capacity.GuestOriginalNativeQEMUProviderEnabled("native-qemu") {
		return ErrCapacityConflict
	}
	return s.guestStoredTransaction(ctx, preID, func(tx *sql.Tx, stored guestOriginalStored, now time.Time) error {
		receipt, _, err := loadGuestReceiptTx(ctx, tx, preID)
		if err != nil {
			return err
		}
		if _, err = loadGuestInstallationTx(ctx, tx, stored, receipt); err != nil {
			return err
		}
		c := request.Challenge
		e := receipt.Enrollment.Statement
		deadline, ok := ctx.Deadline()
		if !ok || c.OriginalDeadline.After(deadline) || ctx.Err() != nil || stored.binding.CoreAuthoritySourceCommit != capacity.CurrentGuestCoreSource() || stored.pre.WorkflowID != s.WorkflowID.String() || stored.binding.EvidenceClass != "native_qemu_qualification" || capacity.ValidateQualificationProbeNonce(c, receipt.Enrollment) != nil || c.Schema != "original_qualification_serving_probe_v2" || c.Purpose != "same_original_admitted_writer_useful_echo" || !validCapacityExecutor(c.ChallengeID) || c.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || c.Tuple != e.Tuple || c.Actor != e.Actor || c.Runtime != e.Runtime || len(e.Writers) != 1 || c.Writer != e.Writers[0] || !capacity.ValidDigest(c.NonceSHA256) || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !now.Before(c.OriginalDeadline) || c.OriginalDeadline.Sub(c.IssuedAt) > 5*time.Second {
			return ErrCapacityConflict
		}
		public, e1 := base64.StdEncoding.DecodeString(e.CoreIntentPublicKey)
		signature, e2 := base64.StdEncoding.DecodeString(request.Signature)
		body, _ := json.Marshal(c)
		if e1 != nil || e2 != nil || len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), body, signature) {
			return ErrCapacityConflict
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_qualification_probe_challenges(challenge_id,preregistration_id,challenge_sha256,original_wire,original_record,original_deadline,recorded_at,usage_class) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,'diagnostic_only')`, c.ChallengeID, preID, capacity.GuestRetirementSHA(c), wire, string(wire), c.OriginalDeadline, now)
		return err
	})
}

// New source phase authority rechecks current lease/policy/workflow AFTER the
// actual echo HTTP/native Read+Close. The original probe deadline never renews.
func (s CapacityStore) FinishGuestQualificationProbe(ctx context.Context, policy model.Manifest, generation, fence int64, owner, preID string, wire []byte) error {
	var header struct {
		Schema                        string    `json:"schema"`
		ChallengeSHA256               string    `json:"challenge_sha256"`
		EnrollmentSHA256              string    `json:"enrollment_sha256"`
		OriginalRegistrationSHA256    string    `json:"original_registration_sha256"`
		OriginalNativeAfterReturnedAt time.Time `json:"original_native_after_returned_at"`
	}
	if json.Unmarshal(wire, &header) != nil || header.Schema != "original_qualification_serving_probe_v2" || !capacity.ValidDigest(header.ChallengeSHA256) {
		return ErrCapacityConflict
	}
	return s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, _ model.CapacityIntent, now time.Time) error {
		stored, err := loadGuestOriginalTx(ctx, tx, preID)
		if err != nil {
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
		if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_probe_challenges WHERE preregistration_id=$1 AND challenge_sha256=$2 AND usage_class='capacity_phase'`, preID, header.ChallengeSHA256).Scan(&challengeWire); err != nil {
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
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_qualification_native_source_returns(id,preregistration_id,native_stage,return_sha256,original_wire,original_record,recorded_at) VALUES($1,$2,'serving_probe',$3,$4,$5::jsonb,$6)`, uuid.New(), preID, capacity.BusinessCreationSHA256(wire), wire, string(wire), now)
		return err
	})
}

// validateStoredQualificationEnrollment checks immutable signed content only.
// Callers MUST first load the admitted enrollment and its matching post-install
// record, and independently enforce current policy, authority and lease. The
// signed Guest timestamp is not evidence of freshness in the Core clock domain.
func validateStoredQualificationEnrollment(p model.CapacityPolicySpec, stored guestOriginalStored, enrollment model.CapacityGuestRetirementEnrollment) error {
	return capacity.GuestRetirementEnrollment(p, stored.binding, stored.member, enrollment, enrollment.Statement.IssuedAt)
}
