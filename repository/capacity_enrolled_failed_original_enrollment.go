package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"regexp"
)

// Verify at the immutable original receipt time, never at an extended deadline
// or a new policy's current admission. No callback or signing key is used.
func loadEnrolledFailedReceipt(ctx context.Context, tx *sql.Tx, stored guestOriginalStored, p model.CapacityPolicySpec, out *enrolledFailedOriginalDispositionSnapshot) error {
	receipt, _, err := loadGuestReceiptTx(ctx, tx, stored.pre.PreregistrationID)
	if err != nil {
		return err
	}
	var registrationWire, receiptWire []byte
	var enrollmentSHA, registrationSHA, tupleSHA string
	if err = tx.QueryRowContext(ctx, `SELECT registration_wire,receipt_wire,enrollment_sha256,original_provisioning_sha256,resource_tuple_sha256 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=$1 FOR SHARE`, stored.pre.PreregistrationID).Scan(&registrationWire, &receiptWire, &enrollmentSHA, &registrationSHA, &tupleSHA); err != nil {
		return err
	}
	var registration model.CapacityGuestOriginalProvisioningRegistration
	if capacity.DecodeGuestLifecycle(registrationWire, &registration) != nil {
		return ErrOriginalCreateDisposition
	}
	if validateEnrolledFailedReceipt(stored, p, receipt, registration, registrationWire, receiptWire, enrollmentSHA, registrationSHA, tupleSHA) != nil {
		return ErrOriginalCreateDisposition
	}
	out.registrationSHA = originalDispositionDigest(registrationWire)
	out.receiptSHA = originalDispositionDigest(receiptWire)
	out.enrollmentSHA = enrollmentSHA
	return nil
}

func validateEnrolledFailedReceipt(stored guestOriginalStored, p model.CapacityPolicySpec, receipt model.CapacityGuestOriginalProvisioningReceipt, registration model.CapacityGuestOriginalProvisioningRegistration, registrationWire, receiptWire []byte, enrollmentSHA, registrationSHA, tupleSHA string) error {
	pre, w, b := stored.pre, stored.witness, stored.binding
	at := receipt.RecordedAt
	// Full wire, signatures, production clock and complete native lifetime joins
	// are re-derived from the retained originals, not caller-supplied booleans.
	canonicalRegistration, e1 := json.Marshal(registration)
	canonicalReceipt, e2 := json.Marshal(receipt)
	if e1 != nil || e2 != nil || !bytes.Equal(canonicalRegistration, registrationWire) || !bytes.Equal(canonicalReceipt, receiptWire) || at.IsZero() || at.Before(w.ObservedAt) || !at.Before(pre.OriginalDeadline) || receipt.PreregistrationID != pre.PreregistrationID || receipt.Enrollment.Statement.Tuple != w.Tuple || registration.Result.Tuple != w.Tuple || receipt.OriginalProvisioningSHA256 != registrationSHA || registrationSHA != originalDispositionDigest(registrationWire) || enrollmentSHA != capacity.GuestRetirementSHA(receipt.Enrollment) || tupleSHA != capacity.GuestRetirementSHA(w.Tuple) || b.EvidenceClass != "owned_provisioner_original" || (w.Tuple.Provider != "aws" && w.Tuple.Provider != "hetzner") || p.GuestRetirementBinding == nil || capacity.GuestRetirementSHA(*p.GuestRetirementBinding) != capacity.GuestRetirementSHA(b) {
		return ErrOriginalCreateDisposition
	}
	if registration.Result.ProductionClock == nil || !capacity.GuestProductionClockStoredMatches(registration.Result.ProductionClock, pre, w, b.ProfileManifest) || capacity.GuestOriginalCreateWitness(p, b, stored.member, pre, w, registration.EnrollmentStatement.CoreIntentPublicKey, at) != nil || capacity.GuestOriginalRegistration(p, b, stored.member, w, registration, at) != nil || capacity.GuestRetirementEnrollment(p, b, stored.member, receipt.Enrollment, at) != nil {
		return ErrOriginalCreateDisposition
	}
	return nil
}

func enrolledFailedKnownAWSAuxiliary(aux []model.CapacityMutationAuxiliaryResource) bool {
	if len(aux) != 2 {
		return false
	}
	kinds := map[string]bool{}
	for _, a := range aux {
		prefix := ""
		if a.Kind == "aws_ebs_volume" {
			prefix = "vol-"
		}
		if a.Kind == "aws_network_interface" {
			prefix = "eni-"
		}
		if prefix == "" || kinds[a.Kind] || !a.RequiresAbsence || !regexp.MustCompile(`^`+prefix+`[a-f0-9]{8,17}$`).MatchString(a.ID) {
			return false
		}
		kinds[a.Kind] = true
	}
	return true
}
