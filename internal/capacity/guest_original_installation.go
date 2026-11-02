package capacity

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

const GuestOriginalInstallationSchema = "guest_original_installation_v1"

// GuestOriginalInstallation authenticates a confirmation against the immutable
// registration receipt. Source code emits it only after local install readback
// and admission. No signed timestamp alone grants serving or business readiness.
func GuestOriginalInstallation(pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt, confirmation model.CapacityGuestOriginalInstallationConfirmation, producer string, now time.Time) error {
	if confirmation.ProductionClock != nil || receipt.Enrollment.Statement.OriginalProvisioningClockSHA256 != "" {
		return fmt.Errorf("explicit production installation proof required")
	}
	if confirmation.Schema != GuestOriginalInstallationSchema || !guestUUID(confirmation.PreregistrationID) || confirmation.PreregistrationID != pre.PreregistrationID || receipt.PreregistrationID != pre.PreregistrationID || !ValidDigest(confirmation.OriginalReceiptSHA256) || confirmation.OriginalReceiptSHA256 != GuestRetirementSHA(receipt) || !ValidDigest(confirmation.EnrollmentSHA256) || confirmation.EnrollmentSHA256 != GuestRetirementSHA(receipt.Enrollment) || receipt.RecordedAt.IsZero() || confirmation.InstalledAt.IsZero() || confirmation.AdmittedAt.IsZero() || confirmation.InstalledAt.Before(receipt.RecordedAt) || confirmation.AdmittedAt.Before(confirmation.InstalledAt) || confirmation.AdmittedAt.After(now) || !now.Before(pre.OriginalDeadline) || !confirmation.AdmittedAt.Before(pre.OriginalDeadline) {
		return fmt.Errorf("original installation confirmation refused")
	}
	signature := confirmation.Signature
	confirmation.Signature = ""
	if !guestRetirementVerify(producer, signature, confirmation) {
		return fmt.Errorf("original installation signature refused")
	}
	return nil
}
