package capacity

import (
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"reflect"
	"time"
)

// Receipt RecordedAt/now belong only to Core PG. Confirmation wall chronology
// and every BOOTTIME sample belong only to the same original Guest boot.
func GuestOriginalInstallationV2(pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt, c model.CapacityGuestOriginalInstallationConfirmation, producer string, original model.CapacityGuestProductionProvisioningClockV2, now time.Time) error {
	clock := c.ProductionClock
	digest := GuestRetirementSHA(original)
	if c.Schema != GuestInstallationV2Schema || clock == nil || clock.Schema != GuestInstallationClockV2Schema || original.Schema != GuestProvisioningClockV2Schema || !reflect.DeepEqual(original.Authority.Preregistration, pre) || original.OriginalResultReturnedMonotonicNS <= 0 || original.AcceptedExpiresMonotonicNS <= original.OriginalResultReturnedMonotonicNS || !guestUUID(c.PreregistrationID) || c.PreregistrationID != pre.PreregistrationID || receipt.PreregistrationID != pre.PreregistrationID || c.OriginalReceiptSHA256 != GuestRetirementSHA(receipt) || c.EnrollmentSHA256 != GuestRetirementSHA(receipt.Enrollment) || !ValidDigest(digest) || receipt.Enrollment.Statement.OriginalProvisioningClockSHA256 != digest || clock.OriginalProvisioningClockSHA256 != digest || receipt.RecordedAt.IsZero() || receipt.RecordedAt.Before(original.Authority.ObservedAt) || !receipt.RecordedAt.Before(pre.OriginalDeadline) || !now.Before(pre.OriginalDeadline) || receipt.RecordedAt.After(now) || c.InstalledAt.IsZero() || c.AdmittedAt.IsZero() || clock.OriginalReceiptReadReturnedAt.IsZero() || clock.OriginalReceiptReadReturnedAt.Before(receipt.Enrollment.Statement.IssuedAt) || c.InstalledAt.Before(clock.OriginalReceiptReadReturnedAt) || c.AdmittedAt.Before(c.InstalledAt) || clock.OriginalReceiptReadStartedMonotonicNS < original.OriginalResultReturnedMonotonicNS || clock.OriginalReceiptReadReturnedMonotonicNS < clock.OriginalReceiptReadStartedMonotonicNS || clock.OriginalReceiptReadReturnedMonotonicNS-clock.OriginalReceiptReadStartedMonotonicNS > int64(5*time.Second) || clock.InstalledMonotonicNS < clock.OriginalReceiptReadReturnedMonotonicNS || clock.AdmittedMonotonicNS < clock.InstalledMonotonicNS || clock.OriginalConfirmationPreparedMonotonicNS < clock.AdmittedMonotonicNS || clock.OriginalConfirmationPreparedMonotonicNS >= original.AcceptedExpiresMonotonicNS {
		return fmt.Errorf("same original production installation clock required")
	}
	signature := c.Signature
	c.Signature = ""
	if !guestRetirementVerify(producer, signature, c) {
		return fmt.Errorf("production original installation signature refused")
	}
	return nil
}
