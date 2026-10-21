//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"path/filepath"
	"time"
)

func (r *Realm) publishProbeDiagnostic(ctx context.Context, slot int, variant string, returned capacity.GuestOriginalHTTPReturn) error {
	_, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), "probe-http-"+variant+".json"), capacity.GuestProbeDiagnostic(returned))
	return err
}

type installationReadProjection struct {
	Schema                 string    `json:"schema"`
	Slot                   int       `json:"slot"`
	ConfirmationSHA256     string    `json:"confirmation_sha256"`
	OriginalReceiptSHA256  string    `json:"original_receipt_sha256"`
	EnrollmentSHA256       string    `json:"enrollment_sha256"`
	InstalledAt            time.Time `json:"installed_at"`
	AdmittedAt             time.Time `json:"admitted_at"`
	DatabaseReadReturnedAt time.Time `json:"database_read_returned_at"`
	OriginalDeadline       time.Time `json:"original_deadline"`
}

// Called only with the actual authenticated repository read returned by the barrier.
func (r *Realm) InstallationRecorded(ctx context.Context, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt, c model.CapacityGuestOriginalInstallationConfirmation, readReturnedAt time.Time) error {
	now := readReturnedAt
	if c.Schema != capacity.GuestOriginalInstallationSchema || c.PreregistrationID != pre.PreregistrationID || c.OriginalReceiptSHA256 != capacity.GuestRetirementSHA(receipt) || c.EnrollmentSHA256 != capacity.GuestRetirementSHA(receipt.Enrollment) || c.InstalledAt.Before(receipt.RecordedAt) || c.AdmittedAt.Before(c.InstalledAt) || c.AdmittedAt.After(now) || !now.Before(pre.OriginalDeadline) {
		return ErrOriginalUnknown
	}
	proof := installationReadProjection{"guest_installation_authenticated_read_v1", g.Slot, capacity.GuestRetirementSHA(c), c.OriginalReceiptSHA256, c.EnrollmentSHA256, c.InstalledAt, c.AdmittedAt, now, pre.OriginalDeadline}
	_, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, g.Slot), "installation-authenticated-read.json"), proof)
	return err
}

func (r *Realm) InstallationReadState(ctx context.Context, slot int, state string) error {
	switch state {
	case "receipt_read_error", "receipt_refused", "read_ok", "receipt_pending", "confirmation_pending", "confirmation_refused", "confirmation_read_error":
	default:
		return ErrOriginalUnknown
	}
	proof := struct {
		Schema     string    `json:"schema"`
		Slot       int       `json:"slot"`
		State      string    `json:"state"`
		ObservedAt time.Time `json:"observed_at"`
	}{"guest_installation_read_state_v1", slot, state, time.Now().UTC()}
	_, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), "installation-read-state.json"), proof)
	return err
}
