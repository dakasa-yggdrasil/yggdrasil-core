package model

import "time"

// An original producer confirms local durable installation and writer admission.
// This is a prerequisite for the one-shot probe, never useful capacity evidence.
type CapacityGuestOriginalInstallationConfirmation struct {
	Schema                string                                      `json:"schema"`
	PreregistrationID     string                                      `json:"preregistration_id"`
	OriginalReceiptSHA256 string                                      `json:"original_receipt_sha256"`
	EnrollmentSHA256      string                                      `json:"enrollment_sha256"`
	InstalledAt           time.Time                                   `json:"installed_at"`
	AdmittedAt            time.Time                                   `json:"admitted_at"`
	Signature             string                                      `json:"signature"`
	ProductionClock       *CapacityGuestProductionInstallationClockV2 `json:"production_clock,omitempty"`
}
