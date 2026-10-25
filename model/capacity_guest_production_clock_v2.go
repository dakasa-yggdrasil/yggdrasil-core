package model

import "time"

type CapacityGuestOriginalProfileAuthorityV2 struct {
	Schema             string                                           `json:"schema"`
	BindingName        string                                           `json:"binding_name"`
	Slot               int                                              `json:"slot"`
	GuestBootID        string                                           `json:"guest_boot_id"`
	RequestNonceSHA256 string                                           `json:"request_nonce_sha256"`
	Profile            CapacityGuestProtectedProfileManifest            `json:"profile_manifest"`
	Preregistration    CapacityGuestOriginalProvisioningPreregistration `json:"preregistration"`
	CreateWitness      CapacityGuestOriginalCreateWitness               `json:"create_witness"`
	RemainingNS        int64                                            `json:"remaining_ns"`
	ObservedAt         time.Time                                        `json:"observed_at"`
	Signature          string                                           `json:"signature"`
}

// These values are captured by the original source operations. Wall chronology
// is entirely Guest-local; kernel chronology is one actual boot, across owner,
// payload and runtime. The producer signs the enclosing original result.
type CapacityGuestProductionProvisioningClockV2 struct {
	Schema                            string                                  `json:"schema"`
	Authority                         CapacityGuestOriginalProfileAuthorityV2 `json:"authority"`
	BootstrapOwnerPID                 int                                     `json:"bootstrap_owner_pid"`
	BootstrapOwnerStartTicks          uint64                                  `json:"bootstrap_owner_start_ticks"`
	AcquisitionStartedMonotonicNS     int64                                   `json:"acquisition_started_monotonic_ns"`
	AcquisitionExpiresMonotonicNS     int64                                   `json:"acquisition_expires_monotonic_ns"`
	OriginalReadStartedAt             time.Time                               `json:"original_read_started_at"`
	OriginalReadReturnedAt            time.Time                               `json:"original_read_returned_at"`
	OriginalReadStartedMonotonicNS    int64                                   `json:"original_read_started_monotonic_ns"`
	OriginalReadReturnedMonotonicNS   int64                                   `json:"original_read_returned_monotonic_ns"`
	AcceptedExpiresMonotonicNS        int64                                   `json:"accepted_expires_monotonic_ns"`
	OriginalResultReturnedMonotonicNS int64                                   `json:"original_result_returned_monotonic_ns"`
}

type CapacityGuestProductionInstallationClockV2 struct {
	Schema                                  string    `json:"schema"`
	OriginalProvisioningClockSHA256         string    `json:"original_provisioning_clock_sha256"`
	OriginalReceiptReadStartedMonotonicNS   int64     `json:"original_receipt_read_started_monotonic_ns"`
	OriginalReceiptReadReturnedMonotonicNS  int64     `json:"original_receipt_read_returned_monotonic_ns"`
	OriginalReceiptReadReturnedAt           time.Time `json:"original_receipt_read_returned_at"`
	InstalledMonotonicNS                    int64     `json:"installed_monotonic_ns"`
	AdmittedMonotonicNS                     int64     `json:"admitted_monotonic_ns"`
	OriginalConfirmationPreparedMonotonicNS int64     `json:"original_confirmation_prepared_monotonic_ns"`
}
