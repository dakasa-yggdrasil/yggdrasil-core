// Separate production-only V2 ABI. V1 and qualification stay byte-exact.
package model

import "time"

const GuestRetirementV2AuthorityPath = "/internal/capacity/guest-retirement/v2/authority"
const GuestRetirementV2NoncePath = "/v2/guest/retirement/nonce"
const GuestRetirementV2WritePath = "/v2/guest/retirement/retire"
const GuestRetirementV2ObservationPath = "/v2/guest/retirement/observation"

// guest_nonce_sha256 always hashes the ENTIRE canonical signed GuestNonceV2.

// Core owns a single monotonic 30s context before issue + nonce GET. Core
// original_deadline/issued_at are validated only on Core. The final accepted
// Guest expiry subtracts the WHOLE elapsed original Core owner duration from
// the raw signed Guest expiry (conservative network/DB budget transfer).
// PreflightSHA zeroes GuestNonce and GuestExpiresMonotonicNS, retaining all
// other exact fields. Final signature covers both. No operation resets expiry.
type CapacityGuestRetirementIntentV2 struct {
	CapacityGuestRetirementIntent
	PreregistrationID       string                          `json:"preregistration_id"`
	ProfileManifestSHA256   string                          `json:"profile_manifest_sha256"`
	CoreSourceCommit        string                          `json:"core_source_commit"`
	Runtime                 CapacityGuestRetirementLifetime `json:"runtime"`
	Writers                 []CapacityGuestRetirementWriter `json:"writers"`
	WriterRosterSHA256      string                          `json:"writer_roster_sha256"`
	GuestExpiresMonotonicNS int64                           `json:"guest_expires_monotonic_ns"`
	GuestNonce              CapacityGuestRetirementNonceV2  `json:"guest_nonce"`
}

type CapacityGuestRetirementNonceV2 struct {
	Schema             string                          `json:"schema"`
	RequestID          string                          `json:"request_id"`
	AttemptID          string                          `json:"attempt_id"`
	PreflightSHA256    string                          `json:"preflight_sha256"`
	EnrollmentSHA256   string                          `json:"enrollment_sha256"`
	Actor              CapacityGuestRetirementLifetime `json:"actor"`
	Runtime            CapacityGuestRetirementLifetime `json:"runtime"`
	WriterRosterSHA256 string                          `json:"writer_roster_sha256"`
	NonceSHA256        string                          `json:"nonce_sha256"`
	IssuedMonotonicNS  int64                           `json:"issued_monotonic_ns"`
	ExpiresMonotonicNS int64                           `json:"expires_monotonic_ns"`
	Signature          string                          `json:"signature"`
}

type CapacityGuestRetirementRequestV2 struct {
	Intent    CapacityGuestRetirementIntentV2 `json:"intent"`
	Signature string                          `json:"signature"`
	Nonce     string                          `json:"nonce"`
}

// Clock is captured ONCE from the same original Guest operation, after nonce
// consumption and before private Runtime RPC; GuestLocalDeadline is local
// diagnostic wall projection only. Native CLOCK_MONOTONIC remains authority.
// Started/Returned <= accepted expiry checked by actual native reads. Runtime
// and Actor share same BootID and exact accepted expiry; no new timer.
type CapacityGuestRetirementClockV2 struct {
	Schema              string    `json:"schema"`
	BootID              string    `json:"boot_id"`
	GuestNonceSHA256    string    `json:"guest_nonce_sha256"`
	ExpiresMonotonicNS  int64     `json:"expires_monotonic_ns"`
	StartedMonotonicNS  int64     `json:"started_monotonic_ns"`
	ReturnedMonotonicNS int64     `json:"returned_monotonic_ns"`
	GuestLocalStartedAt time.Time `json:"guest_local_started_at"`
	GuestLocalDeadline  time.Time `json:"guest_local_deadline"`
}

type CapacityGuestRetirementAuthorityV2 struct {
	Schema                  string    `json:"schema"`
	Purpose                 string    `json:"purpose"`
	Phase                   string    `json:"phase"`
	IntentSHA256            string    `json:"intent_sha256"`
	AttemptID               string    `json:"attempt_id"`
	NonceSHA256             string    `json:"nonce_sha256"`
	EnrollmentSHA256        string    `json:"enrollment_sha256"`
	State                   string    `json:"state"`
	SourceCommit            string    `json:"source_commit"`
	OriginalDeadline        time.Time `json:"original_deadline"`
	ObservedAt              time.Time `json:"observed_at"`
	GuestNonceSHA256        string    `json:"guest_nonce_sha256"`
	GuestExpiresMonotonicNS int64     `json:"guest_expires_monotonic_ns"`
}

type CapacityGuestRetirementRuntimeReturnV2 struct {
	Schema                string                                   `json:"schema"`
	IntentSHA256          string                                   `json:"intent_sha256"`
	AttemptID             string                                   `json:"attempt_id"`
	Runtime               CapacityGuestRetirementLifetime          `json:"runtime"`
	WriterRosterSHA256    string                                   `json:"writer_roster_sha256"`
	WithdrawRequestSHA256 string                                   `json:"withdraw_request_sha256"`
	DrainRequestSHA256    string                                   `json:"drain_request_sha256"`
	Withdraw              CapacityGuestRetirementOriginalOperation `json:"withdraw"`
	Drain                 CapacityGuestRetirementOriginalOperation `json:"drain"`
	CensusBefore          CapacityGuestRetirementProtectedCensus   `json:"census_before"`
	CensusAfter           CapacityGuestRetirementProtectedCensus   `json:"census_after"`
	Writers               []CapacityGuestRetirementWriterReturn    `json:"writers"`
	UnknownWriters        []string                                 `json:"unknown_writers"`
	ReturnedAt            time.Time                                `json:"returned_at"`
	Clock                 CapacityGuestRetirementClockV2           `json:"clock"`
}

type CapacityGuestRetirementRuntimeInputV2 struct {
	Schema        string                                     `json:"schema"`
	Intent        CapacityGuestRetirementIntentV2            `json:"intent"`
	Enrollment    CapacityGuestRetirementEnrollmentStatement `json:"enrollment"`
	CoreSignature string                                     `json:"core_signature"`
}

type CapacityGuestRetirementRecordV2 struct {
	Schema                   string                                  `json:"schema"`
	Sequence                 int                                     `json:"sequence"`
	PreviousSHA256           string                                  `json:"previous_sha256"`
	State                    string                                  `json:"state"`
	Intent                   CapacityGuestRetirementIntentV2         `json:"intent"`
	IntentSHA256             string                                  `json:"intent_sha256"`
	EnrollmentSHA256         string                                  `json:"enrollment_sha256"`
	PossibleStartAt          time.Time                               `json:"possible_start_at"`
	RuntimeOperation         *CapacityGuestRetirementOperationReturn `json:"runtime_operation,omitempty"`
	RuntimeReturn            *CapacityGuestRetirementRuntimeReturnV2 `json:"runtime_return,omitempty"`
	WriterQuiescenceEvidence bool                                    `json:"writer_quiescence_evidence"`
	WriterQuiescenceScope    string                                  `json:"writer_quiescence_scope"`
	PoweroffPossibleStartAt  *time.Time                              `json:"poweroff_possible_start_at,omitempty"`
	PoweroffOperation        *CapacityGuestRetirementOperationReturn `json:"poweroff_operation,omitempty"`
	PoweroffCommandReturned  bool                                    `json:"poweroff_command_returned"`
	PoweredOffObserved       bool                                    `json:"powered_off_observed"`
	RecordedAt               time.Time                               `json:"recorded_at"`
	Clock                    CapacityGuestRetirementClockV2          `json:"clock"`
}

type CapacityGuestRetirementObservationV2 struct {
	Schema             string                          `json:"schema"`
	Record             CapacityGuestRetirementRecordV2 `json:"record"`
	RecordSHA256       string                          `json:"record_sha256"`
	JournalComplete    bool                            `json:"journal_complete"`
	HoldReasons        []string                        `json:"hold_reasons"`
	ActiveAttemptID    string                          `json:"active_attempt_id"`
	ActiveIntentSHA256 string                          `json:"active_intent_sha256"`
	Reader             CapacityGuestRetirementLifetime `json:"reader"`
	ObservedAt         time.Time                       `json:"observed_at"`
	Signature          string                          `json:"signature"`
	Clock              CapacityGuestRetirementClockV2  `json:"clock"`
}
