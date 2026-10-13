package model

import "time"

// Closed separate privileged Guest retirement ABI. It grants no write
// authority to the old Guest bootstrap reader or to its SSH credential.
// Original request identities, operation returns, journal and native power
// observation remain distinct; no caller completion flag is authority.

type CapacityGuestRetirementLifetime struct {
	BootID              string `json:"boot_id"`
	ProcessNonceSHA256  string `json:"process_nonce_sha256"`
	PID                 int    `json:"pid"`
	StartTicks          uint64 `json:"start_ticks"`
	SourceCommit        string `json:"source_commit"`
	BinarySHA256        string `json:"binary_sha256"`
	ServiceInvocationID string `json:"service_invocation_id"`
}

type CapacityGuestRetirementWriter struct {
	ID       string                          `json:"id"`
	Lifetime CapacityGuestRetirementLifetime `json:"lifetime"`
}

type CapacityGuestRetirementEnrollmentStatement struct {
	Schema                     string                          `json:"schema"`
	Purpose                    string                          `json:"purpose"`
	BindingName                string                          `json:"binding_name"`
	SourceClass                string                          `json:"source_class"`
	ProvisionerSourceCommit    string                          `json:"provisioner_source_commit"`
	OriginalNativeResultSHA256 string                          `json:"original_native_result_sha256"`
	Tuple                      CapacityGuestNativeTuple        `json:"tuple"`
	Actor                      CapacityGuestRetirementLifetime `json:"actor"`
	Runtime                    CapacityGuestRetirementLifetime `json:"runtime"`
	Writers                    []CapacityGuestRetirementWriter `json:"writers"`
	WriterRosterSHA256         string                          `json:"writer_roster_sha256"`
	RuntimeCommandSHA256       string                          `json:"runtime_command_sha256"`
	PoweroffCommandSHA256      string                          `json:"poweroff_command_sha256"`
	ObservationPublicKey       string                          `json:"observation_public_key"`
	CoreIntentPublicKey        string                          `json:"core_intent_public_key"`
	CoreAuthoritySourceCommit  string                          `json:"core_authority_source_commit"`
	IssuedAt                   time.Time                       `json:"issued_at"`
}

type CapacityGuestRetirementEnrollment struct {
	Statement CapacityGuestRetirementEnrollmentStatement `json:"statement"`
	Signature string                                     `json:"signature"`
}

type CapacityGuestRetirementIntent struct {
	Schema                string                          `json:"schema"`
	Purpose               string                          `json:"purpose"`
	BindingName           string                          `json:"binding_name"`
	Slot                  int                             `json:"slot"`
	RequestID             string                          `json:"request_id"`
	AttemptID             string                          `json:"attempt_id"`
	NonceSHA256           string                          `json:"nonce_sha256"`
	EnrollmentSHA256      string                          `json:"enrollment_sha256"`
	Tuple                 CapacityGuestNativeTuple        `json:"tuple"`
	Actor                 CapacityGuestRetirementLifetime `json:"actor"`
	PolicyID              string                          `json:"policy_id"`
	PolicyChecksum        string                          `json:"policy_checksum"`
	WorkflowID            string                          `json:"workflow_id"`
	WorkflowChecksum      string                          `json:"workflow_checksum"`
	Generation            uint64                          `json:"generation"`
	Fence                 uint64                          `json:"fence"`
	LeaseOwner            string                          `json:"lease_owner"`
	WithdrawOperationID   string                          `json:"withdraw_operation_id"`
	WithdrawRequestSHA256 string                          `json:"withdraw_request_sha256"`
	DrainOperationID      string                          `json:"drain_operation_id"`
	DrainRequestSHA256    string                          `json:"drain_request_sha256"`
	OriginalDeadline      time.Time                       `json:"original_deadline"`
	IssuedAt              time.Time                       `json:"issued_at"`
}

type CapacityGuestRetirementRequest struct {
	Intent    CapacityGuestRetirementIntent `json:"intent"`
	Signature string                        `json:"signature"`
	Nonce     string                        `json:"nonce"`
}

type CapacityGuestRetirementAuthority struct {
	Schema           string    `json:"schema"`
	Purpose          string    `json:"purpose"`
	Phase            string    `json:"phase"`
	IntentSHA256     string    `json:"intent_sha256"`
	AttemptID        string    `json:"attempt_id"`
	NonceSHA256      string    `json:"nonce_sha256"`
	EnrollmentSHA256 string    `json:"enrollment_sha256"`
	State            string    `json:"state"`
	SourceCommit     string    `json:"source_commit"`
	OriginalDeadline time.Time `json:"original_deadline"`
	ObservedAt       time.Time `json:"observed_at"`
}

type CapacityGuestRetirementWriterReturn struct {
	Writer                      CapacityGuestRetirementWriter `json:"writer"`
	AdmissionClosedAt           time.Time                     `json:"admission_closed_at"`
	OriginalWithdrawReturnedAt  time.Time                     `json:"original_withdraw_returned_at"`
	OriginalWorkersJoinedAt     time.Time                     `json:"original_workers_joined_at"`
	OriginalConnectionsJoinedAt time.Time                     `json:"original_connections_joined_at"`
	OriginalResultSHA256        string                        `json:"original_result_sha256"`
	Outcome                     string                        `json:"outcome"`
}

type CapacityGuestRetirementOriginalOperation struct {
	OperationID        string    `json:"operation_id"`
	RequestSHA256      string    `json:"request_sha256"`
	ResultSHA256       string    `json:"result_sha256"`
	StartedAt          time.Time `json:"started_at"`
	OriginalReturnedAt time.Time `json:"original_returned_at"`
	Outcome            string    `json:"outcome"`
}

type CapacityGuestRetirementNativeProcess struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
}

type CapacityGuestRetirementProtectedCensus struct {
	Schema          string                                 `json:"schema"`
	Scope           string                                 `json:"scope"`
	SourceCommit    string                                 `json:"source_commit"`
	Processes       []CapacityGuestRetirementNativeProcess `json:"processes"`
	RawCensusSHA256 string                                 `json:"raw_census_sha256"`
	ObservedAt      time.Time                              `json:"observed_at"`
}

type CapacityGuestRetirementRuntimeReturn struct {
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
}

type CapacityGuestRetirementRuntimeInput struct {
	Schema     string                                     `json:"schema"`
	Intent     CapacityGuestRetirementIntent              `json:"intent"`
	Enrollment CapacityGuestRetirementEnrollmentStatement `json:"enrollment"`
}

type CapacityGuestRetirementOperationReturn struct {
	StartedAt             time.Time `json:"started_at"`
	PID                   int       `json:"pid"`
	StartTicks            uint64    `json:"start_ticks"`
	WaitReturnedAt        time.Time `json:"wait_returned_at"`
	ExitCode              int       `json:"exit_code"`
	BodyJoined            bool      `json:"body_joined"`
	CloseReturned         bool      `json:"close_returned"`
	OriginalContextFailed bool      `json:"original_context_failed"`
	Outcome               string    `json:"outcome"`
}

type CapacityGuestRetirementRecord struct {
	Schema                   string                                  `json:"schema"`
	Sequence                 int                                     `json:"sequence"`
	PreviousSHA256           string                                  `json:"previous_sha256"`
	State                    string                                  `json:"state"`
	Intent                   CapacityGuestRetirementIntent           `json:"intent"`
	IntentSHA256             string                                  `json:"intent_sha256"`
	EnrollmentSHA256         string                                  `json:"enrollment_sha256"`
	PossibleStartAt          time.Time                               `json:"possible_start_at"`
	RuntimeOperation         *CapacityGuestRetirementOperationReturn `json:"runtime_operation,omitempty"`
	RuntimeReturn            *CapacityGuestRetirementRuntimeReturn   `json:"runtime_return,omitempty"`
	WriterQuiescenceEvidence bool                                    `json:"writer_quiescence_evidence"`
	WriterQuiescenceScope    string                                  `json:"writer_quiescence_scope"`
	PoweroffPossibleStartAt  *time.Time                              `json:"poweroff_possible_start_at,omitempty"`
	PoweroffOperation        *CapacityGuestRetirementOperationReturn `json:"poweroff_operation,omitempty"`
	PoweroffCommandReturned  bool                                    `json:"poweroff_command_returned"`
	PoweredOffObserved       bool                                    `json:"powered_off_observed"`
	RecordedAt               time.Time                               `json:"recorded_at"`
}

type CapacityGuestRetirementObservation struct {
	Schema             string                          `json:"schema"`
	Record             CapacityGuestRetirementRecord   `json:"record"`
	RecordSHA256       string                          `json:"record_sha256"`
	JournalComplete    bool                            `json:"journal_complete"`
	HoldReasons        []string                        `json:"hold_reasons"`
	ActiveAttemptID    string                          `json:"active_attempt_id"`
	ActiveIntentSHA256 string                          `json:"active_intent_sha256"`
	Reader             CapacityGuestRetirementLifetime `json:"reader"`
	ObservedAt         time.Time                       `json:"observed_at"`
	Signature          string                          `json:"signature"`
}
