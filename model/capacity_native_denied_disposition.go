package model

import "time"

const NativeDeniedDispositionSchema = "original_native_authorization_denied_terminal_disposition_v1"
const NativeDeniedObservationSchema = "aws_original_authorization_denied_observation_v1"
const NativeDeniedReadRequestSchema = "aws_original_authorization_denied_read_request_v1"

// Produced from owning immutable records, never accepted from an HTTP caller.
// This is a decision proof, not historical absence or a reconstructed HTTP reply.
type CapacityNativeDeniedReadRequest struct {
	Schema                      string    `json:"schema"`
	Profile                     string    `json:"profile"`
	Slot                        int       `json:"slot"`
	GrantID                     string    `json:"grant_id"`
	AttemptID                   string    `json:"attempt_id"`
	RequestSHA256               string    `json:"request_sha256"`
	ScopeChecksum               string    `json:"scope_checksum"`
	OriginalAdapterSourceCommit string    `json:"original_adapter_source_commit"`
	GrantCreatedAt              time.Time `json:"grant_created_at"`
	SettlementObservedAt        time.Time `json:"settlement_observed_at"`
	OriginalDeadline            time.Time `json:"original_deadline"`
}

type CapacityNativeDeniedCandidate struct {
	Original CapacityOriginalCreateDispositionCandidate
	Request  CapacityNativeDeniedReadRequest
}

// The source-pinned observer independently resolves its account, principal,
// region and physical profile. STS/EC2 retain original HTTP bodies; CloudTrail
// retains only its explicit user-data-omitted projection, never the private body.
// No instance/volume/interface identity may be invented from a denied call.
type CapacityNativeDeniedObservation struct {
	Schema                                     string                                        `json:"schema"`
	Request                                    CapacityNativeDeniedReadRequest               `json:"request"`
	AdapterSourceCommit                        string                                        `json:"adapter_source_commit"`
	AccountID                                  string                                        `json:"account_id"`
	PrincipalARN                               string                                        `json:"principal_arn"`
	Region                                     string                                        `json:"region"`
	ClientToken                                string                                        `json:"client_token"`
	EventID                                    string                                        `json:"event_id"`
	RequestID                                  string                                        `json:"request_id"`
	DeniedAt                                   time.Time                                     `json:"denied_at"`
	Decision                                   string                                        `json:"decision"`
	HistoricalProfileRequestMatched            bool                                          `json:"historical_profile_request_matched"`
	SameTokenInstancesEmpty                    bool                                          `json:"same_token_instances_empty"`
	OriginalHTTPResponseAvailable              bool                                          `json:"original_HTTP_response_available"`
	ObservationStartedAt                       time.Time                                     `json:"observation_started_at"`
	ObservedAt                                 time.Time                                     `json:"observed_at"`
	NativeReads                                []CapacityOriginalCreateDispositionNativeRead `json:"native_reads"`
	NativeMutations                            int                                           `json:"native_mutations"`
	GuestAdmissionOrBusinessOrSavingsAuthority bool                                          `json:"Guest_admission_or_business_or_savings_authority"`
}

type CapacityNativeDeniedDisposition struct {
	Schema                                      string                          `json:"schema"`
	ID                                          string                          `json:"id"`
	GrantID                                     string                          `json:"grant_id"`
	PreregistrationID                           string                          `json:"preregistration_id"`
	JobID                                       string                          `json:"job_id"`
	RunID                                       string                          `json:"run_id"`
	Issuer                                      string                          `json:"issuer"`
	OriginalGrantSHA256                         string                          `json:"original_grant_sha256"`
	OriginalPreregistrationSHA256               string                          `json:"original_preregistration_sha256"`
	OriginalSettlementSHA256                    string                          `json:"original_settlement_sha256"`
	OriginalBindingSHA256                       string                          `json:"original_binding_sha256"`
	OriginalPolicySHA256                        string                          `json:"original_policy_sha256"`
	OriginalWorkflowSHA256                      string                          `json:"original_workflow_sha256"`
	OriginalDispatchSHA256                      string                          `json:"original_dispatch_sha256"`
	OriginalRunSHA256                           string                          `json:"original_run_sha256"`
	OriginalGeneration                          int64                           `json:"original_generation"`
	OriginalFencingToken                        int64                           `json:"original_fencing_token"`
	ClosedGeneration                            int64                           `json:"closed_generation"`
	ClosedFencingToken                          int64                           `json:"closed_fencing_token"`
	OriginalDeadline                            time.Time                       `json:"original_deadline"`
	HistoricalCoreSourceCommit                  string                          `json:"historical_core_source_commit"`
	Observation                                 CapacityNativeDeniedObservation `json:"observation"`
	ObservationSHA256                           string                          `json:"observation_sha256"`
	RecordedAt                                  time.Time                       `json:"recorded_at"`
	OriginalUncertainAndNullIdentitiesUnchanged bool                            `json:"original_uncertain_and_NULL_identities_unchanged"`
	OriginalUnknownACKPreserved                 bool                            `json:"original_unknown_ACK_preserved"`
	WitnessEnrollmentInstallationAbsent         bool                            `json:"witness_enrollment_installation_absent"`
	ServingOrBusinessOrSavingsAuthority         bool                            `json:"serving_or_business_or_savings_authority"`
}
