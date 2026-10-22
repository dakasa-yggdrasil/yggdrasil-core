package model

import "time"

const OriginalCreateDispositionObservationSchema = "original_accepted_create_disposition_observation_v1"
const OriginalCreateDispositionSchema = "original_accepted_create_disposition_v1"

// This request is produced only from the retained owning Core records. It is
// not an HTTP client request and confers no provider mutation permission.
type CapacityOriginalCreateDispositionReadRequest struct {
	OriginalCreateActionID             string                              `json:"original_create_action_id,omitempty"`
	OriginalAuxiliaryInventoryComplete bool                                `json:"original_auxiliary_inventory_complete"`
	Profile                            string                              `json:"profile"`
	Slot                               int                                 `json:"slot"`
	GrantID                            string                              `json:"grant_id"`
	AttemptID                          string                              `json:"attempt_id"`
	RequestSHA256                      string                              `json:"request_sha256"`
	ExpectedResourceID                 string                              `json:"expected_resource_id"`
	ExpectedResourceCreatedAt          string                              `json:"expected_resource_created_at"`
	OriginalAdapterSourceCommit        string                              `json:"original_adapter_source_commit"`
	AuxiliaryResources                 []CapacityMutationAuxiliaryResource `json:"auxiliary_resources"`
}

// Candidate is private in-process source context. Returning a copy does not
// grant admission, renew the historical deadline, or authorize a new create.
type CapacityOriginalCreateDispositionCandidate struct {
	OriginalPolicy                Manifest
	Binding                       CapacityMutationBinding
	Preregistration               CapacityGuestOriginalProvisioningPreregistration
	Receipt                       CapacityMutationReceipt
	Request                       CapacityOriginalCreateDispositionReadRequest
	OriginalGrantSHA256           string
	OriginalPreregistrationSHA256 string
	OriginalBindingSHA256         string
	OriginalSettlementSHA256      string
	OriginalPolicySHA256          string
	OriginalWorkflowSHA256        string
	Generation                    int64
	FencingToken                  int64
	BeganAt                       time.Time
}

type CapacityOriginalCreateDispositionNativeRead struct {
	ResponseBodyBase64     string    `json:"response_body_base64"`
	ResponseRepresentation string    `json:"response_representation"`
	Operation              string    `json:"operation"`
	ResourceKind           string    `json:"resource_kind"`
	ResourceID             string    `json:"resource_id"`
	Status                 int       `json:"status"`
	ResponseSHA256         string    `json:"response_sha256"`
	ResponseBytes          int64     `json:"response_bytes"`
	CalledAt               time.Time `json:"called_at"`
	ReturnedAt             time.Time `json:"returned_at"`
}

// Observation is the closed output of the source-owned authenticated adapter
// GET. The HTTP disposition endpoint never accepts it from a request body.
type CapacityOriginalCreateDispositionObservation struct {
	InventoryBasis                             string                                        `json:"inventory_basis"`
	Schema                                     string                                        `json:"schema"`
	Provider                                   string                                        `json:"provider"`
	Profile                                    string                                        `json:"profile"`
	Slot                                       int                                           `json:"slot"`
	GrantID                                    string                                        `json:"grant_id"`
	AttemptID                                  string                                        `json:"attempt_id"`
	RequestSHA256                              string                                        `json:"request_sha256"`
	ResourceID                                 string                                        `json:"resource_id"`
	ResourceCreatedAt                          string                                        `json:"resource_created_at"`
	OriginalAdapterSourceCommit                string                                        `json:"original_adapter_source_commit"`
	AdapterSourceCommit                        string                                        `json:"adapter_source_commit"`
	ResourceState                              string                                        `json:"resource_state"`
	ResourceAbsenceComplete                    bool                                          `json:"resource_absence_complete"`
	AuxiliaryInventoryComplete                 bool                                          `json:"auxiliary_inventory_complete"`
	SharedResourcesPreserved                   bool                                          `json:"shared_resources_preserved"`
	AuxiliaryResources                         []CapacityVMAuxiliaryObservation              `json:"auxiliary_resources"`
	NativeReads                                []CapacityOriginalCreateDispositionNativeRead `json:"native_reads"`
	ObservationStartedAt                       time.Time                                     `json:"observation_started_at"`
	ObservedAt                                 time.Time                                     `json:"observed_at"`
	NativeMutations                            int                                           `json:"native_mutations"`
	GuestAdmissionOrBusinessOrSavingsAuthority bool                                          `json:"Guest_admission_or_business_or_savings_authority"`
}

// The original accepted grant/state/settlement remain byte-identical. This
// append-only record closes only the independently observed original lifetime.
type CapacityOriginalCreateDisposition struct {
	OriginalAuxiliaryInventoryComplete          bool                                         `json:"original_auxiliary_inventory_complete"`
	Schema                                      string                                       `json:"schema"`
	ID                                          string                                       `json:"id"`
	GrantID                                     string                                       `json:"grant_id"`
	PreregistrationID                           string                                       `json:"preregistration_id"`
	Issuer                                      string                                       `json:"issuer"`
	OriginalGrantSHA256                         string                                       `json:"original_grant_sha256"`
	OriginalPreregistrationSHA256               string                                       `json:"original_preregistration_sha256"`
	OriginalBindingSHA256                       string                                       `json:"original_binding_sha256"`
	OriginalSettlementSHA256                    string                                       `json:"original_settlement_sha256"`
	OriginalPolicySHA256                        string                                       `json:"original_policy_sha256"`
	OriginalWorkflowSHA256                      string                                       `json:"original_workflow_sha256"`
	PolicyID                                    string                                       `json:"policy_id"`
	OriginalGeneration                          int64                                        `json:"original_generation"`
	OriginalFencingToken                        int64                                        `json:"original_fencing_token"`
	ClosedGeneration                            int64                                        `json:"closed_generation"`
	ClosedFencingToken                          int64                                        `json:"closed_fencing_token"`
	OriginalDeadline                            time.Time                                    `json:"original_deadline"`
	Observation                                 CapacityOriginalCreateDispositionObservation `json:"observation"`
	ObservationSHA256                           string                                       `json:"observation_sha256"`
	RecordedAt                                  time.Time                                    `json:"recorded_at"`
	OriginalAcceptedUnchanged                   bool                                         `json:"original_accepted_unchanged"`
	OriginalWitnessEnrollmentInstallationAbsent bool                                         `json:"original_witness_enrollment_installation_absent"`
	HistoricalCoreSourceCommit                  string                                       `json:"historical_core_source_commit"`
	ServingOrBusinessOrSavingsAuthority         bool                                         `json:"serving_or_business_or_savings_authority"`
}
