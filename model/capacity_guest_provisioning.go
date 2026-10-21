package model

import "time"

// This immutable source profile enumerates every protected writer BEFORE
// admission. It is an approved source/body/image contract, not the opaque
// provider cloud-init template or a caller's completeness flag.
type CapacityGuestProtectedProfileManifest struct {
	Schema                            string                                   `json:"schema"`
	Profile                           string                                   `json:"profile"`
	CoverageClass                     string                                   `json:"coverage_class"`
	ProductionCatalogSHA256           string                                   `json:"production_catalog_sha256"`
	MutationBinding                   string                                   `json:"mutation_binding"`
	BootstrapOwnerSourceCommit        string                                   `json:"bootstrap_owner_source_commit"`
	BootstrapOwnerBinarySHA256        string                                   `json:"bootstrap_owner_binary_sha256"`
	BootstrapReaderBinarySHA256       string                                   `json:"bootstrap_reader_binary_sha256"`
	BootstrapPayloadSHA256            string                                   `json:"bootstrap_payload_sha256"`
	BootstrapSHA256                   string                                   `json:"bootstrap_sha256"`
	OriginalProvisioningBudgetSeconds int                                      `json:"original_provisioning_budget_seconds"`
	OriginalProvisioningStepID        string                                   `json:"original_provisioning_step_id"`
	OwnerSourceCommit                 string                                   `json:"owner_source_commit"`
	OwnerBinarySHA256                 string                                   `json:"owner_binary_sha256"`
	OwnerImageDigest                  string                                   `json:"owner_image_digest"`
	ProtectedCgroup                   string                                   `json:"protected_cgroup"`
	ActorSourceCommit                 string                                   `json:"actor_source_commit"`
	ActorBinarySHA256                 string                                   `json:"actor_binary_sha256"`
	RuntimeClientCommandSHA256        string                                   `json:"runtime_client_command_sha256"`
	PoweroffCommandSHA256             string                                   `json:"poweroff_command_sha256"`
	Writers                           []CapacityGuestProtectedWriterDefinition `json:"writers"`
	NotifyCanaryTopology              *CapacityGuestNotifyCanaryTopology       `json:"notify_canary_topology,omitempty"`
}

// Reserved by the protected owning workflow BEFORE the original provider
// send. A later GET/callback/lease renewal never rewrites this deadline, source
// profile or original generation/fence. The native tuple is not promised here.
type CapacityGuestOriginalProvisioningPreregistration struct {
	Schema                             string    `json:"schema"`
	PreregistrationID                  string    `json:"preregistration_id"`
	BindingName                        string    `json:"binding_name"`
	OriginalCreateGrantID              string    `json:"original_create_grant_id"`
	OriginalCreateRequestSHA256        string    `json:"original_create_request_sha256"`
	NonceSHA256                        string    `json:"nonce_sha256"`
	ProfileManifestSHA256              string    `json:"profile_manifest_sha256"`
	PolicyID                           string    `json:"policy_id"`
	PolicyChecksum                     string    `json:"policy_checksum"`
	WorkflowID                         string    `json:"workflow_id"`
	WorkflowChecksum                   string    `json:"workflow_checksum"`
	OriginalWorkflowStepID             string    `json:"original_workflow_step_id"`
	OriginalWorkflowStepTimeoutSeconds int       `json:"original_workflow_step_timeout_seconds"`
	OriginalWorkflowContextDeadline    time.Time `json:"original_workflow_context_deadline"`
	CoreSourceCommit                   string    `json:"core_source_commit"`
	Generation                         int64     `json:"generation"`
	Fence                              int64     `json:"fence"`
	LeaseOwner                         string    `json:"lease_owner"`
	ExecutorID                         string    `json:"executor_id"`
	Slot                               int       `json:"slot"`
	OriginalDeadline                   time.Time `json:"original_deadline"`
	ReservedAt                         time.Time `json:"reserved_at"`
}

type CapacityGuestProtectedWriterDefinition struct {
	ID                       string `json:"id"`
	SourceCommit             string `json:"source_commit"`
	BinarySHA256             string `json:"binary_sha256"`
	CommandSHA256            string `json:"command_sha256"`
	ImageDigest              string `json:"image_digest"`
	SourceImageReceiptSHA256 string `json:"source_image_receipt_sha256"`
	HandleContractSHA256     string `json:"handle_contract_sha256"`
	CgroupRelativePath       string `json:"cgroup_relative_path"`
}

// Only separately approved original provisioning can produce this record.
// Its native tuple is learned from the owning create return, never promised
// in pre-POST user-data. Original placement returns and the fixed native
// enclosure must join the full source profile before enrollment/admission.
type CapacityGuestOriginalProvisioningResult struct {
	Schema                         string                          `json:"schema"`
	BindingName                    string                          `json:"binding_name"`
	SourceClass                    string                          `json:"source_class"`
	ProvisionerSourceCommit        string                          `json:"provisioner_source_commit"`
	OriginalCreateGrantID          string                          `json:"original_create_grant_id"`
	OriginalCreateAttemptID        string                          `json:"original_create_attempt_id"`
	OriginalCreateSettlementSHA256 string                          `json:"original_create_settlement_sha256"`
	PreregistrationID              string                          `json:"preregistration_id"`
	PreregistrationNonceSHA256     string                          `json:"preregistration_nonce_sha256"`
	Tuple                          CapacityGuestNativeTuple        `json:"tuple"`
	ProfileManifestSHA256          string                          `json:"profile_manifest_sha256"`
	Actor                          CapacityGuestRetirementLifetime `json:"actor"`
	Runtime                        CapacityGuestRetirementLifetime `json:"runtime"`
	Writers                        []CapacityGuestRetirementWriter `json:"writers"`
	WriterPlacements               []struct {
		Writer             CapacityGuestRetirementWriter          `json:"writer"`
		DefinitionSHA256   string                                 `json:"definition_sha256"`
		ProtectedCgroup    string                                 `json:"protected_cgroup"`
		RequestSHA256      string                                 `json:"request_sha256"`
		Operation          CapacityGuestRetirementOperationReturn `json:"operation"`
		Census             CapacityGuestRetirementProtectedCensus `json:"census"`
		OriginalReturnedAt time.Time                              `json:"original_returned_at"`
	} `json:"writer_placements"`
	WriterRosterSHA256           string                                 `json:"writer_roster_sha256"`
	ProtectedCensus              CapacityGuestRetirementProtectedCensus `json:"protected_census"`
	PlacementOperation           CapacityGuestRetirementOperationReturn `json:"placement_operation"`
	BootstrapOriginalJournal     CapacityGuestJournal                   `json:"bootstrap_original_journal"`
	BootstrapOriginalObservation CapacityGuestObservation               `json:"bootstrap_original_observation"`
	AdmissionOpened              bool                                   `json:"admission_opened"`
	OriginalReturnedAt           time.Time                              `json:"original_returned_at"`
}

// A producer callback is signed separately from the Guest observation and
// retirement-intent keys. Core stores its original complete result once and
// resolves the SAME preregistration by GET after a lost reply.
type CapacityGuestOriginalProvisioningRegistration struct {
	Result              CapacityGuestOriginalProvisioningResult    `json:"result"`
	EnrollmentStatement CapacityGuestRetirementEnrollmentStatement `json:"enrollment_statement"`
	Signature           string                                     `json:"signature"`
}

type CapacityGuestOriginalProvisioningReceipt struct {
	PreregistrationID          string                            `json:"preregistration_id"`
	OriginalProvisioningSHA256 string                            `json:"original_provisioning_sha256"`
	Enrollment                 CapacityGuestRetirementEnrollment `json:"enrollment"`
	RecordedAt                 time.Time                         `json:"recorded_at"`
}

type CapacityGuestRetirementBinding struct {
	Mode                      string                                 `json:"mode"`
	MutationBindingName       string                                 `json:"mutation_binding_name"`
	EvidenceClass             string                                 `json:"evidence_class"`
	ProvisionerSourceCommit   string                                 `json:"provisioner_source_commit"`
	GuestSourceCommit         string                                 `json:"guest_source_commit"`
	CoreAuthoritySourceCommit string                                 `json:"core_authority_source_commit"`
	ProvisionerPublicKey      string                                 `json:"provisioner_public_key"`
	EnrollmentIssuerPublicKey string                                 `json:"enrollment_issuer_public_key"`
	EnrollmentSigningKeyRef   string                                 `json:"enrollment_signing_key_ref"`
	IntentSigningKeyRef       string                                 `json:"intent_signing_key_ref"`
	ProfileManifest           CapacityGuestProtectedProfileManifest  `json:"profile_manifest"`
	ProfileManifestSHA256     string                                 `json:"profile_manifest_sha256"`
	MaxEvidenceAgeSeconds     int                                    `json:"max_evidence_age_seconds"`
	Members                   []CapacityGuestRetirementMemberBinding `json:"members"`
}

// These separate private mTLS references never reuse the old bootstrap
// observer's SSH credential. No caller can select an origin or certificate.
type CapacityGuestRetirementMemberBinding struct {
	Name                       string `json:"name"`
	Slot                       int    `json:"slot"`
	Origin                     string `json:"origin"`
	ServerCARef                string `json:"server_ca_ref"`
	ClientCertificateRef       string `json:"client_certificate_ref"`
	ClientKeyRef               string `json:"client_key_ref"`
	ActorClientPrincipal       string `json:"actor_client_principal"`
	ProvisionerClientPrincipal string `json:"provisioner_client_principal"`
}

// The original provider return is independently signed by Core before any
// new Guest writer is admitted. Resource-created identity is never configured
// before the original ensure call or inferred from the Guest's own claim.
type CapacityGuestOriginalCreateWitness struct {
	SourceObservation      *CapacityGuestPostlossObservation    `json:"source_observation,omitempty"`
	ProviderNativeIdentity *CapacityGuestProviderNativeIdentity `json:"provider_native_identity,omitempty"`

	Schema                         string                   `json:"schema"`
	BindingName                    string                   `json:"binding_name"`
	PreregistrationID              string                   `json:"preregistration_id"`
	PreregistrationNonceSHA256     string                   `json:"preregistration_nonce_sha256"`
	Tuple                          CapacityGuestNativeTuple `json:"tuple"`
	OriginalCreateGrantID          string                   `json:"original_create_grant_id"`
	OriginalCreateAttemptID        string                   `json:"original_create_attempt_id"`
	OriginalCreateRequestSHA256    string                   `json:"original_create_request_sha256"`
	OriginalCreateSettlementSHA256 string                   `json:"original_create_settlement_sha256"`
	ProfileManifestSHA256          string                   `json:"profile_manifest_sha256"`
	BootstrapSHA256                string                   `json:"bootstrap_sha256"`
	CoreSourceCommit               string                   `json:"core_source_commit"`
	OriginalDeadline               time.Time                `json:"original_deadline"`
	OriginalCreateReturnedAt       time.Time                `json:"original_create_returned_at"`
	ObservedAt                     time.Time                `json:"observed_at"`
	Signature                      string                   `json:"signature"`
}
