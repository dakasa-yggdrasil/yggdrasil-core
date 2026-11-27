package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Native lifecycle is a separate opt-in authority, never a legacy Guest slot
// or a write credential added to the read-only market collector.
type CapacityNativeWorkerLifecycleBinding struct {
	Mode              string                                     `json:"mode"`
	SourceCommit      string                                     `json:"source_commit"`
	MaxReadAgeSeconds int                                        `json:"max_read_age_seconds"`
	Profiles          []CapacityNativeWorkerExecutionProfile     `json:"profiles"`
	PhaseObserver     *CapacityNativeWorkerPhaseReadBinding      `json:"phase_observer,omitempty"`
	RegistryWriter    *CapacityNativeWorkerRegistryWriterBinding `json:"registry_writer,omitempty"`
	PreAdmissionAbort *CapacityNativeWorkerAbortBinding          `json:"pre_admission_abort,omitempty"`
}

type CapacityNativeWorkerExecutionProfile struct {
	Profile               string                       `json:"profile"`
	Adapter               CapacityMarketAdapterBinding `json:"adapter"`
	BindingName           string                       `json:"binding_name"`
	SDKSourceCommit       string                       `json:"sdk_source_commit"`
	ScopeSHA256           string                       `json:"scope_sha256"`
	EnsureCapability      string                       `json:"ensure_capability"`
	ObserveCapability     string                       `json:"observe_capability"`
	DestroyCapability     string                       `json:"destroy_capability"`
	LaunchTemplateSHA256  string                       `json:"launch_template_sha256"`
	BootstrapSourceCommit string                       `json:"bootstrap_source_commit"`
	IPAMScope             string                       `json:"ipam_scope"`
	OverlayCIDR           string                       `json:"overlay_cidr"`
	ExcludedIPv4          []string                     `json:"excluded_ipv4"`
}

// Attempt IDs and addresses are allocated by Core. There is no predeclared
// array of slots and no elapsed-time release of a possible provider send.
type CapacityNativeWorkerAttempt struct {
	ID                          uuid.UUID                            `json:"id"`
	PolicyID                    uuid.UUID                            `json:"policy_id"`
	PolicyChecksum              string                               `json:"policy_checksum"`
	Namespace                   string                               `json:"namespace"`
	Environment                 string                               `json:"environment"`
	Domain                      string                               `json:"domain"`
	Dimension                   string                               `json:"dimension"`
	Generation                  int64                                `json:"generation"`
	FencingToken                int64                                `json:"fencing_token"`
	PoolUID                     string                               `json:"pool_uid"`
	PoolEpoch                   int64                                `json:"pool_epoch"`
	Registry                    CapacityNativePoolRegistryRef        `json:"registry"`
	Profile                     string                               `json:"profile"`
	Provider                    string                               `json:"provider"`
	Region                      string                               `json:"region"`
	ProviderIDPrefix            string                               `json:"provider_id_prefix"`
	SourceCommit                string                               `json:"source_commit"`
	Execution                   CapacityNativeWorkerExecutionProfile `json:"execution"`
	NetworkBindingSHA256        string                               `json:"network_binding_sha256"`
	PhysicalSpecSHA256          string                               `json:"physical_spec_sha256"`
	QualificationEvidenceSHA256 string                               `json:"qualification_evidence_sha256"`
	QualificationValidUntil     time.Time                            `json:"qualification_valid_until"`
	OverlayIPv4                 string                               `json:"overlay_ipv4"`
	LaunchSHA256                string                               `json:"launch_sha256"`
	IntentSHA256                string                               `json:"intent_sha256"`
	State                       string                               `json:"state"`
	Revision                    int64                                `json:"revision"`
	Reservation                 CapacityMarketReservation            `json:"reservation"`
	GroupFixedCostMicros        int64                                `json:"group_fixed_cost_micros"`
	Physical                    *CapacityNativeWorkerPhysical        `json:"physical,omitempty"`
	BirthSHA256                 string                               `json:"birth_sha256,omitempty"`
	NodeUID                     string                               `json:"node_uid,omitempty"`
	CreatedAt                   time.Time                            `json:"created_at"`
	UpdatedAt                   time.Time                            `json:"updated_at"`
}

// Full semantic identity extracted from the original acceptance and compared
// with an independently current bound SDK read. No provider SDK import here.
type CapacityNativeWorkerPhysical struct {
	ResourceID            string    `json:"resource_id"`
	ProviderID            string    `json:"provider_id"`
	AccountID             string    `json:"account_id"`
	InstanceType          string    `json:"instance_type"`
	NetworkID             string    `json:"network_id"`
	CreatedAt             time.Time `json:"created_at"`
	ImageID               string    `json:"image_id"`
	Region                string    `json:"region"`
	Zone                  string    `json:"zone"`
	NativeIPv4            string    `json:"native_ipv4"`
	MACAddress            string    `json:"mac_address"`
	PhysicalSpecSHA256    string    `json:"physical_spec_sha256"`
	PhysicalBindingSHA256 string    `json:"physical_binding_sha256"`
	LaunchSHA256          string    `json:"launch_sha256"`
}

// Birth is neutral registry provenance, not a forged legacy mutation proof.
type CapacityNativeWorkerBirth struct {
	Schema                   string                       `json:"schema"`
	AttemptID                uuid.UUID                    `json:"attempt_id"`
	PolicyID                 uuid.UUID                    `json:"policy_id"`
	Generation               int64                        `json:"generation"`
	FencingToken             int64                        `json:"fencing_token"`
	PoolUID                  string                       `json:"pool_uid"`
	PoolEpoch                int64                        `json:"pool_epoch"`
	ExecutionAdapter         CapacityMarketAdapterBinding `json:"execution_adapter"`
	ExecutionScopeSHA256     string                       `json:"execution_scope_sha256"`
	LaunchSHA256             string                       `json:"launch_sha256"`
	OriginalAcceptanceSHA256 string                       `json:"original_acceptance_sha256"`
	IndependentReadSHA256    string                       `json:"independent_read_sha256"`
	OriginalRequestID        string                       `json:"original_request_id"`
	IndependentRequestID     string                       `json:"independent_request_id"`
	Physical                 CapacityNativeWorkerPhysical `json:"physical"`
}

// These request operands carry no provider acceptance, prices or observation.
type CapacityNativeWorkerAuthority struct {
	Generation   int64 `json:"generation"`
	FencingToken int64 `json:"fencing_token"`
}

// Permit is returned once, only after send_started commits. It is a private
// runtime operand, never proof that a provider accepted or a Node is useful.
type CapacityNativeWorkerPermit struct {
	AttemptID        uuid.UUID
	LaunchSHA256     string
	OverlayIPv4      string
	Adapter          CapacityMarketAdapterBinding
	BindingName      string
	Capability       string
	PublicLaunchJSON json.RawMessage `json:"-"`
}

// OriginalReturn is private custody. It must never be embedded in public
// responses; even malformed/partial/error returns precede any SDK qualification.
type CapacityNativeWorkerOriginalReturn struct {
	Wire            []byte `json:"-"`
	ErrorClass      string `json:"-"`
	CaptureComplete bool   `json:"-"`
}

const CapacityNativeWorkerCommandSchema = "native_worker_attempt_command_v1"

// This private actor protocol never includes controller executor/workflow IDs,
// original-return hashes or bootstrap credentials. Read never returns a launch.
type CapacityNativeWorkerCommand struct {
	Schema               string                                `json:"schema"`
	AttemptID            uuid.UUID                             `json:"attempt_id"`
	BindingName          string                                `json:"binding_name"`
	AttemptState         string                                `json:"attempt_state"`
	MutationPermitted    bool                                  `json:"mutation_permitted"`
	Redeemable           bool                                  `json:"redeemable"`
	ExpiresAt            time.Time                             `json:"expires_at"`
	SDKSourceCommit      string                                `json:"sdk_source_commit"`
	ExecutionScopeSHA256 string                                `json:"execution_scope_sha256"`
	Profile              string                                `json:"profile,omitempty"`
	Provider             string                                `json:"provider,omitempty"`
	Region               string                                `json:"region,omitempty"`
	LaunchSHA256         string                                `json:"launch_sha256,omitempty"`
	OverlayIPv4          string                                `json:"overlay_ipv4,omitempty"`
	Execution            *CapacityNativeWorkerExecutionProfile `json:"execution,omitempty"`
	PublicLaunchJSON     json.RawMessage                       `json:"public_launch_json,omitempty"`
}

// Caller is assembled exclusively by authenticated protected HTTP composition.
type CapacityNativeWorkerCommandCaller struct {
	BindingName     string
	InstanceID      string
	SDKSourceCommit string
	Capability      string
}

// Receive carries original transport custody, not ACK or lifecycle assertions.
// Neither these bytes nor their raw hash belongs in public Attempt metadata.
type CapacityNativeWorkerCommandReceive struct {
	AttemptID       uuid.UUID `json:"attempt_id"`
	BindingName     string    `json:"binding_name"`
	OriginalReturn  []byte    `json:"original_return"`
	CaptureComplete bool      `json:"capture_complete"`
	ErrorClass      string    `json:"error_class"`
}

type CapacityNativeWorkerLaunch struct {
	AttemptID      uuid.UUID
	PoolUID        string
	PoolEpoch      int64
	Generation     int64
	FencingToken   int64
	OverlayIPv4    string
	TemplateSHA256 string
	PublicJSON     json.RawMessage
}

// Observation can only originate from a protected installed runtime callback,
// never a workflow/RPC DTO. Concrete SDK/network/registry collectors are separate.
type CapacityNativeWorkerObservation struct {
	State                         string
	ExecutionScopeSHA256          string
	ObservedAt                    time.Time
	OriginalReturnSHA256          string `json:"-"`
	OriginalAcceptance            CapacityNativeWorkerPhysical
	IndependentCurrent            CapacityNativeWorkerPhysical
	OriginalRequestID             string
	IndependentRequestID          string
	NodeUID                       string
	NodeProviderID                string
	RegistryUID                   string
	RegistryBeforeResourceVersion string
	RegistryAfterResourceVersion  string
	NetworkEvidenceSHA256         string
	NetworkBindingSHA256          string
	WarmupEvidenceSHA256          string
	QualificationEvidenceSHA256   string
	AdmissionReceiptSHA256        string
	DrainEvidenceSHA256           string
	ProviderAbsenceEvidenceSHA256 string
	NetworkAbsenceEvidenceSHA256  string
	AbsentProviderID              string
	AbsentResourceCreatedAt       time.Time
	AbsentOverlayIPv4             string
}

const CapacityNativeWorkerPhasePermitSchema = "native_worker_kube_phase_permit_v1"

// Registry writer credentials and authority are independent from the read-only
// pool/market collectors. A single permit authorizes exactly one native CAS.
type CapacityNativeWorkerRegistryWriterBinding struct {
	Adapter          CapacityMarketAdapterBinding `json:"adapter"`
	BindingName      string                       `json:"binding_name"`
	PrincipalID      string                       `json:"principal_id"`
	SourceCommit     string                       `json:"source_commit"`
	ScopeSHA256      string                       `json:"scope_sha256"` // SHA256 of the exact complete reviewed writer inventory bytes.
	Capability       string                       `json:"capability"`
	MaxPermitSeconds int                          `json:"max_permit_seconds"`
}

type CapacityNativeWorkerPhaseNode struct {
	Name                      string `json:"name"`
	UID                       string `json:"uid"`
	ResourceVersion           string `json:"resource_version"`
	ProviderID                string `json:"provider_id"`
	Profile                   string `json:"profile"`
	PhysicalSpecSHA256        string `json:"physical_spec_sha256"`
	RegistrationBindingSHA256 string `json:"registration_binding_sha256"`
	CapacityPolicyID          string `json:"capacity_policy_id"`
	IntentGeneration          int64  `json:"intent_generation"`
	FencingToken              int64  `json:"fencing_token"`
	CreationProofSHA256       string `json:"creation_proof_sha256"`
}

type CapacityNativeWorkerPhaseAdmission struct {
	ReceiptSHA256               string `json:"receipt_sha256,omitempty"`
	NetworkBindingSHA256        string `json:"network_binding_sha256,omitempty"`
	WarmupEvidenceSHA256        string `json:"warmup_evidence_sha256,omitempty"`
	PhysicalQualificationSHA256 string `json:"physical_qualification_sha256,omitempty"`
}

// Read always returns MutationPermitted=false and no settlement token. Only
// the original successful Redeem returns a private one-send mutation permit.
type CapacityNativeWorkerPhasePermit struct {
	Schema                          string                             `json:"schema"`
	PermitID                        uuid.UUID                          `json:"permit_id"`
	AttemptID                       uuid.UUID                          `json:"attempt_id"`
	BindingName                     string                             `json:"binding_name"`
	WriterScopeSHA256               string                             `json:"writer_scope_sha256"`
	Operation                       string                             `json:"operation"`
	Action                          string                             `json:"action"`
	PolicyID                        uuid.UUID                          `json:"policy_id"`
	IntentGeneration                int64                              `json:"intent_generation"`
	FencingToken                    int64                              `json:"fencing_token"`
	PoolUID                         string                             `json:"pool_uid"`
	Owner                           string                             `json:"owner"`
	Epoch                           int64                              `json:"epoch"`
	RealmNamespace                  string                             `json:"realm_namespace"`
	RealmUID                        string                             `json:"realm_uid"`
	Registry                        CapacityNativePoolRegistryRef      `json:"registry"`
	ExpectedRegistryResourceVersion string                             `json:"expected_registry_resource_version"`
	ExpectedRegistrySHA256          string                             `json:"expected_registry_sha256"`
	Node                            CapacityNativeWorkerPhaseNode      `json:"node"`
	Admission                       CapacityNativeWorkerPhaseAdmission `json:"admission"`
	ExpiresAt                       time.Time                          `json:"expires_at"`
	MutationPermitted               bool                               `json:"mutation_permitted"`
	Redeemable                      bool                               `json:"redeemable"`
	PhaseState                      string                             `json:"phase_state"`
	SettlementToken                 string                             `json:"settlement_token,omitempty"`
}

// Caller identity is assembled by authenticated server composition. It is not
// decoded from the capability input, which contains only binding and permit ID.
type CapacityNativeWorkerPhaseCaller struct {
	Adapter      CapacityMarketAdapterBinding
	PrincipalID  string
	BindingName  string
	SourceCommit string
}

// Receive is authenticated original-return custody, not admission authority.
// OriginalReturn and its hash never enter public read/workflow metadata.
type CapacityNativeWorkerPhaseReceive struct {
	PermitID           uuid.UUID `json:"permit_id"`
	BindingName        string    `json:"binding_name"`
	SettlementToken    string    `json:"settlement_token"`
	HTTPStatus         int       `json:"http_status"`
	TransportCompleted bool      `json:"transport_completed"`
	OriginalReturn     []byte    `json:"original_return"`
	CompletedAt        time.Time `json:"completed_at"`
}

// Prepared/observed facts come only from installed read-only runtime callbacks.
// Neither a workflow request nor the mutating adapter supplies these booleans.
type CapacityNativeWorkerPhasePreparation struct {
	Context           CapacityNativeWorkerPhasePermit
	ObservedAt        time.Time
	NodeReady         bool
	NetworkVerified   bool
	WarmupVerified    bool
	PhysicalQualified bool
}

type CapacityNativeWorkerPhaseObservation struct {
	RealmUID                string
	PoolUID                 string
	Owner                   string
	Epoch                   int64
	ObservedAt              time.Time
	Applied                 bool
	NodeUID                 string
	RegistryUID             string
	RegistryResourceVersion string
	RegistrySHA256          string
	ProviderID              string
	AdmissionReceiptSHA256  string
	QuarantineAbsent        bool
	Ready                   bool
}

// Phase observation has a separate read-only instance and exact mounted file pin.
type CapacityNativeWorkerPhaseReadBinding struct {
	Mode               string                       `json:"mode"`
	Name               string                       `json:"name"`
	SourceCommit       string                       `json:"source_commit"`
	Adapter            CapacityMarketAdapterBinding `json:"adapter"`
	ScopeSHA256        string                       `json:"scope_sha256"`
	RealmNamespace     string                       `json:"realm_namespace"`
	MaxAgeSeconds      int                          `json:"max_age_seconds"`
	QuarantineTaintKey string                       `json:"quarantine_taint_key"`
}

// Readiness facts are installed private Go callbacks, never decoded workflow input.
type CapacityNativeWorkerReadinessProof struct {
	AttemptID                   uuid.UUID
	NodeUID                     string
	ProviderID                  string
	WorkerIPv4                  string
	BirthSHA256                 string
	Physical                    CapacityNativeWorkerPhysical
	NetworkBindingSHA256        string
	NetworkEvidenceSHA256       string
	WarmupEvidenceSHA256        string
	PhysicalQualificationSHA256 string
	ObservedAt                  time.Time
	ValidUntil                  time.Time
}

type CapacityNativeWorkerRegistryEntry struct {
	NodeUID                   string                                `json:"node_uid"`
	ProviderID                string                                `json:"provider_id"`
	Profile                   string                                `json:"profile"`
	PhysicalSpecSHA256        string                                `json:"physical_spec_sha256"`
	RegistrationBindingSHA256 string                                `json:"registration_binding_sha256"`
	CapacityPolicyID          string                                `json:"capacity_policy_id"`
	IntentGeneration          int64                                 `json:"intent_generation"`
	FencingToken              int64                                 `json:"fencing_token"`
	CreationProofSHA256       string                                `json:"creation_proof_sha256"`
	Admission                 CapacityNativeWorkerRegistryAdmission `json:"admission"`
}

type CapacityNativeWorkerRegistryAdmission struct {
	State                       string `json:"state"`
	ReceiptSHA256               string `json:"receipt_sha256"`
	NetworkBindingSHA256        string `json:"network_binding_sha256"`
	WarmupEvidenceSHA256        string `json:"warmup_evidence_sha256"`
	PhysicalQualificationSHA256 string `json:"physical_qualification_sha256"`
}

type CapacityNativeWorkerPhaseReadObservation struct {
	BindingScopeSHA256            string                               `json:"binding_scope_sha256"`
	Schema                        string                               `json:"schema"`
	SourceCommit                  string                               `json:"source_commit"`
	Adapter                       CapacityMarketAdapterBinding         `json:"adapter"`
	BindingName                   string                               `json:"binding_name"`
	RequestedProviderID           string                               `json:"requested_provider_id"`
	RequestedCreationProofSHA256  string                               `json:"requested_creation_proof_sha256"`
	ObservedAt                    time.Time                            `json:"observed_at"`
	Complete                      bool                                 `json:"complete"`
	FullCollectionComplete        bool                                 `json:"full_collection_complete"`
	CollectionResourceVersion     string                               `json:"collection_resource_version"`
	CandidateSelected             bool                                 `json:"candidate_selected"`
	CandidateAbsenceProven        bool                                 `json:"candidate_absence_proven"`
	EvidenceSHA256                string                               `json:"evidence_sha256"`
	MutationAuthorized            bool                                 `json:"mutation_authorized"`
	UsefulCapacityQualified       bool                                 `json:"useful_capacity_qualified"`
	Registry                      CapacityNativeWorkerPhaseRegistry    `json:"registry"`
	Registrations                 []CapacityNativeWorkerRegistryEntry  `json:"registrations"`
	RegistryRegistrationsComplete bool                                 `json:"registry_registrations_complete"`
	Candidates                    []CapacityNativeWorkerPhaseCandidate `json:"candidates"`
}
type CapacityNativeWorkerPhaseRegistry struct {
	Ref              CapacityNativePoolRegistryRef `json:"ref"`
	RealmNamespace   string                        `json:"realm_namespace"`
	RealmUID         string                        `json:"realm_uid"`
	PoolUID          string                        `json:"pool_uid"`
	Owner            string                        `json:"owner"`
	Epoch            int64                         `json:"epoch"`
	CurrentProfile   string                        `json:"current_profile"`
	ResourceVersion  string                        `json:"resource_version"`
	AnnotationSHA256 string                        `json:"annotation_sha256"`
}
type CapacityNativeWorkerPhaseCandidate struct {
	NodeName                       string                              `json:"node_name"`
	NodeUID                        string                              `json:"node_uid"`
	NodeResourceVersion            string                              `json:"node_resource_version"`
	ProviderID                     string                              `json:"provider_id"`
	Addresses                      []CapacityNativeWorkerPhaseAddress  `json:"addresses"`
	ProfileLabel                   string                              `json:"profile_label"`
	PoolUIDLabel                   string                              `json:"pool_uid_label"`
	PhysicalSpecSHA256Label        string                              `json:"physical_spec_sha256_label"`
	RegistrationBindingSHA256Label string                              `json:"registration_binding_sha256_label"`
	PolicyIDLabel                  string                              `json:"policy_id_label"`
	GenerationLabel                string                              `json:"generation_label"`
	FencingTokenLabel              string                              `json:"fencing_token_label"`
	CreationProofSHA256Label       string                              `json:"creation_proof_sha256_label"`
	Taints                         []CapacityNativeWorkerPhaseTaint    `json:"taints"`
	Deleting                       bool                                `json:"deleting"`
	Unschedulable                  bool                                `json:"unschedulable"`
	Ready                          bool                                `json:"ready"`
	Heartbeat                      CapacityNativeWorkerPhaseHeartbeat  `json:"heartbeat"`
	AllocatableKnown               bool                                `json:"allocatable_known"`
	AllocatableMilliCPU            int64                               `json:"allocatable_millicpu"`
	AllocatableMemoryBytes         int64                               `json:"allocatable_memory_bytes"`
	Registrations                  []CapacityNativeWorkerRegistryEntry `json:"registrations"`
}
type CapacityNativeWorkerPhaseAddress struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

type CapacityNativeWorkerPhaseTaint struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Effect    string `json:"effect"`
	TimeAdded string `json:"time_added,omitempty"`
}
type CapacityNativeWorkerPhaseHeartbeat struct {
	Present         bool      `json:"present"`
	Fresh           bool      `json:"fresh"`
	UID             string    `json:"uid"`
	ResourceVersion string    `json:"resource_version"`
	ObservedAt      time.Time `json:"observed_at"`
}

func (v *CapacityNativeWorkerPhaseReadObservation) UnmarshalJSON(raw []byte) error {
	type plain CapacityNativeWorkerPhaseReadObservation
	var out plain
	if err := decodeCapacityMarketJSON(raw, &out); err != nil {
		return err
	}
	*v = CapacityNativeWorkerPhaseReadObservation(out)
	return nil
}
