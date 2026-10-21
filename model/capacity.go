package model

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executorpower"
	"time"

	"github.com/google/uuid"
)

// CapacityPolicySpec is an operator-owned, provider-neutral capacity envelope.
// Price records and validation references are declarations, not live stock receipts.
type CapacityPolicySpec struct {
	GuestNotifyCanaryBinding    *CapacityGuestNotifyCanaryBinding    `json:"guest_notify_canary_binding,omitempty"`
	ExecutorPowerBinding        *executorpower.Binding               `json:"executor_power_binding,omitempty"`
	Environment                 string                               `json:"environment"`
	Domain                      string                               `json:"domain"`
	Dimension                   string                               `json:"dimension"`
	TargetIdentity              string                               `json:"target_identity"`
	Owner                       string                               `json:"owner"`
	Workflow                    ManifestSelector                     `json:"workflow"`
	Currency                    string                               `json:"currency"`
	Floor                       int                                  `json:"floor"`
	Ceiling                     int                                  `json:"ceiling"`
	Step                        int                                  `json:"step"`
	MaxEvidenceAgeSeconds       int                                  `json:"max_evidence_age_seconds"`
	MinSamples                  int                                  `json:"min_samples"`
	MaxSampleGapSeconds         int                                  `json:"max_sample_gap_seconds"`
	UpHoldSeconds               int                                  `json:"up_hold_seconds"`
	DownHoldSeconds             int                                  `json:"down_hold_seconds"`
	CooldownSeconds             int                                  `json:"cooldown_seconds"`
	LeaseSeconds                int                                  `json:"lease_seconds"`
	ExecutionEnabled            bool                                 `json:"execution_enabled"`
	Signals                     []CapacitySignalRule                 `json:"signals"`
	Profiles                    []CapacityProfile                    `json:"profiles"`
	MutationBindings            []CapacityMutationBinding            `json:"mutation_bindings,omitempty"`
	AssessmentBinding           *CapacityBoundAssessmentBinding      `json:"assessment_binding,omitempty"`
	HPAExecutionBinding         *CapacityHPAExecutionBinding         `json:"hpa_execution_binding,omitempty"`
	VMNodeMembershipBinding     *CapacityVMNodeMembershipBinding     `json:"vm_node_membership_binding,omitempty"`
	GuestBootstrapBinding       *CapacityGuestBootstrapBinding       `json:"guest_bootstrap_binding,omitempty"`
	GuestRetirementBinding      *CapacityGuestRetirementBinding      `json:"guest_retirement_binding,omitempty"`
	BusinessCreationBinding     *CapacityBusinessCreationBinding     `json:"business_creation_binding,omitempty"`
	ControllerBinding           *CapacityControllerBinding           `json:"controller_binding,omitempty"`
	ExecutorActivityBinding     *CapacityExecutorActivityBinding     `json:"executor_activity_binding,omitempty"`
	NativeNotifyWindowBinding   *CapacityNativeNotifyWindowBinding   `json:"native_notify_window_binding,omitempty"`
	GuestNotifyReconcileBinding *CapacityGuestNotifyReconcileBinding `json:"guest_notify_reconcile_binding,omitempty"`
}

// This optional source-owned VM collector is separate from the HPA snapshot
// protocol. Adapter identities and range bindings are immutable policy inputs;
// neither a scheduled wake nor a caller supplies a query, sample or proof.
type CapacityGuestNotifyReconcileBinding struct {
	Mode                         string                                `json:"mode"`
	Signals                      []CapacityMetricSignalBinding         `json:"signals"`
	MemberCoverage               *CapacityMetricSignalBinding          `json:"member_coverage,omitempty"`
	AdministrativeCostAssumption *CapacityAdministrativeCostAssumption `json:"administrative_cost_assumption,omitempty"`
}

// Explicit operator planning assumptions, never native price/stock, an invoice
// or a currency conversion. The fixed provider still checks its own originals.
type CapacityAdministrativeCostAssumption struct {
	Mode                  string    `json:"mode"`
	ReviewReference       string    `json:"review_reference"`
	ReviewSHA256          string    `json:"review_sha256"`
	ExpiresAt             time.Time `json:"expires_at"`
	NativeBillingCurrency string    `json:"native_billing_currency"`
}

// Optional lab demand/shutdown prerequisite. It does not lower the capacity floor
// or authorize any provider action. Configuration belongs to the pinned operator policy.
type CapacityExecutorActivityBinding struct {
	Mode                     string `json:"mode"`
	LeaseTTLSeconds          int    `json:"lease_ttl_seconds"`
	IdleAfterSeconds         int    `json:"idle_after_seconds"`
	MaxObservationAgeSeconds int    `json:"max_observation_age_seconds"`
	MaxTasks                 int    `json:"max_tasks"`
}

// This optional operator binding selects fixed product HTTPS transports. It
// neither supplies a caller proof nor permits infrastructure operations. The
// original dispatcher independently reads every selected native lifetime.
type CapacityNativeNotifyWindowBinding struct {
	Mode               string                            `json:"mode"`
	Name               string                            `json:"name"`
	SourceCommit       string                            `json:"source_commit"`
	QuerySHA256        string                            `json:"query_sha256"`
	CoreAuthorityURL   string                            `json:"core_authority_url"`
	Adapter            CapacityObservationAdapterBinding `json:"adapter"`
	NativeNamespace    string                            `json:"native_namespace"`
	NativeBindingName  string                            `json:"native_binding_name"`
	PrivateBindingName string                            `json:"private_binding_name"`
	ControlKeyRef      string                            `json:"control_key_ref"`
	ReadKeyRef         string                            `json:"read_key_ref"`
	ProbeCount         int                               `json:"probe_count"`
	Participants       []CapacityNativeNotifyParticipant `json:"participants"`
	RequiredResources  []CapacityNativeNotifyResource    `json:"required_resources,omitempty"`
}

// These sealed operator expectations never supply a native resource receipt.
// Every selected actor is covered when this optional prerequisite is enabled.
// Unsupported resource producers keep execution on HOLD, before an arm attempt.
type CapacityNativeNotifyResource struct {
	PodName          string `json:"pod_name"`
	Kind             string `json:"kind"`
	ResourceName     string `json:"resource_name"`
	BindingSHA256    string `json:"binding_sha256"`
	Database         string `json:"database"`
	DatabaseOID      string `json:"database_oid"`
	SystemIdentifier string `json:"system_identifier"`
	Role             string `json:"role"`
}

// Name/URI/role are operator declarations only. Pod UID, container and process
// evidence must come from the current original supplier, never this binding.
type CapacityNativeNotifyParticipant struct {
	PodName string `json:"pod_name"`
	Origin  string `json:"origin"`
	Role    string `json:"role"`
}

// One bounded, persistent possible-start witness for the original window.
// Unknown survives generation changes and can never expire into send authority.
// No bearer, payload, native body or private transport credential is persisted.
type CapacityOriginalNotifyWindowMarker struct {
	Schema                    string     `json:"schema"`
	State                     string     `json:"state"`
	WindowID                  string     `json:"window_id"`
	ScopeSHA256               string     `json:"scope_sha256"`
	SourceCommit              string     `json:"source_commit"`
	QuerySHA256               string     `json:"query_sha256"`
	RosterSHA256              string     `json:"roster_sha256"`
	PolicyID                  string     `json:"policy_id"`
	PolicyChecksum            string     `json:"policy_checksum"`
	WorkflowID                string     `json:"workflow_id"`
	WorkflowChecksum          string     `json:"workflow_checksum"`
	DispatchJobID             string     `json:"dispatch_job_id"`
	DispatchFence             int64      `json:"dispatch_fence"`
	IntentGeneration          int64      `json:"intent_generation"`
	IntentFence               int64      `json:"intent_fence"`
	LeaseOwner                string     `json:"lease_owner"`
	ExecutorID                string     `json:"executor_id"`
	Deadline                  time.Time  `json:"deadline"`
	PossibleStartAt           time.Time  `json:"possible_start_at"`
	OriginalReturnsSHA256     string     `json:"original_returns_sha256,omitempty"`
	OriginalReturnsObservedAt *time.Time `json:"original_returns_observed_at,omitempty"`
}

// Optional operator delegation to the existing protected pressure workflow.
// A schedule/alert carries demand only; it cannot select an actor or proof.
type CapacityControllerBinding struct {
	Mode                 string                       `json:"mode"`
	MachinePrincipalID   string                       `json:"machine_principal_id"`
	DispatchLeaseSeconds int                          `json:"dispatch_lease_seconds"`
	DemandSource         *CapacityDemandSourceBinding `json:"demand_source,omitempty"`
}

// One operator-owned sensor workflow may wake the existing executor. Its
// completed event is only demand; no event field supplies execution authority.
type CapacityDemandSourceBinding struct {
	Mode          string `json:"mode"`
	ManifestID    string `json:"manifest_id"`
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	Version       int    `json:"version"`
	Checksum      string `json:"checksum"`
	MaxAgeSeconds int    `json:"max_age_seconds"`
}

// Optional original business reader. Only the operator policy selects its
// origin, secret reference, native identities and expected original input.
// This is a diagnostic read binding, never a mutation/transition permission.
type CapacityBusinessCreationBinding struct {
	Name            string                                    `json:"name"`
	Adapter         CapacityObservationAdapterBinding         `json:"adapter"`
	ReaderURL       string                                    `json:"reader_url"`
	ReadTokenRef    string                                    `json:"read_token_ref"`
	SourceCommit    string                                    `json:"source_commit"`
	QuerySHA256     string                                    `json:"query_sha256"`
	RecordSHA256    string                                    `json:"record_sha256"`
	BodySHA256      string                                    `json:"body_sha256"`
	RecipientSHA256 string                                    `json:"recipient_sha256"`
	RecipientCount  int                                       `json:"recipient_count"`
	Database        string                                    `json:"database"`
	DatabaseOID     string                                    `json:"database_oid"`
	SystemID        string                                    `json:"system_identifier"`
	TableOIDs       []string                                  `json:"table_oids"`
	Pod             AdapterObserveCapacityPodAdmissionRequest `json:"pod"`
}

type CapacityBusinessCreationReply struct {
	Schema            string                            `json:"schema_version"`
	Source            string                            `json:"source_commit"`
	Query             string                            `json:"query_sha256"`
	PreparationBefore NativeProcessAdmissionObservation `json:"preparation_before"`
	NativeRaw         []byte                            `json:"native_snapshot_base64"`
	PreparationAfter  NativeProcessAdmissionObservation `json:"preparation_after"`
}

// Hashes and native identities only; it carries no payload/token/lease owner.
type CapacityBusinessCreationObservation struct {
	RecordSHA256         string    `json:"record_sha256"`
	BodySHA256           string    `json:"body_sha256"`
	NativeSnapshotSHA256 string    `json:"native_snapshot_sha256"`
	NotificationSHA256   string    `json:"notification_sha256"`
	OriginalXID          string    `json:"original_xid"`
	OriginalCommit       time.Time `json:"original_commit"`
	NativeObserved       time.Time `json:"native_observed"`
	ConsumerPodUID       string    `json:"consumer_pod_uid"`
	ConsumerProcessNonce string    `json:"consumer_process_nonce"`
	RecipientSHA256      string    `json:"recipient_sha256"`
	RecipientCount       int       `json:"recipient_count"`
}

// Optional fixed read binding. It grants no provider mutation or phase proof.
type CapacityVMNodeMembershipBinding struct {
	MutationBindingName string                            `json:"mutation_binding_name"`
	Adapter             CapacityObservationAdapterBinding `json:"adapter"`
	Target              CapacityNodeMembershipTarget      `json:"target"`
}

type CapacityNodeMembershipTarget struct {
	BindingName        string                    `json:"binding_name"`
	RealmUID           string                    `json:"realm_uid"`
	Owner              string                    `json:"owner"`
	ProfileName        string                    `json:"profile_name"`
	ProviderIDPrefix   string                    `json:"provider_id_prefix"`
	MaxLeaseAgeSeconds int                       `json:"max_lease_age_seconds"`
	Slots              []CapacityNodeSlotBinding `json:"slots"`
}
type CapacityNodeSlotBinding struct {
	Slot     int    `json:"slot"`
	NodeName string `json:"node_name"`
}
type CapacityNodeMembershipTuple struct {
	Slot                 int       `json:"slot"`
	Name                 string    `json:"name"`
	UID                  string    `json:"uid"`
	ResourceVersion      string    `json:"resource_version"`
	CreatedAt            time.Time `json:"created_at"`
	ProviderID           string    `json:"provider_id"`
	BootID               string    `json:"boot_id"`
	Ready                bool      `json:"ready"`
	ReadyKnown           bool      `json:"ready_known"`
	ReadyChangedAt       time.Time `json:"ready_changed_at"`
	Unschedulable        bool      `json:"unschedulable"`
	LeaseUID             string    `json:"lease_uid"`
	LeaseVersion         string    `json:"lease_version"`
	LeaseHolder          string    `json:"lease_holder"`
	LeaseDurationSeconds int       `json:"lease_duration_seconds"`
	LeaseRenewedAt       time.Time `json:"lease_renewed_at"`
}
type CapacityNodeMembershipResponse struct {
	Operation            string                        `json:"operation"`
	Status               string                        `json:"status"`
	BindingName          string                        `json:"binding_name"`
	BindingSHA256        string                        `json:"binding_sha256"`
	RealmUID             string                        `json:"realm_uid"`
	Owner                string                        `json:"owner"`
	ProfileName          string                        `json:"profile_name"`
	Complete             bool                          `json:"complete"`
	NativeNodeCount      int                           `json:"native_node_count"`
	FirstListVersion     string                        `json:"first_list_version"`
	LastListVersion      string                        `json:"last_list_version"`
	FirstListSHA256      string                        `json:"first_list_sha256"`
	LastListSHA256       string                        `json:"last_list_sha256"`
	ObservationStartedAt time.Time                     `json:"observation_started_at"`
	ObservedAt           time.Time                     `json:"observed_at"`
	Nodes                []CapacityNodeMembershipTuple `json:"nodes"`
	AtomicSnapshot       bool                          `json:"atomic_snapshot"`
	BootstrapCompleted   bool                          `json:"bootstrap_completed_known"`
	WarmResources        bool                          `json:"warm_resources_known"`
	UsefulCapacity       bool                          `json:"useful_capacity_known"`
	RoutingWithdrawn     bool                          `json:"routing_withdrawn_known"`
	BusinessDrain        bool                          `json:"business_drain_known"`
	PhysicalReleased     bool                          `json:"physical_capacity_released"`
	Metadata             map[string]any                `json:"metadata"`
}
type CapacityVMNodeJoin struct {
	Slot              int                         `json:"slot"`
	ResourceID        string                      `json:"resource_id"`
	ResourceCreatedAt string                      `json:"resource_created_at"`
	DesiredSpecSHA256 string                      `json:"desired_spec_sha256"`
	Node              CapacityNodeMembershipTuple `json:"node"`
}

// Optional original Guest read. These are operator catalog/enrollment bindings,
// never workflow input, adapter credentials or transition permissions.
type CapacityGuestBootstrapBinding struct {
	Mode                  string                            `json:"mode"`
	Adapter               CapacityObservationAdapterBinding `json:"adapter"`
	BaseURL               string                            `json:"base_url"`
	ReadTokenRef          string                            `json:"read_token_ref"`
	MaxEvidenceAgeSeconds int                               `json:"max_evidence_age_seconds"`
	EvidenceClass         string                            `json:"evidence_class"`
	Members               []CapacityGuestMemberBinding      `json:"members"`
}

type CapacityGuestNativeTuple struct {
	Provider         string `json:"provider"`
	InstanceID       string `json:"integration_instance_id"`
	InstanceChecksum string `json:"instance_checksum"`
	TypeID           string `json:"integration_type_id"`
	TypeChecksum     string `json:"type_checksum"`
	ScopeChecksum    string `json:"scope_checksum"`
	ProfileChecksum  string `json:"profile_checksum"`
	Profile          string `json:"profile"`
	Slot             int    `json:"slot"`
	ResourceID       string `json:"resource_id"`
	CreatedAt        string `json:"resource_created_at"`
}

// The issuer key and signature are public trust bindings. No bearer or SSH
// private material belongs here. QEMU enrollment certifies only its fixture.
type CapacityGuestEnrollmentStatement struct {
	Schema                     string                   `json:"schema"`
	SourceClass                string                   `json:"source_class"`
	ProvisionerSourceCommit    string                   `json:"provisioner_source_commit"`
	OriginalNativeResultSHA256 string                   `json:"original_native_result_sha256"`
	BindingName                string                   `json:"binding_name"`
	Tuple                      CapacityGuestNativeTuple `json:"tuple"`
	BootID                     string                   `json:"boot_id"`
	HostKeySHA256              string                   `json:"host_key_sha256"`
	CredentialPublicKeySHA256  string                   `json:"credential_public_key_sha256"`
	ForcedReaderCommandSHA256  string                   `json:"forced_reader_command_sha256"`
	UserDataSHA256             string                   `json:"user_data_sha256"`
	PayloadSHA256              string                   `json:"payload_sha256"`
	OwnerBinarySHA256          string                   `json:"owner_binary_sha256"`
	ReaderBinarySHA256         string                   `json:"reader_binary_sha256"`
	GuestSourceCommit          string                   `json:"guest_source_commit"`
	IssuedAt                   time.Time                `json:"issued_at"`
}
type CapacityGuestMemberBinding struct {
	Name                string                           `json:"name"`
	EnrollmentIssuerKey string                           `json:"enrollment_issuer_key"`
	Enrollment          CapacityGuestEnrollmentStatement `json:"enrollment"`
	EnrollmentSignature string                           `json:"enrollment_signature"`
}

// Public Guest wire, locally owned by Core. Importing an adapter's private
// package would couple the provider-neutral control plane to its implementation.
type CapacityGuestUnitObservation struct {
	InvocationID   string `json:"invocation_id"`
	MainPID        int    `json:"main_pid"`
	ExecMainPID    int    `json:"exec_main_pid"`
	ExecMainCode   int    `json:"exec_main_code"`
	ExecMainStatus int    `json:"exec_main_status"`
	StartMonotonic uint64 `json:"start_monotonic_usec"`
	ExitMonotonic  uint64 `json:"exit_monotonic_usec"`
	ActiveState    string `json:"active_state"`
	SubState       string `json:"sub_state"`
	Result         string `json:"result"`
}
type CapacityGuestJournal struct {
	Schema                 string                       `json:"schema"`
	AdmissionProtocol      string                       `json:"admission_protocol"`
	InvocationNonce        string                       `json:"invocation_nonce"`
	State                  string                       `json:"state"`
	BootID                 string                       `json:"boot_id"`
	Tuple                  CapacityGuestNativeTuple     `json:"tuple"`
	UserDataSHA256         string                       `json:"user_data_sha256"`
	PayloadSHA256          string                       `json:"payload_sha256"`
	OwnerSourceCommit      string                       `json:"owner_source_commit"`
	OwnerBinarySHA256      string                       `json:"owner_binary_sha256"`
	OwnerPID               int                          `json:"owner_pid"`
	OwnerStartTicks        uint64                       `json:"owner_start_ticks"`
	ParentAncestry         []int                        `json:"parent_ancestry"`
	UnitAtAdmission        CapacityGuestUnitObservation `json:"unit_at_admission"`
	PossibleStartAt        time.Time                    `json:"possible_start_at"`
	ChildPID               int                          `json:"child_pid"`
	ChildStartTicks        uint64                       `json:"child_start_ticks"`
	StartedAt              *time.Time                   `json:"started_at,omitempty"`
	OriginalWaitReturnedAt *time.Time                   `json:"original_wait_returned_at,omitempty"`
	ExitCode               *int                         `json:"exit_code,omitempty"`
	Signal                 string                       `json:"signal"`
	OriginalContextFailed  bool                         `json:"original_context_failed"`
	FinalRecordPreparedAt  *time.Time                   `json:"final_record_prepared_at,omitempty"`
}
type CapacityGuestObservation struct {
	Schema                 string                       `json:"schema"`
	ReaderSourceCommit     string                       `json:"reader_source_commit"`
	ReaderBinarySHA256     string                       `json:"reader_binary_sha256"`
	ReaderPID              int                          `json:"reader_pid"`
	ReaderStartTicks       uint64                       `json:"reader_start_ticks"`
	BootID                 string                       `json:"boot_id"`
	UserDataSHA256         string                       `json:"user_data_sha256"`
	Journal                CapacityGuestJournal         `json:"journal"`
	JournalSHA256          string                       `json:"journal_sha256"`
	Unit                   CapacityGuestUnitObservation `json:"unit"`
	CloudInitStatus        string                       `json:"cloud_init_status"`
	CloudInitFinalFinished float64                      `json:"cloud_init_final_finished"`
	CloudInitHasErrors     bool                         `json:"cloud_init_has_errors"`
	ObservedAt             time.Time                    `json:"observed_at"`
}
type CapacityGuestBootstrapResult struct {
	BindingName                     string                   `json:"binding_name"`
	EnrollmentSourceClass           string                   `json:"enrollment_source_class"`
	Observation                     CapacityGuestObservation `json:"observation"`
	OriginalPayloadReturnObserved   bool                     `json:"original_payload_return_observed"`
	BootstrapCompletedKnown         bool                     `json:"bootstrap_completed_known"`
	ProviderMutationQuiescenceKnown bool                     `json:"provider_mutation_quiescence_known"`
	WarmResourcesKnown              bool                     `json:"warm_resources_known"`
	UsefulCapacityKnown             bool                     `json:"useful_capacity_known"`
	RoutingWithdrawnKnown           bool                     `json:"routing_withdrawn_known"`
	BusinessDrainKnown              bool                     `json:"business_drain_known"`
	PhysicalCapacityReleased        bool                     `json:"physical_capacity_released"`
}
type CapacityGuestBootstrapJoin struct {
	Slot                      int       `json:"slot"`
	ResourceID                string    `json:"resource_id"`
	ResourceCreatedAt         string    `json:"resource_created_at"`
	BootID                    string    `json:"boot_id"`
	InvocationNonce           string    `json:"invocation_nonce"`
	JournalSHA256             string    `json:"journal_sha256"`
	ObservedAt                time.Time `json:"observed_at"`
	EnclosingBootstrapRead    bool      `json:"enclosing_bootstrap_read"`
	OriginalCallerReturnKnown bool      `json:"original_caller_return_known"`
	PhysicalCertificate       bool      `json:"physical_certificate"`
	EvidenceClass             string    `json:"evidence_class"`
}

type CapacitySignalRule struct {
	Name           string  `json:"name"`
	SourceIdentity string  `json:"source_identity"`
	Unit           string  `json:"unit"`
	UpAbove        float64 `json:"up_above"`
	DownBelow      float64 `json:"down_below"`
}

type CapacityProfile struct {
	Name                 string    `json:"name"`
	Provider             string    `json:"provider"`
	Region               string    `json:"region"`
	MinUnits             int       `json:"min_units"`
	MaxUnits             int       `json:"max_units"`
	UnitMonthlyCostMinor int64     `json:"unit_monthly_cost_minor"`
	QuoteValidUntil      time.Time `json:"quote_valid_until"`
	ValidationValidUntil time.Time `json:"validation_valid_until"`
	ValidationRef        string    `json:"validation_ref"`
	ReadinessSeconds     int       `json:"readiness_seconds"`
}

// CapacityEvidence must carry source sample time independently of adapter/query time.
// A PromQL instant-vector value-pair timestamp is not a scrape timestamp.
type CapacityEvidence struct {
	Name             string    `json:"name"`
	SourceIdentity   string    `json:"source_identity"`
	Unit             string    `json:"unit"`
	RequireData      bool      `json:"require_data"`
	Matched          bool      `json:"matched"`
	DataState        string    `json:"data_state"`
	Value            *float64  `json:"value"`
	RangeMin         *float64  `json:"range_min"`
	RangeMax         *float64  `json:"range_max"`
	SourceSampledAt  time.Time `json:"source_sampled_at"`
	WindowStart      time.Time `json:"window_start"`
	WindowEnd        time.Time `json:"window_end"`
	Samples          int       `json:"samples"`
	CoverageComplete bool      `json:"coverage_complete"`
	MaxGapSeconds    int       `json:"max_gap_seconds"`
}

type CapacitySnapshot struct {
	TargetIdentity          string    `json:"target_identity"`
	ResourceUID             string    `json:"resource_uid"`
	WorkloadUID             string    `json:"workload_uid"`
	WorkloadResourceVersion string    `json:"workload_resource_version"`
	ResourceVersion         string    `json:"resource_version"`
	Owner                   string    `json:"owner"`
	Profile                 string    `json:"profile"`
	Units                   int       `json:"units"`
	ObservedAt              time.Time `json:"observed_at"`
}

type CapacityAssessment struct {
	Snapshot CapacitySnapshot   `json:"snapshot"`
	Evidence []CapacityEvidence `json:"evidence"`
}

type CapacityClockState struct {
	PolicyFingerprint       string    `json:"policy_fingerprint"`
	ResourceUID             string    `json:"resource_uid"`
	WorkloadUID             string    `json:"workload_uid"`
	WorkloadResourceVersion string    `json:"workload_resource_version"`
	Profile                 string    `json:"profile"`
	LastObservedAt          time.Time `json:"last_observed_at"`
	LastActionAt            time.Time `json:"last_action_at"`
	UpSince                 time.Time `json:"up_since"`
	DownSince               time.Time `json:"down_since"`
}

type CapacityDecision struct {
	Action             string             `json:"action"`
	Reason             string             `json:"reason"`
	Profile            string             `json:"profile"`
	Units              int                `json:"units"`
	Floor              int                `json:"floor"`
	ExecutionPermitted bool               `json:"execution_permitted"`
	Clock              CapacityClockState `json:"clock"`
}

// CapacityIntent is one durable generation per logical domain/dimension.
type CapacityIntent struct {
	Namespace            string                              `json:"namespace"`
	PolicyName           string                              `json:"policy_name"`
	PolicyID             uuid.UUID                           `json:"policy_id"`
	PolicyChecksum       string                              `json:"policy_checksum"`
	Environment          string                              `json:"environment"`
	Domain               string                              `json:"domain"`
	Dimension            string                              `json:"dimension"`
	Generation           int64                               `json:"generation"`
	FencingToken         int64                               `json:"fencing_token"`
	Phase                string                              `json:"phase"`
	LeaseOwner           string                              `json:"lease_owner,omitempty"`
	LeaseExecutorID      string                              `json:"lease_executor_id,omitempty"`
	LeaseExpiresAt       *time.Time                          `json:"lease_expires_at,omitempty"`
	RecoveryOnly         bool                                `json:"recovery_only"`
	FloorDegraded        bool                                `json:"floor_degraded,omitempty"`
	NativeHPAGeneration  int64                               `json:"native_hpa_generation"`
	NativePodBaseline    []string                            `json:"native_pod_baseline"`
	BaselineSnapshot     CapacitySnapshot                    `json:"baseline_snapshot"`
	Decision             CapacityDecision                    `json:"decision"`
	Assessment           CapacityAssessment                  `json:"assessment"`
	UpdatedAt            time.Time                           `json:"updated_at"`
	OriginalNotifyWindow *CapacityOriginalNotifyWindowMarker `json:"original_notify_window,omitempty"`
}

// CapacityTransitionProof is a receipt assembled by the policy's protected
// workflow from provider observations. Core does not generate these receipts
// or infer readiness, canary health, or a completed drain from replica counts.
type CapacityTransitionProof struct {
	Assessment CapacityAssessment `json:"assessment"`
	ObservedAt time.Time          `json:"observed_at"`
	ReceiptRef string             `json:"receipt_ref"`
	Healthy    bool               `json:"healthy"`
	Inflight   *int               `json:"inflight"`
	// Recovery proof is distinct from business inflight work. Its assertions
	// must come from the fixed workflow's provider fencing/quiescence receipt.
	MutationInflight     *int  `json:"mutation_inflight,omitempty"`
	ProviderFencingToken int64 `json:"provider_fencing_token,omitempty"`
	NoMutationVerified   bool  `json:"no_mutation_verified,omitempty"`
	// core_mutation_grants names Core's durable at-most-one-send ledger;
	// it must not be represented as a native provider CAS/fencing token.
	MutationAuthorityKind string `json:"mutation_authority_kind,omitempty"`
	// Partial recovery also requires a complete native inventory. The store
	// independently matches its freshly reread immutable membership ledger.
	MembershipComplete    bool `json:"membership_complete,omitempty"`
	AdmissionClosed       bool `json:"admission_closed,omitempty"`
	RoutingWithdrawn      bool `json:"routing_withdrawn,omitempty"`
	NativeActionsInflight *int `json:"native_actions_inflight,omitempty"`
}
