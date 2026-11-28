// Source-owned member/placement wire. SDKs mirror JSON locally; they never import Core.
package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// These aliases freeze the existing d1b9 JSON shapes unchanged.

const (
	CapacityNativeWorkerMemberContextSchema             = "native_worker_member_context_v1"
	CapacityNativeWorkerMemberReadSchema                = "native_worker_member_read_v1"
	CapacityNativeWorkerMemberPermitSchema              = "native_worker_member_permit_v1"
	CapacityNativeWorkerMemberReceiveSchema             = "native_worker_member_receive_v1"
	CapacityNativeWorkerMemberReadOriginalSchema        = "native_worker_member_read_original_v1"
	CapacityNativeWorkerMemberObservationSchema         = "native_worker_member_observation_v1"
	CapacityNativeWorkerKubeConfigurationSchema         = "native_worker_kubelet_configuration_v1"
	CapacityNativeWorkerPlacementBootstrapSchema        = "native_worker_placement_bootstrap_v1"
	CapacityNativeWorkerAllocatorFenceContextSchema     = "native_worker_allocator_fence_context_v1"
	CapacityNativeWorkerAllocatorFenceReadSchema        = "native_worker_allocator_fence_read_v1"
	CapacityNativeWorkerAllocatorFenceObservationSchema = "native_worker_allocator_fence_observation_v1"
	CapacityNativeWorkerMemberCallbackBase              = "/internal/capacity/native-workers/member-permits/"
	CapacityNativeWorkerPlacementBootstrapPath          = "/native-worker/placement-bootstrap"
	CapacityNativeWorkerMemberMaxContextBytes           = 64 << 10
	CapacityNativeWorkerMemberMaxOriginalBytes          = 1 << 20
	CapacityNativeWorkerMemberMaxReceiveBytes           = 2 << 20
	CapacityNativeWorkerMemberMaxObservationBytes       = 2 << 20
	CapacityNativeWorkerMemberMaxGuestBytes             = 64 << 10
	CapacityNativeWorkerMemberMaxSelectorBytes          = 2 << 10
	CapacityNativeWorkerMemberMaxPrivateRecordBytes     = 8 << 20
	CapacityNativeWorkerMemberMaxPods                   = 256
	CapacityNativeWorkerMemberMaxPages                  = 128
	CapacityNativeWorkerMemberMaxPermitSeconds          = 30
	CapacityNativeWorkerMemberMaxGuestAgeSeconds        = 30
)

// Every SDK capability input and read/redeem/reconcile HTTP request has ONLY these keys.
type CapacityNativeWorkerMemberSelectors struct {
	BindingName string `json:"binding_name"`
	PermitID    string `json:"permit_id"`
}
type CapacityNativeWorkerMemberEndpoint struct {
	Adapter      CapacityMarketAdapterBinding `json:"adapter"`
	BindingName  string                       `json:"binding_name"`
	SourceCommit string                       `json:"source_commit"`
	ScopeSHA256  string                       `json:"scope_sha256"`
	Capability   string                       `json:"capability"`
}
type CapacityNativeWorkerMemberNode struct {
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	ProviderID      string `json:"provider_id"`
}
type CapacityNativeWorkerMemberPod struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
}
type CapacityNativeWorkerMemberContext struct {
	Schema                        string                             `json:"schema"`
	PlanID                        string                             `json:"plan_id"`
	PermitID                      string                             `json:"permit_id"`
	AttemptID                     string                             `json:"attempt_id"`
	CoreSourceCommit              string                             `json:"core_source_commit"`
	Mode                          string                             `json:"mode"`
	Action                        string                             `json:"action"`
	Actor                         CapacityNativeWorkerMemberEndpoint `json:"actor"`
	Observer                      CapacityNativeWorkerMemberEndpoint `json:"observer"`
	PolicyID                      string                             `json:"policy_id"`
	PolicyChecksum                string                             `json:"policy_checksum"`
	IntentGeneration              int64                              `json:"intent_generation"`
	FencingToken                  int64                              `json:"fencing_token"`
	RealmNamespace                string                             `json:"realm_namespace"`
	RealmUID                      string                             `json:"realm_uid"`
	PoolUID                       string                             `json:"pool_uid"`
	Owner                         string                             `json:"owner"`
	Epoch                         int64                              `json:"epoch"`
	Profile                       string                             `json:"profile"`
	BirthSHA256                   string                             `json:"birth_sha256"`
	Physical                      CapacityNativeWorkerPhysical       `json:"physical"`
	OverlayIPv4                   string                             `json:"overlay_ipv4"`
	Node                          *CapacityNativeWorkerMemberNode    `json:"node"`
	Pod                           *CapacityNativeWorkerMemberPod     `json:"pod"`
	Registry                      CapacityNativePoolRegistryRef      `json:"registry"`
	RegistryResourceVersion       string                             `json:"registry_resource_version"`
	RegistrySHA256                string                             `json:"registry_sha256"`
	PlacementFenceSHA256          string                             `json:"placement_fence_sha256"`
	BootstrapPolicySHA256         string                             `json:"bootstrap_policy_sha256"`
	AdmissionReceiptSHA256        string                             `json:"admission_receipt_sha256"`
	DrainEvidenceSHA256           string                             `json:"drain_evidence_sha256"`
	UsefulCapacityEvidenceSHA256  string                             `json:"useful_capacity_evidence_sha256"`
	PhysicalAbsenceEvidenceSHA256 string                             `json:"physical_absence_evidence_sha256"`
	NodeAbsenceEvidenceSHA256     string                             `json:"node_absence_evidence_sha256"`
	NotAfter                      time.Time                          `json:"not_after"`
}

// Read is a closed non-authorizing projection. Reader always sees Redeemable=false.
type CapacityNativeWorkerMemberRead struct {
	ReadID            string                            `json:"read_id"`
	Schema            string                            `json:"schema"`
	BindingName       string                            `json:"binding_name"`
	Context           CapacityNativeWorkerMemberContext `json:"context"`
	State             string                            `json:"state"`
	Redeemable        bool                              `json:"redeemable"`
	MutationPermitted bool                              `json:"mutation_permitted"`
}

// Only original successful Redeem returns this explicitly private representation.
type capacityNativeWorkerMemberPermitWire struct {
	Schema            string                            `json:"schema"`
	Context           CapacityNativeWorkerMemberContext `json:"context"`
	State             string                            `json:"state"`
	MutationPermitted bool                              `json:"mutation_permitted"`
	SettlementToken   string                            `json:"settlement_token"`
}
type CapacityNativeWorkerMemberReceive struct {
	Schema             string    `json:"schema"`
	BindingName        string    `json:"binding_name"`
	PermitID           string    `json:"permit_id"`
	SettlementToken    string    `json:"settlement_token"`
	HTTPStatus         int       `json:"http_status"`
	RequestID          string    `json:"request_id"`
	OriginalReturn     []byte    `json:"original_return"`
	CaptureComplete    bool      `json:"capture_complete"`
	TransportCompleted bool      `json:"transport_completed"`
	CompletedAt        time.Time `json:"completed_at"`
	ErrorClass         string    `json:"error_class"`
}

// Read-only evidence custody: never a writer token or a mutation grant.
type CapacityNativeWorkerMemberReadOriginal struct {
	Schema             string    `json:"schema"`
	BindingName        string    `json:"binding_name"`
	PermitID           string    `json:"permit_id"`
	ReadID             string    `json:"read_id"`
	Kind               string    `json:"kind"`
	HTTPStatus         int       `json:"http_status"`
	OriginalReturn     []byte    `json:"original_return"`
	CaptureComplete    bool      `json:"capture_complete"`
	TransportCompleted bool      `json:"transport_completed"`
	CompletedAt        time.Time `json:"completed_at"`
	ErrorClass         string    `json:"error_class"`
}
type CapacityNativeWorkerMemberController struct {
	APIVersion         string `json:"api_version"`
	Kind               string `json:"kind"`
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	ResourceVersion    string `json:"resource_version"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observed_generation"`
}
type CapacityNativeWorkerMemberPDB struct {
	Namespace          string               `json:"namespace"`
	Name               string               `json:"name"`
	UID                string               `json:"uid"`
	ResourceVersion    string               `json:"resource_version"`
	Generation         int64                `json:"generation"`
	ObservedGeneration int64                `json:"observed_generation"`
	DisruptionsAllowed int32                `json:"disruptions_allowed"`
	DisruptedPods      map[string]time.Time `json:"disrupted_pods"`
}
type CapacityNativeWorkerMemberPodFact struct {
	Identity                 CapacityNativeWorkerMemberPod          `json:"identity"`
	NodeName                 string                                 `json:"node_name"`
	Phase                    string                                 `json:"phase"`
	Deleting                 bool                                   `json:"deleting"`
	TerminationGraceSeconds  int64                                  `json:"termination_grace_seconds"`
	Finalizers               []string                               `json:"finalizers"`
	Controllers              []CapacityNativeWorkerMemberController `json:"controllers"`
	PDBs                     []CapacityNativeWorkerMemberPDB        `json:"pdbs"`
	ContractID               string                                 `json:"contract_id"`
	ContractMatched          bool                                   `json:"contract_matched"`
	Mirror                   bool                                   `json:"mirror"`
	StorageKinds             []string                               `json:"storage_kinds"`
	VolumeAttachmentsPresent bool                                   `json:"volume_attachments_present"`
}
type CapacityNativeWorkerKubeConfigurationObservation struct {
	Schema               string    `json:"schema"`
	NodeName             string    `json:"node_name"`
	NodeUID              string    `json:"node_uid"`
	NodeResourceVersion  string    `json:"node_resource_version"`
	KubeletVersion       string    `json:"kubelet_version"`
	EndpointIPv4         string    `json:"endpoint_ipv4"`
	ServerLeafSHA256     string    `json:"server_leaf_sha256"`
	ObservedAt           time.Time `json:"observed_at"`
	HTTPStatus           int       `json:"http_status"`
	ConfigurationPresent bool      `json:"configuration_present"`
	StaticPodPath        string    `json:"static_pod_path"`
	StaticPodURL         string    `json:"static_pod_url"`
	ReadComplete         bool      `json:"read_complete"`
	PrivateOriginalRef   string    `json:"private_original_ref"`
}
type CapacityNativeWorkerMemberObservation struct {
	Schema                  string                                            `json:"schema"`
	BindingName             string                                            `json:"binding_name"`
	PermitID                string                                            `json:"permit_id"`
	SourceCommit            string                                            `json:"source_commit"`
	ScopeSHA256             string                                            `json:"scope_sha256"`
	Adapter                 CapacityMarketAdapterBinding                      `json:"adapter"`
	ContextSHA256           string                                            `json:"context_sha256"`
	ReadID                  string                                            `json:"read_id"`
	ObservedAt              time.Time                                         `json:"observed_at"`
	PodRosterSHA256         string                                            `json:"pod_roster_sha256"`
	Inventory               CapacityNativeWorkerAbortInventoryObservation     `json:"inventory"`
	Configuration           *CapacityNativeWorkerKubeConfigurationObservation `json:"configuration"`
	Pods                    []CapacityNativeWorkerMemberPodFact               `json:"pods"`
	ControllerReadsComplete bool                                              `json:"controller_reads_complete"`
	PDBReadsComplete        bool                                              `json:"pdb_reads_complete"`
	StorageReadsComplete    bool                                              `json:"storage_reads_complete"`
	Complete                bool                                              `json:"complete"`
	MutationAuthorized      bool                                              `json:"mutation_authorized"`
	SubjectPod              *CapacityNativeWorkerMemberPodFact                `json:"subject_pod"`
}

// Separate guest GET0 DTO: no NetworkWitness wire extension and no pre-create fact.
type CapacityNativeWorkerPlacementBootstrapObservation struct {
	Schema                string    `json:"schema"`
	SourceCommit          string    `json:"source_commit"`
	AttemptID             string    `json:"attempt_id"`
	LaunchSHA256          string    `json:"launch_sha256"`
	ProviderID            string    `json:"provider_id"`
	NodeName              string    `json:"node_name"`
	ObservedAt            time.Time `json:"observed_at"`
	AgentPID              int       `json:"agent_pid"`
	AgentStartTicks       uint64    `json:"agent_start_ticks"`
	ActualAgentArgv       []string  `json:"actual_agent_argv"`
	AgentConfigPath       string    `json:"agent_config_path"`
	ConfiguredKubeletArgs []string  `json:"configured_kubelet_args"`
	ConfiguredNodeIPv4    string    `json:"configured_node_ipv4"`
	AgentConfigComplete   bool      `json:"agent_config_complete"`
}

// Pre-create context is separate: no fake NodeUID, birth, Physical or mutation actor.
type CapacityNativeWorkerAllocatorFenceContext struct {
	Schema                string                             `json:"schema"`
	CreatorPermitID       string                             `json:"creator_permit_id"`
	AttemptID             string                             `json:"attempt_id"`
	CoreSourceCommit      string                             `json:"core_source_commit"`
	Observer              CapacityNativeWorkerMemberEndpoint `json:"observer"`
	PolicyID              string                             `json:"policy_id"`
	PolicyChecksum        string                             `json:"policy_checksum"`
	IntentGeneration      int64                              `json:"intent_generation"`
	FencingToken          int64                              `json:"fencing_token"`
	RealmUID              string                             `json:"realm_uid"`
	PoolUID               string                             `json:"pool_uid"`
	Owner                 string                             `json:"owner"`
	Epoch                 int64                              `json:"epoch"`
	BootstrapPolicySHA256 string                             `json:"bootstrap_policy_sha256"`
	NotAfter              time.Time                          `json:"not_after"`
}
type CapacityNativeWorkerAllocatorFenceRead struct {
	Schema      string                                    `json:"schema"`
	BindingName string                                    `json:"binding_name"`
	Context     CapacityNativeWorkerAllocatorFenceContext `json:"context"`
}
type CapacityNativeWorkerFenceObject struct {
	APIVersion          string `json:"api_version"`
	Kind                string `json:"kind"`
	Namespace           string `json:"namespace"`
	Name                string `json:"name"`
	UID                 string `json:"uid"`
	ResourceVersion     string `json:"resource_version"`
	Generation          int64  `json:"generation"`
	PublicContentSHA256 string `json:"public_content_sha256"`
}
type CapacityNativeWorkerFenceEnforcement struct {
	APIServerID              string    `json:"api_server_id"`
	PolicyUID                string    `json:"policy_uid"`
	ParameterUID             string    `json:"parameter_uid"`
	ParameterResourceVersion string    `json:"parameter_resource_version"`
	Operation                string    `json:"operation"`
	SubjectName              string    `json:"subject_name"`
	Principal                string    `json:"principal"`
	ObservedAt               time.Time `json:"observed_at"`
	HTTPStatus               int       `json:"http_status"`
	Reason                   string    `json:"reason"`
}
type CapacityNativeWorkerLegacyController struct {
	Identity               CapacityNativeWorkerMemberController `json:"identity"`
	DesiredReplicas        int32                                `json:"desired_replicas"`
	ReadyReplicas          int32                                `json:"ready_replicas"`
	LivePodUIDs            []string                             `json:"live_pod_uids"`
	ExposedCallsUnresolved int32                                `json:"exposed_calls_unresolved"`
}
type CapacityNativeWorkerAllocatorFenceObservation struct {
	Schema                    string                                 `json:"schema"`
	BindingName               string                                 `json:"binding_name"`
	CreatorPermitID           string                                 `json:"creator_permit_id"`
	SourceCommit              string                                 `json:"source_commit"`
	ScopeSHA256               string                                 `json:"scope_sha256"`
	Adapter                   CapacityMarketAdapterBinding           `json:"adapter"`
	ContextSHA256             string                                 `json:"context_sha256"`
	ObservedAt                time.Time                              `json:"observed_at"`
	Objects                   []CapacityNativeWorkerFenceObject      `json:"objects"`
	Enforcement               []CapacityNativeWorkerFenceEnforcement `json:"enforcement"`
	LegacyControllers         []CapacityNativeWorkerLegacyController `json:"legacy_controllers"`
	ProducerInventoryComplete bool                                   `json:"producer_inventory_complete"`
	Complete                  bool                                   `json:"complete"`
	MutationAuthorized        bool                                   `json:"mutation_authorized"`
}

// The optional lifecycle declaration cannot install a client, signer or writer.
// Nil preserves old policy JSON; production composition remains separately off.
type CapacityNativeWorkerMemberBinding struct {
	Mode                  string                                   `json:"mode"`
	Name                  string                                   `json:"name"`
	Writer                CapacityNativeWorkerProbeResourceBinding `json:"writer"`
	Reader                CapacityNativeWorkerProbeResourceBinding `json:"reader"`
	AllocatorFenceReader  CapacityNativeWorkerProbeResourceBinding `json:"allocator_fence_reader"`
	BootstrapPolicySHA256 string                                   `json:"bootstrap_policy_sha256"`
	MaxPermitSeconds      int                                      `json:"max_permit_seconds"`
	MaxReadAgeSeconds     int                                      `json:"max_read_age_seconds"`
}

// Copies share a private wire but never expose it through ordinary formatting/JSON.
type CapacityNativeWorkerMemberPermit struct {
	wire *capacityNativeWorkerMemberPermitWire
}

func (CapacityNativeWorkerMemberPermit) String() string     { return "[private Native member permit]" }
func (v CapacityNativeWorkerMemberPermit) GoString() string { return v.String() }
func (CapacityNativeWorkerMemberPermit) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("private Native member permit serialization refused")
}
func NewCapacityNativeWorkerMemberPermit(c CapacityNativeWorkerMemberContext, token string) (CapacityNativeWorkerMemberPermit, error) {
	rawToken, tokenErr := base64.RawURLEncoding.DecodeString(token)
	defer clear(rawToken)
	if c.Schema != CapacityNativeWorkerMemberContextSchema || c.PermitID == "" || len(token) != 43 || tokenErr != nil || len(rawToken) != 32 || base64.RawURLEncoding.EncodeToString(rawToken) != token {
		return CapacityNativeWorkerMemberPermit{}, fmt.Errorf("private Native member permit unavailable")
	}
	raw, e := json.Marshal(c)
	var own CapacityNativeWorkerMemberContext
	if e != nil || json.Unmarshal(raw, &own) != nil {
		return CapacityNativeWorkerMemberPermit{}, fmt.Errorf("private Native member permit unavailable")
	}
	return CapacityNativeWorkerMemberPermit{wire: &capacityNativeWorkerMemberPermitWire{Schema: CapacityNativeWorkerMemberPermitSchema, Context: own, State: "redeemed", MutationPermitted: true, SettlementToken: token}}, nil
}
func (v CapacityNativeWorkerMemberPermit) WritePrivateJSON(w io.Writer) error {
	if v.wire == nil || w == nil {
		return fmt.Errorf("private Native member permit unavailable")
	}
	return json.NewEncoder(w).Encode(v.wire)
}

// Safe response binding for the protected listener; never returns the token.
// Clone nested subject pointers so a caller cannot change the private wire.
func (v CapacityNativeWorkerMemberPermit) PublicContext() (CapacityNativeWorkerMemberContext, error) {
	if v.wire == nil {
		return CapacityNativeWorkerMemberContext{}, fmt.Errorf("private Native member permit unavailable")
	}
	raw, err := json.Marshal(v.wire.Context)
	var c CapacityNativeWorkerMemberContext
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return c, fmt.Errorf("private Native member permit unavailable")
	}
	return c, nil
}
func (CapacityNativeWorkerMemberReceive) String() string     { return "[private Native member original]" }
func (v CapacityNativeWorkerMemberReceive) GoString() string { return v.String() }
func (CapacityNativeWorkerMemberReceive) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("private Native member original serialization refused")
}
func (v CapacityNativeWorkerMemberReceive) PrivateJSON() ([]byte, error) {
	type wire CapacityNativeWorkerMemberReceive
	return json.Marshal(wire(v))
}
func (CapacityNativeWorkerMemberReadOriginal) String() string {
	return "[private Native member read original]"
}
func (v CapacityNativeWorkerMemberReadOriginal) GoString() string { return v.String() }
func (CapacityNativeWorkerMemberReadOriginal) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("private Native member read serialization refused")
}
func (v CapacityNativeWorkerMemberReadOriginal) PrivateJSON() ([]byte, error) {
	type wire CapacityNativeWorkerMemberReadOriginal
	return json.Marshal(wire(v))
}
