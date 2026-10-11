package model

// The provider-neutral closed VM-slot observation protocol accompanies
// capacity_vm_slot_v1. Fields carry native facts, not traffic qualification.
// Transport/type/instance revisions remain checked by the protected dispatcher.
type CapacityVMNativeTuple struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}

type CapacityVMFleetPlan struct {
	DesiredSpec                  CapacityMutationSpecV1           `json:"desired_spec"`
	RequestSHA256                string                           `json:"request_sha256"`
	Protected                    bool                             `json:"protected"`
	Quote                        *CapacityVMFleetQuote            `json:"quote,omitempty"`
	Server                       *CapacityVMServerObservation     `json:"server,omitempty"`
	AuxiliaryResources           []CapacityVMAuxiliaryObservation `json:"auxiliary_resources,omitempty"`
	ObservedAt                   string                           `json:"observed_at"`
	CompensationOf               string                           `json:"compensation_of,omitempty"`
	CompensationIdentityVerified bool                             `json:"compensation_identity_verified"`
	ProviderFencingEvidence      bool                             `json:"provider_fencing_evidence"`
	WarmReadinessEvidence        bool                             `json:"warm_readiness_evidence"`
	BusinessReadyEvidence        bool                             `json:"business_ready_evidence"`
}

// Inventory is a complete bounded read of one configured profile, supplemented
// by exact configured-name collision checks. It is never an atomic snapshot or
// useful capacity certificate. All native states count as members.
type CapacityVMFleetInventory struct {
	IntegrationInstanceID   string                             `json:"integration_instance_id"`
	ScopeChecksum           string                             `json:"scope_checksum"`
	ProfileChecksum         string                             `json:"profile_checksum"`
	AdmissionChecksum       string                             `json:"admission_checksum"`
	ProfileName             string                             `json:"profile_name"`
	ProtectedSlots          int                                `json:"protected_slots"`
	MaxSlots                int                                `json:"max_slots"`
	Members                 []CapacityVMFleetInventoryMember   `json:"members"`
	MissingSlots            []int                              `json:"missing_slots"`
	Complete                bool                               `json:"complete"`
	ObservationStartedAt    string                             `json:"observation_started_at"`
	ObservedAt              string                             `json:"observed_at"`
	AtomicProviderSnapshot  bool                               `json:"atomic_provider_snapshot"`
	ProviderFencingEvidence bool                               `json:"provider_fencing_evidence"`
	WarmReadinessEvidence   bool                               `json:"warm_readiness_evidence"`
	BusinessReadyEvidence   bool                               `json:"business_ready_evidence"`
	FailedCreation          *CapacityVMFailedCreationCandidate `json:"failed_creation,omitempty"`
}

type CapacityVMFleetInventoryMember struct {
	Slot          int                         `json:"slot"`
	Protected     bool                        `json:"protected"`
	DesiredSpec   CapacityMutationSpecV1      `json:"desired_spec"`
	RequestSHA256 string                      `json:"request_sha256"`
	Server        CapacityVMServerObservation `json:"server"`
	Unresolved    bool                        `json:"unresolved"`
}

type CapacityVMFailedCreationCandidate struct {
	Plan                  CapacityVMFleetPlan        `json:"plan"`
	ParentGrantID         string                     `json:"parent_grant_id"`
	Actions               CapacityVMActionCollection `json:"actions"`
	ActionHistoryComplete bool                       `json:"action_history_complete"`
	ActionsTerminal       bool                       `json:"actions_terminal"`
	ActionsFailed         bool                       `json:"actions_failed"`
	NativeActionsInflight int                        `json:"native_actions_inflight"`
}

type CapacityVMAuxiliaryObservation struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	Absent     bool   `json:"absent"`
	ObservedAt string `json:"observed_at"`
}

type CapacityVMActionCollection struct {
	ResourceID        string                        `json:"resource_id"`
	ResourceCreatedAt string                        `json:"resource_created_at"`
	CreationGrantID   string                        `json:"creation_grant_id,omitempty"`
	Actions           []CapacityVMActionObservation `json:"actions"`
	Complete          bool                          `json:"complete"`
	ObservedAt        string                        `json:"observed_at"`
}

type CapacityVMFleetQuote struct {
	Currency            string   `json:"currency"`
	GrossHourlyMicros   int64    `json:"gross_hourly_micros"`
	GrossMonthlyMicros  int64    `json:"gross_monthly_micros"`
	Location            string   `json:"location"`
	ServerTypeID        string   `json:"server_type_id"`
	Available           bool     `json:"available"`
	IncludesPrimaryIPv4 bool     `json:"includes_primary_ipv4"`
	ObservedAt          string   `json:"observed_at"`
	ValidUntil          string   `json:"valid_until"`
	StockReserved       bool     `json:"stock_reserved"`
	AdditionalCosts     []string `json:"additional_costs"`
}

type CapacityVMServerObservation struct {
	CapacityVMNativeTuple
	Name                         string            `json:"name"`
	Status                       string            `json:"status"`
	Locked                       bool              `json:"locked"`
	ProtectedFromDelete          bool              `json:"protected_from_delete"`
	Location                     string            `json:"location"`
	NetworkZone                  string            `json:"network_zone"`
	TypeID                       string            `json:"type_id"`
	TypeName                     string            `json:"type_name"`
	ImageID                      string            `json:"image_id"`
	Labels                       map[string]string `json:"labels"`
	PrimaryIPv4ID                string            `json:"primary_ipv4_id,omitempty"`
	PrimaryIPv6ID                string            `json:"primary_ipv6_id,omitempty"`
	IndependentBillableResources bool              `json:"independent_billable_resources"`
	AuxiliaryInventoryComplete   bool              `json:"auxiliary_inventory_complete"`
	PhysicalSpecVerified         bool              `json:"physical_spec_verified"`
	CompensationIdentityVerified bool              `json:"compensation_identity_verified"`
	ObservedAt                   string            `json:"observed_at"`
}

type CapacityVMActionObservation struct {
	ID                      string `json:"id"`
	Status                  string `json:"status"`
	Command                 string `json:"command"`
	ResourceID              string `json:"resource_id"`
	StartedAt               string `json:"started_at"`
	FinishedAt              string `json:"finished_at,omitempty"`
	ErrorCode               string `json:"error_code,omitempty"`
	ObservedAt              string `json:"observed_at"`
	ProviderFencingEvidence bool   `json:"provider_fencing_evidence"`
}

// CapacityVMObservationInput cannot contain caller evidence, alternate adapter
// selectors/capabilities or warm/drain booleans. Lease fields are accepted only
// by operations that persist facts through the existing authority store.
type CapacityVMObservationInput struct {
	Policy        ManifestSelector `json:"policy"`
	BindingName   string           `json:"binding_name"`
	ParentGrantID string           `json:"parent_grant_id,omitempty"`
	Slot          int              `json:"slot,omitempty"`
	GrantID       string           `json:"grant_id,omitempty"`
	Generation    int64            `json:"generation,omitempty"`
	FencingToken  int64            `json:"fencing_token,omitempty"`
	LeaseOwner    string           `json:"lease_owner,omitempty"`
}

// UsefulCapacityKnown remains false. Owned native units include powered-off
// machines and cannot be substituted for warm/ready business capacity.
type CapacityVMInventoryReceipt struct {
	Inventory           CapacityVMFleetInventory `json:"inventory"`
	MutationProofs      []CapacityMutationProof  `json:"mutation_proofs"`
	NativeMembers       int                      `json:"native_members"`
	Registered          int                      `json:"registered"`
	UsefulCapacityKnown bool                     `json:"useful_capacity_known"`
}
