package model

import "time"

// ProjectID is Source-reviewed, not a provider introspection response. A token
// digest is checked privately, and the actual network anchor joins that scope.
type CapacityNativeWorkerHCloudProjectScope struct {
	DeclaredProjectID     string    `json:"declared_project_id"`
	ProofKind             string    `json:"proof_kind"`
	AnchorID              string    `json:"anchor_id"`
	AnchorCreated         time.Time `json:"anchor_created"`
	AnchorOwnerLabelKey   string    `json:"anchor_owner_label_key"`
	AnchorOwnerLabelValue string    `json:"anchor_owner_label_value"`
}

type CapacityNativeWorkerHCloudObservedLabels struct {
	AttemptID          string `json:"attempt_id"`
	PoolUID            string `json:"pool_uid"`
	LaunchSHA256Base32 string `json:"launch_sha256_base32"`
}

// Region is the actual location name (the Core market region); NetworkZone
// supplies the distinct actual System native region. AccountID stays empty,
// as required by System's HCloud Provider. No physical binding hash is invented.
type CapacityNativeWorkerHCloudPhysicalFacts struct {
	ResourceID         string    `json:"resource_id"`
	ProviderID         string    `json:"provider_id"`
	AccountID          string    `json:"account_id"`
	InstanceType       string    `json:"instance_type"`
	NetworkID          string    `json:"network_id"`
	NativeNetworkCIDR  string    `json:"native_network_cidr"`
	CreatedAt          time.Time `json:"created_at"`
	ImageID            string    `json:"image_id"`
	Region             string    `json:"region"`
	Zone               string    `json:"zone"`
	NetworkZone        string    `json:"network_zone"`
	NativeIPv4         string    `json:"native_ipv4"`
	MACAddress         string    `json:"mac_address"`
	PhysicalSpecSHA256 string    `json:"physical_spec_sha256"`
	LaunchSHA256       string    `json:"launch_sha256"`
}

type CapacityNativeWorkerHCloudObservedRPC struct {
	Operation         string    `json:"operation"`
	HTTPStatus        int       `json:"http_status"`
	RequestID         string    `json:"request_id"`
	RequestIDObserved bool      `json:"request_id_observed"`
	ObservedAt        time.Time `json:"observed_at"`
}

type CapacityNativeWorkerHCloudObservedPrimaryIP struct {
	ResourceID      string `json:"resource_id"`
	Type            string `json:"type"`
	IP              string `json:"ip"`
	AssigneeID      string `json:"assignee_id"`
	AutoDelete      bool   `json:"auto_delete"`
	DeleteProtected bool   `json:"delete_protected"`
}

type CapacityNativeWorkerHCloudRootStorage struct {
	Kind                     string `json:"kind"`
	SizeGiB                  int64  `json:"size_gib"`
	ProviderEncryptionProven bool   `json:"provider_encryption_proven"`
}

type CapacityNativeWorkerHCloudPhysicalObservation struct {
	Schema                  string                                        `json:"schema"`
	SourceCommit            string                                        `json:"source_commit"`
	Adapter                 CapacityMarketAdapterBinding                  `json:"adapter"`
	BindingName             string                                        `json:"binding_name"`
	BindingScopeSHA256      string                                        `json:"binding_scope_sha256"`
	Requested               CapacityNativeWorkerObservationRequest        `json:"requested"`
	StartedAt               time.Time                                     `json:"started_at"`
	ObservedAt              time.Time                                     `json:"observed_at"`
	Complete                bool                                          `json:"complete"`
	ProjectScope            CapacityNativeWorkerHCloudProjectScope        `json:"project_scope"`
	ActualLabels            CapacityNativeWorkerHCloudObservedLabels      `json:"actual_labels"`
	ActualLaunchSHA256      string                                        `json:"actual_launch_sha256"`
	ServerName              string                                        `json:"server_name"`
	InstanceState           string                                        `json:"instance_state"`
	ServerLocked            bool                                          `json:"server_locked"`
	TransportEndpointIPv4   string                                        `json:"transport_endpoint_ipv4"`
	Physical                CapacityNativeWorkerHCloudPhysicalFacts       `json:"physical"`
	RootStorage             CapacityNativeWorkerHCloudRootStorage         `json:"root_storage"`
	FirewallIDs             []string                                      `json:"firewall_ids"`
	PrimaryIPs              []CapacityNativeWorkerHCloudObservedPrimaryIP `json:"primary_ips"`
	Reads                   []CapacityNativeWorkerHCloudObservedRPC       `json:"reads"`
	EvidenceSHA256          string                                        `json:"evidence_sha256"`
	MutationAuthorized      bool                                          `json:"mutation_authorized"`
	NodeReadyQualified      bool                                          `json:"node_ready_qualified"`
	UsefulCapacityQualified bool                                          `json:"useful_capacity_qualified"`
	AbsenceProven           bool                                          `json:"absence_proven"`
}

// Safe original acceptance projection. Optional NIC fields record only what
// the original asynchronous creation reply actually contained. No root_password,
// user-data, credential, raw original bytes or raw-original digest belongs here.
type CapacityNativeWorkerHCloudAcceptance struct {
	ResourceID        string                                   `json:"resource_id"`
	ServerName        string                                   `json:"server_name"`
	CreatedAt         time.Time                                `json:"created_at"`
	ServerTypeID      string                                   `json:"server_type_id"`
	InstanceType      string                                   `json:"instance_type"`
	ImageID           string                                   `json:"image_id"`
	LocationID        string                                   `json:"location_id"`
	Location          string                                   `json:"location"`
	NetworkZone       string                                   `json:"network_zone"`
	Labels            CapacityNativeWorkerHCloudObservedLabels `json:"labels"`
	NetworkID         string                                   `json:"network_id,omitempty"`
	NativeIPv4        string                                   `json:"native_ipv4,omitempty"`
	MACAddress        string                                   `json:"mac_address,omitempty"`
	ActionID          string                                   `json:"action_id"`
	ActionCommand     string                                   `json:"action_command"`
	ActionStatus      string                                   `json:"action_status"`
	RequestID         string                                   `json:"request_id"`
	RequestIDObserved bool                                     `json:"request_id_observed"`
}

// A protected Core qualifier constructs this provider-specific witness. The
// whole safe DTO and static reader pin are bound, rather than filling generic
// account/request-ID fields with fabricated HCloud values. It grants no Node,
// network, admission, billing-closure or new mutation authority.
type CapacityNativeWorkerHCloudWitness struct {
	Schema                 string                                        `json:"schema"`
	CoreSourceCommit       string                                        `json:"core_source_commit"`
	AttemptID              string                                        `json:"attempt_id"`
	PolicyID               string                                        `json:"policy_id"`
	PoolUID                string                                        `json:"pool_uid"`
	PoolEpoch              int64                                         `json:"pool_epoch"`
	IntentGeneration       int64                                         `json:"intent_generation"`
	FencingToken           int64                                         `json:"fencing_token"`
	LaunchSHA256           string                                        `json:"launch_sha256"`
	PhysicalIdentitySHA256 string                                        `json:"physical_identity_sha256"`
	MaxReadAgeSeconds      int                                           `json:"max_read_age_seconds"`
	Acceptance             CapacityNativeWorkerHCloudAcceptance          `json:"acceptance"`
	Reader                 CapacityNativeWorkerPhysicalReadBinding       `json:"reader"`
	Observation            CapacityNativeWorkerHCloudPhysicalObservation `json:"observation"`
	EvidenceSHA256         string                                        `json:"evidence_sha256"`
}
