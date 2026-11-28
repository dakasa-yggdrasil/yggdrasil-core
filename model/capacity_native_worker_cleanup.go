// Safe typed observations from protected provider cleanup readers.
// IDs in a request select reads; only Core-owned archived custody is authority.
package model

import "time"

type CapacityNativeWorkerCleanupRequest struct {
	BindingName  string `json:"binding_name"`
	AttemptID    string `json:"attempt_id"`
	ResourceID   string `json:"resource_id"`
	LaunchSHA256 string `json:"launch_sha256"`
	// Exactly this key may be null. Null is PRESENT snapshot mode, never absence.
	Footprint *CapacityNativeWorkerResourceFootprint `json:"footprint"`
}
type CapacityNativeWorkerCleanupPhysical struct {
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
	NetworkZone        string    `json:"network_zone,omitempty"`
	NativeIPv4         string    `json:"native_ipv4"`
	MACAddress         string    `json:"mac_address"`
	PhysicalSpecSHA256 string    `json:"physical_spec_sha256"`
	LaunchSHA256       string    `json:"launch_sha256"`
}
type CapacityNativeWorkerAWSResourceFootprint struct {
	RootVolume       CapacityNativeWorkerCleanupVolume    `json:"root_volume"`
	PrimaryInterface CapacityNativeWorkerCleanupInterface `json:"primary_interface"`
	InstanceState    string                               `json:"instance_state"`
	// none|automatic. automatic requires both actual interface associations,
	// no allocation ID, and the same actual public IPv4 across the full bracket.
	PublicIPv4Kind      string `json:"public_ipv4_kind"`
	AutomaticPublicIPv4 string `json:"automatic_public_ipv4"`
}
type CapacityNativeWorkerHCloudResourceFootprint struct {
	ProjectScope CapacityNativeWorkerCleanupProjectScope `json:"project_scope"`
	PrimaryIPs   []CapacityNativeWorkerCleanupPrimaryIP  `json:"primary_ips"`
	RootStorage  CapacityNativeWorkerCleanupRootStorage  `json:"root_storage"`
	// These lists must have been explicitly present/empty in the actual reply;
	// a missing/null list is unknown, never an inferred zero.
	AdditionalVolumeIDs []string `json:"additional_volume_ids"`
	FloatingIPIDs       []string `json:"floating_ip_ids"`
}
type CapacityNativeWorkerResourceFootprint struct {
	Schema             string                                       `json:"schema"`   // native_worker_resource_footprint_v1
	Provider           string                                       `json:"provider"` // aws|hetzner, exactly one provider arm
	SourceCommit       string                                       `json:"source_commit"`
	Adapter            CapacityMarketAdapterBinding                 `json:"adapter"`
	BindingName        string                                       `json:"binding_name"`
	BindingScopeSHA256 string                                       `json:"binding_scope_sha256"`
	Requested          CapacityNativeWorkerObservationRequest       `json:"requested"`
	ActualPoolUID      string                                       `json:"actual_pool_uid"`
	ObservedAt         time.Time                                    `json:"observed_at"`
	Physical           CapacityNativeWorkerCleanupPhysical          `json:"physical"`
	AWS                *CapacityNativeWorkerAWSResourceFootprint    `json:"aws,omitempty"`
	HCloud             *CapacityNativeWorkerHCloudResourceFootprint `json:"hcloud,omitempty"`
	EvidenceSHA256     string                                       `json:"evidence_sha256"` // Safe allowlisted projection only.
}
type CapacityNativeWorkerCleanupResource struct {
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id"`
	// present|terminal|not_found|unknown, derived only from the actual GET.
	Outcome     string `json:"outcome"`
	NativeState string `json:"native_state"`
	// Only a real typed provider not_found; generic errors are unknown.
	NotFoundCode string `json:"not_found_code"`
	// Actual current relationship when present, empty otherwise.
	AttachedInstanceID string `json:"attached_instance_id"`
}
type CapacityNativeWorkerCleanupAWSRead struct {
	Operation  string    `json:"operation"`
	Role       string    `json:"role"`
	RequestID  string    `json:"request_id"`
	ObservedAt time.Time `json:"observed_at"`
}
type CapacityNativeWorkerCleanupHCloudRead struct {
	Operation         string    `json:"operation"`
	Role              string    `json:"role"`
	HTTPStatus        int       `json:"http_status"`
	RequestID         string    `json:"request_id"`
	RequestIDObserved bool      `json:"request_id_observed"`
	ObservedAt        time.Time `json:"observed_at"`
}
type CapacityNativeWorkerCleanupObservation struct {
	Schema             string                                 `json:"schema"` // native_worker_cleanup_observation_v1
	Provider           string                                 `json:"provider"`
	Mode               string                                 `json:"mode"` // snapshot|closure; derived from null/non-null input
	SourceCommit       string                                 `json:"source_commit"`
	Adapter            CapacityMarketAdapterBinding           `json:"adapter"`
	BindingName        string                                 `json:"binding_name"`
	BindingScopeSHA256 string                                 `json:"binding_scope_sha256"`
	Requested          CapacityNativeWorkerObservationRequest `json:"requested"`
	StartedAt          time.Time                              `json:"started_at"`
	ObservedAt         time.Time                              `json:"observed_at"`
	Complete           bool                                   `json:"complete"` // Complete reads, never admission/bill closure.
	// Snapshot: newly independently observed present footprint.
	// Closure: identical persisted footprint, informational selectors only.
	Footprint      *CapacityNativeWorkerResourceFootprint  `json:"footprint"`
	Resources      []CapacityNativeWorkerCleanupResource   `json:"resources"`
	AWSReads       []CapacityNativeWorkerCleanupAWSRead    `json:"aws_reads,omitempty"`
	HCloudReads    []CapacityNativeWorkerCleanupHCloudRead `json:"hcloud_reads,omitempty"`
	EvidenceSHA256 string                                  `json:"evidence_sha256"`
}

// No ancillary_charges_closed/absence/admission/useful/mutation boolean exists.
// Core derives closure against its immutable initial abort event and separately
// verifies Nodes/Pods/registry and schema117 owned network/IPAM removal.

type CapacityNativeWorkerCleanupVolume struct {
	ResourceID          string `json:"resource_id"`
	DeviceName          string `json:"device_name"`
	AttachedInstanceID  string `json:"attached_instance_id"`
	Encrypted           bool   `json:"encrypted"`
	KMSKeyARN           string `json:"kms_key_arn"`
	VolumeType          string `json:"volume_type"`
	VolumeGiB           int32  `json:"volume_gib"`
	IOPS                int32  `json:"iops"`
	Throughput          int32  `json:"throughput"`
	DeleteOnTermination bool   `json:"delete_on_termination"`
}
type CapacityNativeWorkerCleanupInterface struct {
	ResourceID          string `json:"resource_id"`
	NetworkID           string `json:"network_id"`
	SubnetID            string `json:"subnet_id"`
	NativeIPv4          string `json:"native_ipv4"`
	MACAddress          string `json:"mac_address"`
	AttachedInstanceID  string `json:"attached_instance_id"`
	AttachmentID        string `json:"attachment_id"`
	DeleteOnTermination bool   `json:"delete_on_termination"`
}
type CapacityNativeWorkerCleanupProjectScope struct {
	DeclaredProjectID     string    `json:"declared_project_id"`
	ProofKind             string    `json:"proof_kind"`
	AnchorID              string    `json:"anchor_id"`
	AnchorCreated         time.Time `json:"anchor_created"`
	AnchorOwnerLabelKey   string    `json:"anchor_owner_label_key"`
	AnchorOwnerLabelValue string    `json:"anchor_owner_label_value"`
}
type CapacityNativeWorkerCleanupPrimaryIP struct {
	ResourceID      string `json:"resource_id"`
	Type            string `json:"type"`
	IP              string `json:"ip"`
	AssigneeID      string `json:"assignee_id"`
	AutoDelete      bool   `json:"auto_delete"`
	DeleteProtected bool   `json:"delete_protected"`
}
type CapacityNativeWorkerCleanupRootStorage struct {
	Kind                     string `json:"kind"`
	SizeGiB                  int64  `json:"size_gib"`
	ProviderEncryptionProven bool   `json:"provider_encryption_proven"`
}
