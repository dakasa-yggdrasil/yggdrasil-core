package model

import "time"

type CapacityNativeWorkerObservationRequest struct {
	BindingName  string `json:"binding_name"`
	AttemptID    string `json:"attempt_id"`
	ResourceID   string `json:"resource_id"`
	LaunchSHA256 string `json:"launch_sha256"`
}

type CapacityNativeWorkerObservedTags struct {
	AttemptID    string `json:"attempt_id"`
	PoolUID      string `json:"pool_uid"`
	LaunchSHA256 string `json:"launch_sha256"`
}

// Actual SDK facts plus the reviewed static physical-spec identity. BindingSHA
// is deliberately absent: Core/System must reconstruct the canonical binding
// from persisted Launch plus independently received actual provider facts.
type CapacityNativeWorkerPhysicalFacts struct {
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
	NativeIPv4         string    `json:"native_ipv4"`
	MACAddress         string    `json:"mac_address"`
	PhysicalSpecSHA256 string    `json:"physical_spec_sha256"`
	LaunchSHA256       string    `json:"launch_sha256"`
}

type CapacityNativeWorkerObservedVolume struct {
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

type CapacityNativeWorkerObservedInterface struct {
	ResourceID          string `json:"resource_id"`
	NetworkID           string `json:"network_id"`
	SubnetID            string `json:"subnet_id"`
	NativeIPv4          string `json:"native_ipv4"`
	MACAddress          string `json:"mac_address"`
	AttachedInstanceID  string `json:"attached_instance_id"`
	AttachmentID        string `json:"attachment_id"`
	DeleteOnTermination bool   `json:"delete_on_termination"`
}

type CapacityNativeWorkerObservedRPC struct {
	Operation  string    `json:"operation"`
	Role       string    `json:"role"`
	RequestID  string    `json:"request_id"`
	ObservedAt time.Time `json:"observed_at"`
}

type CapacityNativeWorkerPhysicalObservation struct {
	// Internal carrier only. The provider-specific RPC decoder populates this
	// after closed HCloud decoding; AWS wire/evidence serialization is unchanged.
	HCloud                  *CapacityNativeWorkerHCloudPhysicalObservation `json:"-"`
	Schema                  string                                         `json:"schema"`
	SourceCommit            string                                         `json:"source_commit"`
	Adapter                 CapacityMarketAdapterBinding                   `json:"adapter"`
	BindingName             string                                         `json:"binding_name"`
	BindingScopeSHA256      string                                         `json:"binding_scope_sha256"`
	Requested               CapacityNativeWorkerObservationRequest         `json:"requested"`
	StartedAt               time.Time                                      `json:"started_at"`
	ObservedAt              time.Time                                      `json:"observed_at"`
	Complete                bool                                           `json:"complete"`
	ActualTags              CapacityNativeWorkerObservedTags               `json:"actual_tags"`
	ActualClientToken       string                                         `json:"actual_client_token"`
	InstanceState           string                                         `json:"instance_state"`
	Physical                CapacityNativeWorkerPhysicalFacts              `json:"physical"`
	TransportEndpointIPv4   string                                         `json:"transport_endpoint_ipv4,omitempty"`
	RootVolume              CapacityNativeWorkerObservedVolume             `json:"root_volume"`
	PrimaryInterface        CapacityNativeWorkerObservedInterface          `json:"primary_interface"`
	Reads                   []CapacityNativeWorkerObservedRPC              `json:"reads"`
	EvidenceSHA256          string                                         `json:"evidence_sha256"`
	MutationAuthorized      bool                                           `json:"mutation_authorized"`
	NodeReadyQualified      bool                                           `json:"node_ready_qualified"`
	UsefulCapacityQualified bool                                           `json:"useful_capacity_qualified"`
	AbsenceProven           bool                                           `json:"absence_proven"`
}

// This observer is a separate protected read-only integration, never the
// execution or pricing instance and never a caller-provided endpoint.
type CapacityNativeWorkerPhysicalReadBinding struct {
	Profile      string                                  `json:"profile"`
	Provider     string                                  `json:"provider"`
	Region       string                                  `json:"region"`
	Adapter      CapacityMarketAdapterBinding            `json:"adapter"`
	BindingName  string                                  `json:"binding_name"`
	SourceCommit string                                  `json:"source_commit"`
	ScopeSHA256  string                                  `json:"scope_sha256"`
	Capability   string                                  `json:"capability"`
	HCloudScope  *CapacityNativeWorkerHCloudProjectScope `json:"hcloud_scope,omitempty"`
}
