package model

import "time"

// Safe independent observations contain no object manifest, Secret.data,
// annotation payload, key names/values, private original or raw-body digest.
// Found=false is a GET result, never closure of an uncertain native mutation.
type NativeWorkerProbeResourceObservation struct {
	Schema                                 string                               `json:"schema"`
	SourceCommit                           string                               `json:"source_commit"`
	BindingScopeSHA256                     string                               `json:"binding_scope_sha256"`
	Adapter                                CapacityMarketAdapterBinding         `json:"adapter"`
	BindingName                            string                               `json:"binding_name"`
	RunID                                  string                               `json:"run_id"`
	AttemptID                              string                               `json:"attempt_id"`
	Slot                                   string                               `json:"slot"`
	ObservedAt                             time.Time                            `json:"observed_at"`
	HTTPStatus                             int                                  `json:"http_status"`
	ReadComplete                           bool                                 `json:"read_complete"`
	Found                                  bool                                 `json:"found"`
	Namespace                              NativeWorkerProbeResourceIdentity    `json:"namespace"`
	Resource                               NativeWorkerProbeResourceIdentity    `json:"resource"`
	Pod                                    *NativeWorkerProbePodObservation     `json:"pod,omitempty"`
	Node                                   *NativeWorkerProbeNodeObservation    `json:"node,omitempty"`
	Service                                *NativeWorkerProbeServiceObservation `json:"service,omitempty"`
	SecretMetadataOnly                     bool                                 `json:"secret_metadata_only"`
	EndpointSlicesComplete                 bool                                 `json:"endpoint_slices_complete"`
	EndpointSliceCollectionResourceVersion string                               `json:"endpoint_slice_collection_resource_version"`
	EndpointSlices                         []NativeWorkerProbeEndpointSlice     `json:"endpoint_slices"`
	MutationAuthorized                     bool                                 `json:"mutation_authorized"`
	ReadinessQualified                     bool                                 `json:"readiness_qualified"`
	AbsenceProven                          bool                                 `json:"absence_proven"`
	EvidenceSHA256                         string                               `json:"evidence_sha256"`
}
type NativeWorkerProbeResourceIdentity struct {
	APIVersion      string    `json:"api_version"`
	Kind            string    `json:"kind"`
	Namespace       string    `json:"namespace"`
	Name            string    `json:"name"`
	UID             string    `json:"uid"`
	ResourceVersion string    `json:"resource_version"`
	CreatedAt       time.Time `json:"created_at"`
	Deleting        bool      `json:"deleting"`
}
type NativeWorkerProbePodObservation struct {
	Phase         string                                  `json:"phase"`
	PodIPv4       string                                  `json:"pod_ipv4"`
	NodeName      string                                  `json:"node_name"`
	ContainerName string                                  `json:"container_name"`
	ContainerID   string                                  `json:"container_id"`
	Image         string                                  `json:"image"`
	ImageID       string                                  `json:"image_id"`
	StartedAt     time.Time                               `json:"started_at"`
	RestartCount  int32                                   `json:"restart_count"`
	Running       bool                                    `json:"running"`
	Ready         bool                                    `json:"ready"`
	Containers    []NativeWorkerProbeContainerObservation `json:"containers"`
}
type NativeWorkerProbeContainerObservation struct {
	Name         string    `json:"name"`
	ContainerID  string    `json:"container_id"`
	Image        string    `json:"image"`
	ImageID      string    `json:"image_id"`
	StartedAt    time.Time `json:"started_at"`
	RestartCount int32     `json:"restart_count"`
	Running      bool      `json:"running"`
	Ready        bool      `json:"ready"`
}
type NativeWorkerProbeNodeObservation struct {
	Name                      string `json:"name"`
	UID                       string `json:"uid"`
	ResourceVersion           string `json:"resource_version"`
	ProviderID                string `json:"provider_id"`
	Deleting                  bool   `json:"deleting"`
	RegistrationFound         bool   `json:"registration_found"`
	RegistrationEpoch         int64  `json:"registration_epoch"`
	Profile                   string `json:"profile"`
	RegistrationBindingSHA256 string `json:"registration_binding_sha256"`
	PhysicalSpecSHA256        string `json:"physical_spec_sha256"`
	CapacityPolicyID          string `json:"capacity_policy_id"`
	IntentGeneration          int64  `json:"intent_generation"`
	FencingToken              int64  `json:"fencing_token"`
	CreationProofSHA256       string `json:"creation_proof_sha256"`
	RegistryUID               string `json:"registry_uid"`
	RegistryResourceVersion   string `json:"registry_resource_version"`
}
type NativeWorkerProbeServiceObservation struct {
	ClusterIPv4   string                         `json:"cluster_ipv4"`
	Type          string                         `json:"type"`
	SelectorRunID string                         `json:"selector_run_id"`
	SelectorSlot  string                         `json:"selector_slot"`
	Ports         []NativeWorkerProbeServicePort `json:"ports"`
}
type NativeWorkerProbeServicePort struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Port       int32  `json:"port"`
	TargetPort string `json:"target_port"`
}
type NativeWorkerProbeEndpointSlice struct {
	Name            string                         `json:"name"`
	UID             string                         `json:"uid"`
	ResourceVersion string                         `json:"resource_version"`
	AddressType     string                         `json:"address_type"`
	OwnerServiceUID string                         `json:"owner_service_uid"`
	Ports           []NativeWorkerProbeServicePort `json:"ports"`
	Endpoints       []NativeWorkerProbeEndpoint    `json:"endpoints"`
}
type NativeWorkerProbeEndpoint struct {
	Addresses        []string `json:"addresses"`
	Ready            *bool    `json:"ready"`
	Serving          *bool    `json:"serving"`
	Terminating      *bool    `json:"terminating"`
	NodeName         string   `json:"node_name"`
	TargetAPIVersion string   `json:"target_api_version"`
	TargetKind       string   `json:"target_kind"`
	TargetNamespace  string   `json:"target_namespace"`
	TargetName       string   `json:"target_name"`
	TargetUID        string   `json:"target_uid"`
}
