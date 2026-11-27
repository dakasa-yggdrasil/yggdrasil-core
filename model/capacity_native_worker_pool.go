package model

import "time"

// CapacityNativeWorkerPoolBinding selects one protected read-only observer.
// It declares identities and eligibility, never an expected worker quantity.
type CapacityNativeWorkerPoolBinding struct {
	Mode              string                               `json:"mode"`
	Name              string                               `json:"name"`
	SourceCommit      string                               `json:"source_commit"`
	Adapter           CapacityMarketAdapterBinding         `json:"adapter"`
	RealmUID          string                               `json:"realm_uid"`
	PoolUID           string                               `json:"pool_uid"`
	Owner             string                               `json:"owner"`
	MaxAgeSeconds     int                                  `json:"max_age_seconds"`
	ExpectedPoolEpoch int64                                `json:"expected_pool_epoch"`
	RegistryRef       CapacityNativePoolRegistryRef        `json:"registry_ref"`
	Signals           []CapacityMetricSignalBinding        `json:"signals"`
	Profiles          []CapacityNativeWorkerProfileBinding `json:"profiles"`
	ProtectedNodes    []CapacityNativeProtectedNode        `json:"protected_nodes"`
}

// Only this exact installation registry may establish the pool epoch.
type CapacityNativePoolRegistryRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type CapacityNativeWorkerProfileBinding struct {
	Profile                string `json:"profile"`
	Provider               string `json:"provider"`
	ProviderIDPrefix       string `json:"provider_id_prefix"`
	PhysicalSpecSHA256     string `json:"physical_spec_sha256"`
	RegistrationBindingSHA string `json:"registration_binding_sha256"`
	MinAllocatableMilliCPU int64  `json:"min_allocatable_millicpu"`
	MinAllocatableMemory   int64  `json:"min_allocatable_memory_bytes"`
}

type CapacityNativeProtectedNode struct {
	NodeUID    string `json:"node_uid"`
	ProviderID string `json:"provider_id"`
}

// OwnerEpoch is read from the exact installation registry and must equal the
// stable binding epoch; it is separate from each intent's generation/fence.
// Complete means the source read the whole typed Node collection, not a sample.
type CapacityNativeWorkerPoolObservation struct {
	Schema                    string                        `json:"schema"`
	SourceCommit              string                        `json:"source_commit"`
	Adapter                   CapacityMarketAdapterBinding  `json:"adapter"`
	RealmUID                  string                        `json:"realm_uid"`
	PoolUID                   string                        `json:"pool_uid"`
	Owner                     string                        `json:"owner"`
	CurrentProfile            string                        `json:"current_profile"`
	OwnerEpoch                int64                         `json:"owner_epoch"`
	RegistryRef               CapacityNativePoolRegistryRef `json:"registry_ref"`
	OwnerResourceUID          string                        `json:"owner_resource_uid"`
	OwnerResourceVersion      string                        `json:"owner_resource_version"`
	CollectionResourceVersion string                        `json:"collection_resource_version"`
	EvidenceSHA256            string                        `json:"evidence_sha256"`
	ObservedAt                time.Time                     `json:"observed_at"`
	Complete                  bool                          `json:"complete"`
	Nodes                     []CapacityNativeWorkerNode    `json:"nodes"`
}

type CapacityNativeWorkerNode struct {
	NodeUID                          string    `json:"node_uid"`
	NodeResourceVersion              string    `json:"node_resource_version"`
	ProviderID                       string    `json:"provider_id"`
	Provider                         string    `json:"provider"`
	Profile                          string    `json:"profile"`
	PoolUID                          string    `json:"pool_uid"`
	RegistrationEpoch                int64     `json:"registration_epoch"`
	RegistrationBindingSHA256        string    `json:"registration_binding_sha256"`
	PhysicalSpecSHA256               string    `json:"physical_spec_sha256"`
	CurrentRegistration              bool      `json:"current_registration"`
	CapacityPolicyID                 string    `json:"capacity_policy_id"`
	IntentGeneration                 int64     `json:"intent_generation"`
	FencingToken                     int64     `json:"fencing_token"`
	RegistrationReceiptSHA256        string    `json:"registration_receipt_sha256"`
	Ready                            bool      `json:"ready"`
	SchedulingAdmitted               bool      `json:"scheduling_admitted"`
	AdmissionReceiptSHA256           string    `json:"admission_receipt_sha256"`
	AdmissionRegistryUID             string    `json:"admission_registry_uid"`
	AdmissionRegistryResourceVersion string    `json:"admission_registry_resource_version"`
	ReadyObservedAt                  time.Time `json:"ready_observed_at"`
	Deleting                         bool      `json:"deleting"`
	Unschedulable                    bool      `json:"unschedulable"`
	AllocatableMilliCPU              int64     `json:"allocatable_millicpu"`
	AllocatableMemoryBytes           int64     `json:"allocatable_memory_bytes"`
}

func (v *CapacityNativeWorkerPoolBinding) UnmarshalJSON(raw []byte) error {
	type plain CapacityNativeWorkerPoolBinding
	var out plain
	if err := decodeCapacityMarketJSON(raw, &out); err != nil {
		return err
	}
	*v = CapacityNativeWorkerPoolBinding(out)
	return nil
}

func (v *CapacityNativeWorkerPoolObservation) UnmarshalJSON(raw []byte) error {
	type plain CapacityNativeWorkerPoolObservation
	var out plain
	if err := decodeCapacityMarketJSON(raw, &out); err != nil {
		return err
	}
	*v = CapacityNativeWorkerPoolObservation(out)
	return nil
}
