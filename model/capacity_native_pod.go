package model

import "time"

// CapacityPodTerminationTarget is an approved instance scope. Image and lane
// identities are immutable operator declarations, never caller receipts.
type CapacityPodTerminationTarget struct {
	BindingName         string   `json:"binding_name"`
	Namespace           string   `json:"namespace"`
	WorkloadName        string   `json:"workload_name"`
	WorkloadUID         string   `json:"workload_uid"`
	Owner               string   `json:"owner"`
	ContainerName       string   `json:"container_name"`
	ImageDigest         string   `json:"image_digest"`
	Lanes               []string `json:"lanes"`
	ProjectionDirectory string   `json:"projection_directory"`
}

// This public closed wire shape matches the independently qualified producer.
// The adapter remains standalone and imports no DaKasa or Core runtime code.
type NativePodTerminationChallenge struct {
	SchemaVersion    int       `json:"schema_version"`
	Namespace        string    `json:"namespace"`
	PodName          string    `json:"pod_name"`
	PodUID           string    `json:"pod_uid"`
	WorkloadUID      string    `json:"workload_uid"`
	ContainerName    string    `json:"container_name"`
	ImageDigest      string    `json:"image_digest"`
	IntentGeneration int64     `json:"intent_generation"`
	DrainNonce       string    `json:"drain_nonce"`
	IssuedAt         time.Time `json:"issued_at"`
	LaneRosterSHA256 string    `json:"lane_roster_sha256"`
}

type NativePodTerminationReceipt struct {
	NativePodTerminationChallenge
	JoinedAt time.Time         `json:"joined_at"`
	Lanes    map[string]string `json:"lanes"`
}

type AdapterObserveCapacityPodTerminationRequest struct {
	BindingName                string                        `json:"binding_name"`
	PodName                    string                        `json:"pod_name"`
	ExpectedPodUID             string                        `json:"expected_pod_uid"`
	ExpectedPodGeneration      int64                         `json:"expected_pod_generation"`
	ExpectedContainerID        string                        `json:"expected_container_id"`
	ExpectedContainerStartedAt time.Time                     `json:"expected_container_started_at"`
	ExpectedRestartCount       int32                         `json:"expected_restart_count"`
	Challenge                  NativePodTerminationChallenge `json:"challenge"`
}

type AdapterEnsureCapacityPodDrainRequest struct {
	AuthorityToken             string                        `json:"authority_token,omitempty"`
	BindingName                string                        `json:"binding_name"`
	PodName                    string                        `json:"pod_name"`
	ExpectedPodUID             string                        `json:"expected_pod_uid"`
	ExpectedPodResourceVersion string                        `json:"expected_pod_resource_version"`
	ExpectedPodGeneration      int64                         `json:"expected_pod_generation"`
	ExpectedContainerID        string                        `json:"expected_container_id"`
	ExpectedContainerStartedAt time.Time                     `json:"expected_container_started_at"`
	ExpectedRestartCount       int32                         `json:"expected_restart_count"`
	Challenge                  NativePodTerminationChallenge `json:"challenge"`
	// Protection and termination are separate single-send native phases.
	// No phase accepts a drain, inflight, scrape or readiness boolean.
	Phase  string `json:"phase"`
	DryRun *bool  `json:"dry_run,omitempty"`
}

type AdapterDestroyCapacityPodDrainProtectionRequest struct {
	AuthorityToken string `json:"authority_token,omitempty"`
	AdapterObserveCapacityPodTerminationRequest
	ExpectedPodResourceVersion string `json:"expected_pod_resource_version"`
	DryRun                     *bool  `json:"dry_run,omitempty"`
}

// NativeTerminationObservation exposes actual API facts. Missing/unknown
// containers or receipts never acquire an implicit successful zero value.
type NativeTerminationObservation struct {
	BindingName             string                       `json:"binding_name"`
	Namespace               string                       `json:"namespace"`
	PodName                 string                       `json:"pod_name"`
	PodUID                  string                       `json:"pod_uid"`
	PodResourceVersion      string                       `json:"pod_resource_version"`
	PodGeneration           int64                        `json:"pod_generation"`
	WorkloadUID             string                       `json:"workload_uid"`
	WorkloadResourceVersion string                       `json:"workload_resource_version"`
	ContainerName           string                       `json:"container_name"`
	ContainerID             string                       `json:"container_id"`
	ImageID                 string                       `json:"image_id"`
	ImageDigest             string                       `json:"image_digest"`
	RestartCount            int32                        `json:"restart_count"`
	ContainerState          string                       `json:"container_state"`
	ExitCode                *int32                       `json:"exit_code"`
	Signal                  *int32                       `json:"signal"`
	StartedAt               *time.Time                   `json:"started_at"`
	FinishedAt              *time.Time                   `json:"finished_at"`
	DeletionRequestedAt     *time.Time                   `json:"deletion_requested_at"`
	Protected               bool                         `json:"protected"`
	State                   string                       `json:"state"`
	Reason                  string                       `json:"reason"`
	Receipt                 *NativePodTerminationReceipt `json:"receipt"`
	ReceiptSHA256           string                       `json:"receipt_sha256"`
	ObservedAt              time.Time                    `json:"observed_at"`
}

type AdapterCapacityPodTerminationResponse struct {
	Operation   string                       `json:"operation"`
	Status      string                       `json:"status"`
	Observation NativeTerminationObservation `json:"observation"`
	Metadata    map[string]any               `json:"metadata"`
}

type AdapterObserveCapacityPodInventoryRequest struct {
	BindingName string `json:"binding_name"`
}

type AdapterCapacityPodInventoryResponse struct {
	Operation               string                         `json:"operation"`
	Status                  string                         `json:"status"`
	BindingName             string                         `json:"binding_name"`
	Namespace               string                         `json:"namespace"`
	WorkloadUID             string                         `json:"workload_uid"`
	WorkloadResourceVersion string                         `json:"workload_resource_version"`
	ListResourceVersion     string                         `json:"list_resource_version"`
	Complete                bool                           `json:"complete"`
	Pods                    []NativeTerminationObservation `json:"pods"`
	ObservedAt              time.Time                      `json:"observed_at"`
	Metadata                map[string]any                 `json:"metadata"`
}
