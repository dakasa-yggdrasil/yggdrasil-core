package model

import (
	"encoding/json"
	"time"
)

// Human administrative measurements are not native termination observations.
// Every zero is explicit, and the original process has no invented SDK witness.
type CapacityMigratedSourceFence struct {
	Class                    string    `json:"class"`
	MeasuredBy               string    `json:"measured_by"`
	ObservedAt               time.Time `json:"observed_at"`
	NamespaceUID             string    `json:"namespace_uid"`
	WorkloadUID              string    `json:"workload_uid"`
	ResourceVersion          string    `json:"resource_version"`
	Generation               int64     `json:"generation"`
	ObservedGeneration       int64     `json:"observed_generation"`
	DesiredReplicas          *int32    `json:"desired_replicas"`
	CurrentReplicas          *int32    `json:"current_replicas"`
	ReadyReplicas            *int32    `json:"ready_replicas"`
	AvailableReplicas        *int32    `json:"available_replicas"`
	UnavailableReplicas      *int32    `json:"unavailable_replicas"`
	CompletePodCensus        bool      `json:"complete_pod_census"`
	OwnedPods                *int32    `json:"owned_pods"`
	UnattributedMatchingPods *int32    `json:"unattributed_matching_pods"`
	OldUIDAbsent             bool      `json:"old_uid_absent"`
	OldNameHTTP404           bool      `json:"old_name_http404"`
	ReopeningFenced          bool      `json:"reopening_fenced"`
	EvidenceSHA256           string    `json:"evidence_sha256"`
	FenceEvidenceSHA256      string    `json:"fence_evidence_sha256"`
}

type CapacityMigratedNativeOriginBinding struct {
	Schema                     string                      `json:"schema"`
	Confirmation               string                      `json:"confirmation"`
	OperatorID                 string                      `json:"operator_id"`
	PolicyID                   string                      `json:"policy_id"`
	PolicyChecksum             string                      `json:"policy_checksum"`
	OriginPolicyID             string                      `json:"origin_policy_id"`
	OriginPolicyChecksum       string                      `json:"origin_policy_checksum"`
	PodUID                     string                      `json:"pod_uid"`
	PodName                    string                      `json:"pod_name"`
	WorkloadUID                string                      `json:"workload_uid"`
	ContainerName              string                      `json:"container_name"`
	ImageDigest                string                      `json:"image_digest"`
	OriginGeneration           int64                       `json:"origin_generation"`
	CheckpointSHA256           string                      `json:"checkpoint_sha256"`
	ProtectCommandID           string                      `json:"protect_command_id"`
	ProtectCommandSHA256       string                      `json:"protect_command_sha256"`
	AdmitCommandID             string                      `json:"admit_command_id"`
	AdmitCommandSHA256         string                      `json:"admit_command_sha256"`
	ExpectedIntentGeneration   int64                       `json:"expected_intent_generation"`
	ExpectedIntentFencingToken int64                       `json:"expected_intent_fencing_token"`
	TargetNamespaceUID         string                      `json:"target_namespace_uid"`
	Source                     CapacityMigratedSourceFence `json:"source"`
}

// These observations are owned by the handler's fixed native read calls.
type CapacityMigratedNativeTargetEvidence struct {
	BirthGuard CurrentBirthGuardObservation                  `json:"birth_guard"`
	HPA        CapacityHPAEnvelopeResponse                   `json:"hpa"`
	Candidates AdapterCapacityPodAdmissionCandidatesResponse `json:"candidates"`
}

type CapacityMigratedNativeOriginRetirement struct {
	Schema     string                               `json:"schema"`
	Binding    CapacityMigratedNativeOriginBinding  `json:"binding"`
	WorkflowID string                               `json:"workflow_id"`
	ExecutorID string                               `json:"executor_id"`
	OperatorID string                               `json:"operator_id"`
	Checkpoint json.RawMessage                      `json:"checkpoint"`
	Commands   []json.RawMessage                    `json:"commands"`
	Target     CapacityMigratedNativeTargetEvidence `json:"target"`
	RecordedAt time.Time                            `json:"recorded_at"`
}
