package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Bound execution remains optional and defaults disabled. It never authorizes
// VM mutations through a reserved HPA envelope policy.
type CapacityHPAExecutionBinding struct {
	AdapterPrincipalID    string           `json:"adapter_principal_id"`
	Mode                  string           `json:"mode"`
	PodTerminationBinding string           `json:"pod_termination_binding"`
	ContainerName         string           `json:"container_name"`
	ImageDigest           string           `json:"image_digest"`
	Lanes                 []string         `json:"lanes"`
	ProjectionDirectory   string           `json:"projection_directory"`
	AdmissionMode         string           `json:"admission_mode,omitempty"`
	AdmissionPort         int              `json:"admission_port,omitempty"`
	AdmissionWorkflow     ManifestSelector `json:"admission_workflow,omitempty"`
	BirthGuardBinding     string           `json:"birth_guard_binding,omitempty"`
	BirthGuardSHA256      string           `json:"birth_guard_sha256,omitempty"`
}

// Native commands are fixed server-authored, one-send envelopes. Their private
// permission and adapter transport settlement are distinct from native readback.
type CapacityNativeCommand struct {
	AdapterPrincipalID   string                            `json:"adapter_principal_id"`
	CommandID            uuid.UUID                         `json:"command_id"`
	PolicyID             uuid.UUID                         `json:"policy_id"`
	PolicyChecksum       string                            `json:"policy_checksum"`
	WorkflowID           uuid.UUID                         `json:"workflow_id"`
	Namespace            string                            `json:"namespace"`
	Environment          string                            `json:"environment"`
	Domain               string                            `json:"domain"`
	Dimension            string                            `json:"dimension"`
	IntentGeneration     int64                             `json:"intent_generation"`
	FencingToken         int64                             `json:"fencing_token"`
	LeaseOwner           string                            `json:"lease_owner"`
	ExecutorID           string                            `json:"executor_id"`
	Adapter              CapacityObservationAdapterBinding `json:"adapter"`
	Operation            string                            `json:"operation"`
	Phase                string                            `json:"phase"`
	Sequence             int                               `json:"sequence"`
	Request              json.RawMessage                   `json:"request"`
	RequestSHA256        string                            `json:"request_sha256"`
	State                string                            `json:"state"`
	AuthorityTokenSHA256 string                            `json:"authority_token_sha256"`
	AttemptID            uuid.UUID                         `json:"attempt_id"`
	RedeemedBy           string                            `json:"redeemed_by"`
	CreatedAt            time.Time                         `json:"created_at"`
	ExpiresAt            time.Time                         `json:"expires_at"`
	NativeReadback       json.RawMessage                   `json:"native_readback"`
	UpdatedAt            time.Time                         `json:"updated_at"`
	OriginPolicy         json.RawMessage                   `json:"origin_policy,omitempty"`
	OriginPolicySHA256   string                            `json:"origin_policy_sha256,omitempty"`
	AdmissionOnly        bool                              `json:"admission_only,omitempty"`
}

// This is a private durable target checkpoint, not caller proof. A same-name
// replacement or restarted current container never matches the old lifetime.
type CapacityNativePodCheckpoint struct {
	Namespace                 string          `json:"namespace"`
	PodName                   string          `json:"pod_name"`
	PodUID                    string          `json:"pod_uid"`
	PodResourceVersion        string          `json:"pod_resource_version"`
	PodGeneration             int64           `json:"pod_generation"`
	WorkloadUID               string          `json:"workload_uid"`
	ContainerName             string          `json:"container_name"`
	ContainerID               string          `json:"container_id"`
	ContainerStartedAt        time.Time       `json:"container_started_at"`
	ImageDigest               string          `json:"image_digest"`
	RestartCount              int32           `json:"restart_count"`
	IntentGeneration          int64           `json:"intent_generation"`
	DrainNonce                string          `json:"drain_nonce"`
	Challenge                 json.RawMessage `json:"challenge"`
	OriginChallengeBytes      []byte          `json:"origin_challenge_bytes"`
	OriginChallengeSHA256     string          `json:"origin_challenge_sha256"`
	State                     string          `json:"state"`
	NativeTerminationReceipt  json.RawMessage `json:"native_termination_receipt"`
	ConfirmedAt               *time.Time      `json:"confirmed_at"`
	PolicyID                  uuid.UUID       `json:"policy_id"`
	PolicyChecksum            string          `json:"policy_checksum"`
	BindingSHA256             string          `json:"binding_sha256"`
	ProcessNonce              string          `json:"process_nonce"`
	ProjectionAcknowledgement json.RawMessage `json:"projection_acknowledgement"`
	RootAcknowledgement       json.RawMessage `json:"root_acknowledgement"`
	OriginPolicy              json.RawMessage `json:"origin_policy"`
	OriginPolicySHA256        string          `json:"origin_policy_sha256"`
}

type CapacityNativeAuthorityRedeemRequest struct {
	AuthorityToken        string `json:"authority_token"`
	IntegrationInstanceID string `json:"integration_instance_id"`
	IntegrationTypeID     string `json:"integration_type_id"`
	Capability            string `json:"capability"`
	RequestSHA256         string `json:"request_sha256"`
}

type CapacityNativeAuthorityPermit struct {
	SchemaVersion int       `json:"schema_version"`
	CommandID     uuid.UUID `json:"command_id"`
	AttemptID     uuid.UUID `json:"attempt_id"`
	Capability    string    `json:"capability"`
	RequestSHA256 string    `json:"request_sha256"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type CapacityNativeHPARequest struct {
	Namespace                       string `json:"namespace"`
	HPAName                         string `json:"hpa_name"`
	ExpectedUID                     string `json:"expected_uid"`
	ExpectedResourceVersion         string `json:"expected_resource_version"`
	ExpectedWorkloadUID             string `json:"expected_workload_uid"`
	ExpectedWorkloadResourceVersion string `json:"expected_workload_resource_version"`
	Owner                           string `json:"owner"`
	Generation                      int64  `json:"generation"`
	IdempotencyKey                  string `json:"idempotency_key"`
	MinReplicas                     int    `json:"min_replicas"`
	MaxReplicas                     int    `json:"max_replicas"`
	Adopt                           bool   `json:"adopt,omitempty"`
	DryRun                          *bool  `json:"dry_run,omitempty"`
	Mode                            string `json:"mode,omitempty"`
	BirthGuardBindingName           string `json:"birth_guard_binding_name"`
}
