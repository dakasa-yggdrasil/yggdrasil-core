package model

import "time"

// References retain the exact four original, atomically unredeemed permissions.
// No caller permission/token, native witness or mutable readiness flag is accepted.
type CapacityUnredeemedProtectReference struct {
	CommandID    string `json:"command_id"`
	RecordSHA256 string `json:"record_sha256"`
}

type CapacityUnredeemedProtectRecoveryBinding struct {
	Schema                     string                               `json:"schema"`
	PolicyID                   string                               `json:"policy_id"`
	PolicyChecksum             string                               `json:"policy_checksum"`
	OperatorID                 string                               `json:"operator_id"`
	PodUID                     string                               `json:"pod_uid"`
	CheckpointSHA256           string                               `json:"checkpoint_sha256"`
	ExpectedIntentGeneration   int64                                `json:"expected_intent_generation"`
	ExpectedIntentFencingToken int64                                `json:"expected_intent_fencing_token"`
	Commands                   []CapacityUnredeemedProtectReference `json:"commands"`
	Confirmation               string                               `json:"confirmation"`
}

// This marker is authored and retained by Core under the same scope/UID locks as
// the new intent and child identity. It is never an adapter execution input.
type CapacityUnredeemedProtectRecoveryProof struct {
	Schema           string                                   `json:"schema"`
	Binding          CapacityUnredeemedProtectRecoveryBinding `json:"binding"`
	Workflow         ManifestReference                        `json:"workflow"`
	WorkflowChecksum string                                   `json:"workflow_checksum"`
	RecoveryID       string                                   `json:"recovery_id"`
	ChildID          string                                   `json:"child_id"`
	Generation       int64                                    `json:"generation"`
	Fence            int64                                    `json:"fencing_token"`
	Boot             AdapterCapacityPodAdmissionResponse      `json:"boot"`
	AuthoredAt       time.Time                                `json:"authored_at"`
}
