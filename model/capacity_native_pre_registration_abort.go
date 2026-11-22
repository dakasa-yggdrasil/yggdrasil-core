package model

import "time"

// CapacityNativeAbortBinding is an operator-reviewed literal in a separate
// human-only workflow. It never retargets the original capacity policy.
type CapacityNativeAbortBinding struct {
	Schema              string                               `json:"schema"`
	PolicyID            string                               `json:"policy_id"`
	PolicyChecksum      string                               `json:"policy_checksum"`
	Generation          int64                                `json:"generation"`
	Adapter             CapacityObservationAdapterBinding    `json:"adapter"`
	AdapterPrincipalID  string                               `json:"adapter_principal_id"`
	AdapterSourceCommit string                               `json:"adapter_source_commit"`
	OperatorID          string                               `json:"operator_id"`
	BindingName         string                               `json:"binding_name"`
	Namespace           string                               `json:"namespace"`
	PodName             string                               `json:"pod_name"`
	PodUID              string                               `json:"pod_uid"`
	WorkloadUID         string                               `json:"workload_uid"`
	ReplicaSetUID       string                               `json:"replica_set_uid"`
	ContainerName       string                               `json:"container_name"`
	ImageDigest         string                               `json:"image_digest"`
	PodSpecSHA256       string                               `json:"pod_spec_sha256"`
	Confirmation        string                               `json:"confirmation"`
	ReviewedQuarantines *CapacityNativeAbortQuarantineReview `json:"reviewed_quarantines,omitempty"`
}

// This is native terminal metadata, not an SDK receipt or a lane witness.
type NativePreRegistrationAbortObservation struct {
	NativeTerminationObservation
	ReplicaSetUID    string `json:"replica_set_uid"`
	PodSpecSHA256    string `json:"pod_spec_sha256"`
	PodPhase         string `json:"pod_phase"`
	ProtectionOwner  string `json:"protection_owner"`
	BirthWorkloadUID string `json:"birth_workload_uid"`
	ChallengeState   string `json:"challenge_state"`
}

type AdapterObserveCapacityPodUnregisteredTerminalRequest struct {
	BindingName    string `json:"binding_name"`
	PodName        string `json:"pod_name"`
	ExpectedPodUID string `json:"expected_pod_uid"`
}

type AdapterCapacityPodUnregisteredTerminalResponse struct {
	Operation   string                                `json:"operation"`
	Status      string                                `json:"status"`
	Observation NativePreRegistrationAbortObservation `json:"observation"`
	Metadata    map[string]any                        `json:"metadata"`
}

// Counts cover every scope and every state for the original UID. The server
// computes these while holding the dimension and global UID locks.
type CapacityNativeAbortZeroHistory struct {
	Lifetimes         int64 `json:"lifetimes"`
	LifetimeArchives  int64 `json:"lifetime_archives"`
	LegacyCheckpoints int64 `json:"legacy_checkpoints"`
	CommandIdentities int64 `json:"command_identities"`
	HotCommands       int64 `json:"hot_commands"`
	ArchivedCommands  int64 `json:"archived_commands"`
}

type CapacityNativeAbortProof struct {
	Schema                   string                                `json:"schema"`
	Binding                  CapacityNativeAbortBinding            `json:"binding"`
	Observation              NativePreRegistrationAbortObservation `json:"observation"`
	ZeroHistory              CapacityNativeAbortZeroHistory        `json:"zero_history"`
	ScopeUnsettledCommands   int64                                 `json:"scope_unsettled_commands"`
	FencingToken             int64                                 `json:"fencing_token"`
	AuthoredAt               time.Time                             `json:"authored_at"`
	ReviewedQuarantineCounts *CapacityNativeUnsettledCounts        `json:"reviewed_quarantine_counts,omitempty"`
}

// References identify the complete reviewed administrative receipt, not an
// assertion that its original uncertain command returned or was settled.
type CapacityNativeAbortQuarantineReference struct {
	CommandID    string `json:"command_id"`
	SubjectUID   string `json:"subject_uid"`
	RecordSHA256 string `json:"record_sha256"`
}

type CapacityNativeAbortQuarantineReview struct {
	Receipts []CapacityNativeAbortQuarantineReference `json:"receipts"`
}

// The canonical request is retained under its immutable command-identity
// digest. Only IssueNativePreRegistrationAbort may author Proof.
type AdapterDestroyCapacityPodUnregisteredProtectionRequest struct {
	AuthorityToken             string                   `json:"authority_token,omitempty"`
	ExpectedPodUID             string                   `json:"expected_pod_uid"`
	ExpectedPodResourceVersion string                   `json:"expected_pod_resource_version"`
	Proof                      CapacityNativeAbortProof `json:"proof"`
	DryRun                     *bool                    `json:"dry_run"`
}
