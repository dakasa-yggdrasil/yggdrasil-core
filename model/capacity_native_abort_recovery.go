package model

import "time"

// The literal human binding names one expired, never-redeemed predecessor.
// Native remains the distinct adapter/Pod binding; it never retargets policy.
type CapacityNativeAbortRecoveryBinding struct {
	Schema                     string                     `json:"schema"`
	Native                     CapacityNativeAbortBinding `json:"native"`
	ParentCommandID            string                     `json:"parent_command_id"`
	ParentFencingToken         int64                      `json:"parent_fencing_token"`
	ParentExpiresAt            time.Time                  `json:"parent_expires_at"`
	ExpectedIntentFencingToken int64                      `json:"expected_intent_fencing_token"`
}

// Lineage describes an administrative authority disposition, never a native
// result. No private token, nonce or command-record digest crosses this wire.
type CapacityNativeAbortRecoveryLineage struct {
	ParentCommandID     string    `json:"parent_command_id"`
	ParentSequence      int       `json:"parent_sequence"`
	PriorState          string    `json:"prior_state"`
	AdministrativeState string    `json:"administrative_state"`
	ParentFencingToken  int64     `json:"parent_fencing_token"`
	ParentExpiresAt     time.Time `json:"parent_expires_at"`
	DispositionAt       time.Time `json:"disposition_at"`
}

// This separate schema reports the actual retained parent history. The v1
// proof's all-zero history and canonical representation remain unchanged.
type CapacityNativeAbortRecoveryProof struct {
	Schema                 string                                `json:"schema"`
	Binding                CapacityNativeAbortRecoveryBinding    `json:"binding"`
	Observation            NativePreRegistrationAbortObservation `json:"observation"`
	History                CapacityNativeAbortZeroHistory        `json:"history"`
	ScopeUnsettledCommands int64                                 `json:"scope_unsettled_commands"`
	Lineage                CapacityNativeAbortRecoveryLineage    `json:"lineage"`
	FencingToken           int64                                 `json:"fencing_token"`
	AuthoredAt             time.Time                             `json:"authored_at"`
}

type AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest struct {
	AuthorityToken             string                           `json:"authority_token,omitempty"`
	ExpectedPodUID             string                           `json:"expected_pod_uid"`
	ExpectedPodResourceVersion string                           `json:"expected_pod_resource_version"`
	Proof                      CapacityNativeAbortRecoveryProof `json:"proof"`
	DryRun                     *bool                            `json:"dry_run"`
}
