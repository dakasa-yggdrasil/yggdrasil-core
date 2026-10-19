package model

import "time"

// CapacitySourceRecoveryCleanupEpoch is a distinct Source-only authority epoch.
// The immutable original tuple is history, never a revived write lease.
type CapacitySourceRecoveryCleanupEpoch struct {
 Schema string `json:"schema"`
 OriginalGeneration int64 `json:"original_generation"`
 OriginalFencingToken int64 `json:"original_fencing_token"`
 OriginalLeaseOwner string `json:"original_lease_owner"`
 OriginalExecutorID string `json:"original_executor_id"`
 CurrentPolicyID string `json:"current_policy_id"`
 CurrentPolicyChecksum string `json:"current_policy_checksum"`
 Generation int64 `json:"generation"`
 FencingToken int64 `json:"fencing_token"`
 LeaseOwner string `json:"lease_owner"`
 ExecutorID string `json:"executor_id"`
 RecoveryDBObservedAt time.Time `json:"recovery_db_observed_at"`
 LeaseExpiresAt time.Time `json:"lease_expires_at"`
 IntentSHA256 string `json:"intent_sha256"`
 NonceSHA256 string `json:"nonce_sha256"`
 ChallengePreparedAt time.Time `json:"challenge_prepared_at"`
 FreshFailureSHA256 string `json:"fresh_failure_sha256"`
 FreshNativeSHA256 string `json:"fresh_native_sha256"`
 FreshObservedAt time.Time `json:"fresh_observed_at"`
}

type CapacitySourceRecoveryEffectRequest struct {
 Schema string `json:"schema"`
 Phase string `json:"phase"`
 NonceSHA256 string `json:"nonce_sha256"`
 AuthoritySHA256 string `json:"authority_sha256"`
 ChildAuthoritySHA256 string `json:"child_authority_sha256"`
 NativeIdentitySHA256 string `json:"native_identity_sha256"`
}

type CapacitySourceRecoveryEffectPermit struct {
 Schema string `json:"schema"`
 Scope string `json:"scope"`
 Phase string `json:"phase"`
 RequestSHA256 string `json:"request_sha256"`
 AuthoritySHA256 string `json:"authority_sha256"`
 ChildAuthoritySHA256 string `json:"child_authority_sha256"`
 ChildGrantID string `json:"child_grant_id"`
 ChildAttemptID string `json:"child_attempt_id"`
 NativeIdentitySHA256 string `json:"native_identity_sha256"`
 NonceSHA256 string `json:"nonce_sha256"`
 Generation int64 `json:"generation"`
 FencingToken int64 `json:"fencing_token"`
 LeaseOwner string `json:"lease_owner"`
 ExecutorID string `json:"executor_id"`
 CheckedAt time.Time `json:"checked_at"`
 Deadline time.Time `json:"deadline"`
 CoreSource string `json:"core_source"`
 GuestSource string `json:"guest_source"`
 ProductionQualified bool `json:"production_qualified"`
}
