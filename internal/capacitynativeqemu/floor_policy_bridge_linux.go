//go:build linux && nativequalification

package capacitynativeqemu

import (
 "time"
)

// Source-only policy successor. This never rewrites or relabels an original
// enrollment/preregistration: both real manifest identities remain explicit.
type SourceFloorPolicyBridge struct {
 Schema string `json:"schema"`
 Scope string `json:"scope"`
 CoreSource string `json:"core_source"`
 GuestSource string `json:"guest_source"`
 Namespace string `json:"namespace"`
 PolicyName string `json:"policy_name"`
 OriginalPolicyID string `json:"original_policy_id"`
 OriginalPolicyChecksum string `json:"original_policy_checksum"`
 CurrentPolicyID string `json:"current_policy_id"`
 CurrentPolicyChecksum string `json:"current_policy_checksum"`
 OriginalVersion int `json:"original_version"`
 CurrentVersion int `json:"current_version"`
 WorkflowID string `json:"workflow_id"`
 BindingSHA256 string `json:"binding_sha256"`
 OriginalFloor int `json:"original_floor"`
 CurrentFloor int `json:"current_floor"`
 BaselineUnits int `json:"baseline_units"`
 OriginalBaselineProbeSHA256 string `json:"original_baseline_probe_sha256"`
 CreatedAt time.Time `json:"created_at"`
 NativeQualified bool `json:"native_qualified"`
}

func SourceFailedFloorCase(value string) bool { return value == "source_live_failed_floor_recovery" || value == "canonical_failed_floor_recovery" }

type SourceFailedFloorContract struct {
 Schema string `json:"schema"`
 Scope string `json:"scope"`
 Case string `json:"case"`
 CoreSource string `json:"core_source"`
 GuestSource string `json:"guest_source"`
 OriginalPolicyID string `json:"original_policy_id"`
 CurrentPolicyID string `json:"current_policy_id"`
 PolicyBridgeSHA256 string `json:"policy_bridge_sha256"`
 CompensationResultSHA256 string `json:"compensation_result_sha256"`
 ParentGrantID string `json:"parent_grant_id"`
 ParentState string `json:"parent_state"`
 FailedFloorPhase string `json:"failed_floor_phase"`
 BaselineUnits int `json:"baseline_units"`
 FloorUnits int `json:"floor_units"`
 NativeProbeSHA256 string `json:"native_probe_sha256"`
 PhysicalSHA256 string `json:"physical_sha256"`
 FailedSlotCurrentReadSHA256 string `json:"failed_slot_current_read_sha256"`
 TerminalSHA256 string `json:"terminal_sha256"`
 SourceIntentTerminalSHA256 string `json:"source_intent_terminal_sha256"`
 NextIntentSHA256 string `json:"next_intent_sha256"`
 NextGeneration int64 `json:"next_generation"`
 Refused []string `json:"refused"`
 Generation int64 `json:"generation"`
 CheckedAt time.Time `json:"checked_at"`
 OriginalDeadline time.Time `json:"original_deadline"`
 NativeQualified bool `json:"native_qualified"`
}
