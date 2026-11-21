package capacity

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const (
	NativePreRegistrationAbortSchema    = "native_pre_registration_abort_v1"
	NativePreRegistrationAbortProtocol  = "native_pre_registration_abort_original_v1"
	ObserveNativeUnregisteredTerminal   = "observe_capacity_pod_unregistered_terminal"
	DestroyNativeUnregisteredProtection = "destroy_capacity_pod_unregistered_protection"
	NativePreRegistrationAbortPhase     = "abort_before_admission"
)

func nativeAbortHex(value string, size int) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == size && value == strings.ToLower(value)
}

func ValidateNativeAbortBinding(policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityNativeAbortBinding) error {
	if b.ReviewedQuarantines != nil {
		return fmt.Errorf("legacy native abort cannot review quarantines")
	}
	if b.Schema != NativePreRegistrationAbortSchema || b.PolicyID != policy.ID.String() || b.PolicyChecksum != policy.Checksum || b.Generation < 1 || p.AssessmentBinding == nil || p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != HPALifetimeExecutionMode || p.HPAExecutionBinding.AdmissionMode != "process_v2" || b.Namespace != p.AssessmentBinding.Snapshot.Namespace || b.WorkloadUID != p.AssessmentBinding.Snapshot.WorkloadUID || b.ContainerName != p.HPAExecutionBinding.ContainerName || b.ImageDigest != p.HPAExecutionBinding.ImageDigest || b.BindingName != p.HPAExecutionBinding.PodTerminationBinding || !NativeProcessNonce(b.PodUID) || !NativeProcessNonce(b.ReplicaSetUID) || !NativeProcessNonce(b.OperatorID) || b.PodName == "" || strings.TrimSpace(b.PodName) != b.PodName || !nativeAbortHex(b.PodSpecSHA256, 32) || !nativeAbortHex(b.AdapterSourceCommit, 20) || !NativeProcessNonce(b.Adapter.IntegrationInstanceID) || !NativeProcessNonce(b.Adapter.IntegrationTypeID) || !nativeAbortHex(b.Adapter.InstanceChecksum, 32) || !nativeAbortHex(b.Adapter.TypeChecksum, 32) || b.AdapterPrincipalID == "" || len(b.AdapterPrincipalID) > 128 || strings.ContainsAny(b.AdapterPrincipalID, "\r\n\t") || b.Confirmation == "" || len(b.Confirmation) > 128 || strings.ContainsAny(b.Confirmation, "\r\n\t") {
		return fmt.Errorf("fixed native pre-registration abort binding required")
	}
	return nil
}

// This proves an actual native failed/deleting target only. It never proves
// completed SDK lanes, successful drain, or a formerly opened business root.
func ValidateNativeAbortObservation(p model.CapacityPolicySpec, b model.CapacityNativeAbortBinding, o model.NativePreRegistrationAbortObservation, now time.Time, requireProtected bool) error {
	if NativePodIdentity(p, o.NativeTerminationObservation, now) != nil || o.PodUID != b.PodUID || o.PodName != b.PodName || o.Namespace != b.Namespace || o.ReplicaSetUID != b.ReplicaSetUID || o.PodSpecSHA256 != b.PodSpecSHA256 || o.PodPhase != "Failed" || o.State != "failed_deleting" || o.ContainerState != "terminated" || o.RestartCount != 0 || o.StartedAt == nil || o.FinishedAt == nil || o.StartedAt.IsZero() || o.FinishedAt.Before(*o.StartedAt) || o.DeletionRequestedAt == nil || o.DeletionRequestedAt.IsZero() || o.ProtectionOwner != "" || o.BirthWorkloadUID != b.WorkloadUID || o.ChallengeState != "absent" || o.AdmissionReady || o.Receipt != nil || o.ReceiptSHA256 != "" || o.ExitCode == nil || *o.ExitCode == 0 || o.Signal == nil || (requireProtected && !o.Protected) {
		return fmt.Errorf("exact original failed deleting unregistered native target required")
	}
	return nil
}

func ValidateNativeAbortProof(policy model.Manifest, p model.CapacityPolicySpec, proof model.CapacityNativeAbortProof, now time.Time) error {
	if proof.ReviewedQuarantineCounts != nil {
		return fmt.Errorf("legacy native abort cannot exclude quarantines")
	}
	if ValidateNativeAbortBinding(policy, p, proof.Binding) != nil || proof.Schema != NativePreRegistrationAbortSchema || proof.FencingToken < 1 || proof.AuthoredAt.IsZero() || !Fresh(proof.AuthoredAt, now, p.MaxEvidenceAgeSeconds) || proof.AuthoredAt.Before(proof.Observation.ObservedAt) || proof.ScopeUnsettledCommands != 0 || proof.ZeroHistory != (model.CapacityNativeAbortZeroHistory{}) || ValidateNativeAbortObservation(p, proof.Binding, proof.Observation, now, true) != nil {
		return fmt.Errorf("server-owned native pre-registration abort proof required")
	}
	return nil
}

// Readback settles only the already authorized original. Absence says nothing
// about fleet quiescence, successful drain or which actor removed the object.
func ValidateNativeAbortRemoval(p model.CapacityPolicySpec, b model.CapacityNativeAbortBinding, r model.AdapterCapacityPodUnregisteredTerminalResponse, now time.Time) error {
	o := r.Observation
	if r.Operation != ObserveNativeUnregisteredTerminal || r.Status != "observed" || o.Namespace != b.Namespace || o.PodName != b.PodName || o.BindingName != b.BindingName || !Fresh(o.ObservedAt, now, p.MaxEvidenceAgeSeconds) || o.Protected {
		return fmt.Errorf("fresh original native abort readback required")
	}
	if o.State == "absent" && o.Reason == "native_name_absent" && o.PodUID == "" {
		return nil
	}
	return ValidateNativeAbortObservation(p, b, o, now, false)
}
