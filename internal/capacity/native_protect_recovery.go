package capacity

import (
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const UnredeemedProtectRecoverySchema = "native_unredeemed_protect_recovery_v1"
const RecoverUnredeemedNativeProtect = "capacity.recover_unredeemed_native_protect"

func ValidateUnredeemedProtectRecoveryBinding(policy model.Manifest, p model.CapacityPolicySpec, b model.CapacityUnredeemedProtectRecoveryBinding) error {
	if b.Schema != UnredeemedProtectRecoverySchema || b.PolicyID != policy.ID.String() || b.PolicyChecksum != policy.Checksum || !p.ExecutionEnabled || p.AssessmentBinding == nil || p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != HPALifetimeExecutionMode || p.HPAExecutionBinding.AdmissionMode != "process_v2" || !NativeProcessNonce(b.OperatorID) || !NativeProcessNonce(b.PodUID) || !lowerSHA.MatchString(b.CheckpointSHA256) || b.ExpectedIntentGeneration < 1 || b.ExpectedIntentFencingToken < 1 || len(b.Commands) != 4 || b.Confirmation == "" || len(b.Confirmation) > 128 || strings.TrimSpace(b.Confirmation) != b.Confirmation || strings.ContainsAny(b.Confirmation, "\r\n\t") {
		return fmt.Errorf("fixed human unredeemed protect recovery binding required")
	}
	seen := map[string]bool{}
	for _, ref := range b.Commands {
		if !NativeProcessNonce(ref.CommandID) || seen[ref.CommandID] || !lowerSHA.MatchString(ref.RecordSHA256) {
			return fmt.Errorf("four distinct ordered original permission references required")
		}
		seen[ref.CommandID] = true
	}
	return nil
}

// A fresh SDK read is required, not an operator assertion that a Pod is live.
// The immutable checkpoint origin is retained; no receipt or root ACK is minted.
func ValidateUnredeemedProtectRecoveryBoot(p model.CapacityPolicySpec, cp model.CapacityNativePodCheckpoint, boot model.AdapterCapacityPodAdmissionResponse, now time.Time) error {
	if cp.State != "planned" || NativeProcessAdmission(p, boot, now) != nil || boot.Admission.State != "waiting_projection" || boot.Admission.Challenge != nil || boot.Admission.ChallengeSHA256 != "" || boot.Observation.AdmissionReady || NativePodMatchesCheckpoint(p, cp, boot.Observation, now) != nil || boot.Observation.StartedAt == nil || !boot.Observation.StartedAt.Equal(cp.ContainerStartedAt) || boot.Admission.ProcessNonce != cp.ProcessNonce || boot.Observation.PodResourceVersion == "" || boot.Observation.Receipt != nil || boot.Observation.ReceiptSHA256 != "" || boot.Observation.FinishedAt != nil || boot.Observation.ExitCode != nil || boot.Observation.Signal != nil {
		return fmt.Errorf("fresh same original waiting SDK process required")
	}
	return nil
}
