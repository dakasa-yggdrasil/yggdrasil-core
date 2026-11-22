package capacity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"sort"
	"strings"
	"time"
)

func NativeRosterDigest(lanes []string) string {
	ordered := append([]string(nil), lanes...)
	sort.Strings(ordered)
	raw, _ := json.Marshal(ordered)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func NativePodInventory(p model.CapacityPolicySpec, inventory model.AdapterCapacityPodInventoryResponse, now time.Time) error {
	b := p.HPAExecutionBinding
	s := p.AssessmentBinding
	if b == nil || s == nil || inventory.Operation != ObserveNativePodInventory || inventory.Status != "observed" || !inventory.Complete || inventory.BindingName != b.PodTerminationBinding || inventory.Namespace != s.Snapshot.Namespace || inventory.WorkloadUID != s.Snapshot.WorkloadUID || inventory.WorkloadResourceVersion == "" || inventory.ListResourceVersion == "" || !Fresh(inventory.ObservedAt, now, p.MaxEvidenceAgeSeconds) || len(inventory.Pods) > 64 {
		return fmt.Errorf("native Pod inventory unavailable or outside binding")
	}
	seen := map[string]bool{}
	for _, pod := range inventory.Pods {
		if err := NativePodIdentity(p, pod, now); err != nil {
			return err
		}
		if seen[pod.PodUID] {
			return fmt.Errorf("native Pod UID ambiguous")
		}
		seen[pod.PodUID] = true
	}
	return nil
}
func NativePodIdentity(p model.CapacityPolicySpec, pod model.NativeTerminationObservation, now time.Time) error {
	b := p.HPAExecutionBinding
	s := p.AssessmentBinding
	id, err := uuid.Parse(pod.PodUID)
	if b == nil || s == nil || err != nil || id == uuid.Nil || id.String() != pod.PodUID || pod.PodName == "" || pod.PodGeneration < 0 || pod.PodResourceVersion == "" || pod.Namespace != s.Snapshot.Namespace || pod.WorkloadUID != s.Snapshot.WorkloadUID || pod.ContainerName != b.ContainerName || pod.ContainerID == "" || pod.ImageDigest != b.ImageDigest || !strings.HasSuffix(pod.ImageID, b.ImageDigest) || pod.RestartCount < 0 || !Fresh(pod.ObservedAt, now, p.MaxEvidenceAgeSeconds) {
		return fmt.Errorf("native Pod identity unavailable or drifted")
	}
	return nil
}
func NativePodChallenge(p model.CapacityPolicySpec, intent model.CapacityIntent, pod model.NativeTerminationObservation, now time.Time) (model.NativePodTerminationChallenge, error) {
	if NativePodIdentity(p, pod, now) != nil || pod.State != "running" || pod.ContainerState != "running" || pod.StartedAt == nil || pod.StartedAt.IsZero() || pod.DeletionRequestedAt != nil {
		return model.NativePodTerminationChallenge{}, fmt.Errorf("native running Pod lifetime required")
	}
	return model.NativePodTerminationChallenge{SchemaVersion: 1, Namespace: pod.Namespace, PodName: pod.PodName, PodUID: pod.PodUID, WorkloadUID: pod.WorkloadUID, ContainerName: pod.ContainerName, ImageDigest: pod.ImageDigest, IntentGeneration: intent.Generation, DrainNonce: uuid.NewString(), IssuedAt: now.UTC(), LaneRosterSHA256: NativeRosterDigest(p.HPAExecutionBinding.Lanes)}, nil
}
func NativePodMatchesCheckpoint(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, observed model.NativeTerminationObservation, now time.Time) error {
	if nativePodMatchesProcess(p, checkpoint, observed, now) != nil || observed.PodGeneration != checkpoint.PodGeneration {
		return fmt.Errorf("native lifetime differs from private checkpoint")
	}
	return nil
}

func nativePodMatchesProcess(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, observed model.NativeTerminationObservation, now time.Time) error {
	if NativePodIdentity(p, observed, now) != nil || observed.PodUID != checkpoint.PodUID || observed.PodName != checkpoint.PodName || observed.ContainerID != checkpoint.ContainerID || observed.RestartCount != checkpoint.RestartCount || observed.ImageDigest != checkpoint.ImageDigest {
		return fmt.Errorf("native process differs from private checkpoint")
	}
	return nil
}

// BeforeDelete in Kubernetes increments a nonzero generation exactly once when
// first setting deletionTimestamp. This does not change the process's immutable
// birth generation. Only the complete current termination witness below may
// qualify that one transition; live/admission identity remains strictly equal.
func nativePodTerminationGeneration(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, observed model.NativeTerminationObservation) bool {
	return observed.PodGeneration == checkpoint.PodGeneration ||
		(p.HPAExecutionBinding != nil && p.HPAExecutionBinding.Mode == HPALifetimeExecutionMode && checkpoint.PodGeneration > 0 && observed.PodGeneration > checkpoint.PodGeneration && observed.PodGeneration-checkpoint.PodGeneration == 1 && observed.DeletionRequestedAt != nil && !observed.DeletionRequestedAt.IsZero())
}

func NativePodWitness(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, observed model.NativeTerminationObservation, now time.Time) error {
	if nativePodMatchesProcess(p, checkpoint, observed, now) != nil || !nativePodTerminationGeneration(p, checkpoint, observed) || !observed.Protected || observed.State != "terminated" || observed.ContainerState != "terminated" || observed.ExitCode == nil || *observed.ExitCode != 0 || observed.Signal == nil || *observed.Signal != 0 || observed.StartedAt == nil || !observed.StartedAt.Equal(checkpoint.ContainerStartedAt) || observed.FinishedAt == nil || observed.DeletionRequestedAt == nil || observed.Receipt == nil {
		return fmt.Errorf("current successful native termination unavailable")
	}
	var challenge model.NativePodTerminationChallenge
	if json.Unmarshal(checkpoint.Challenge, &challenge) != nil {
		return fmt.Errorf("private challenge unavailable")
	}
	receipt := observed.Receipt
	if p.HPAExecutionBinding.Mode == HPALifetimeExecutionMode && (challenge.SchemaVersion != 2 || challenge.ProcessNonce != checkpoint.ProcessNonce || !NativeProcessNonce(checkpoint.ProcessNonce) || (receipt.RootAdmission != "never_opened" && receipt.RootAdmission != "previously_opened")) {
		return fmt.Errorf("current process nonce and real root admission history unavailable")
	}
	rawExpected, _ := json.Marshal(challenge)
	rawActual, _ := json.Marshal(receipt.NativePodTerminationChallenge)
	if string(rawExpected) != string(rawActual) || receipt.IntentGeneration != checkpoint.IntentGeneration || receipt.DrainNonce != checkpoint.DrainNonce || receipt.LaneRosterSHA256 != NativeRosterDigest(p.HPAExecutionBinding.Lanes) || receipt.JoinedAt.Before(challenge.IssuedAt) || !nativeJoinTimestamp(receipt.JoinedAt, *observed.FinishedAt) || len(receipt.Lanes) != len(p.HPAExecutionBinding.Lanes) || len(observed.ReceiptSHA256) != 64 {
		return fmt.Errorf("exact complete native challenge receipt unavailable")
	}
	for _, lane := range p.HPAExecutionBinding.Lanes {
		state, ok := receipt.Lanes[lane]
		if !ok || (state != "done" && state != "inactive") {
			return fmt.Errorf("native lane incomplete or Failed")
		}
	}
	return nil
}

// Read the actual persisted witness at its durable confirmation time. Callers
// issuing new authority must additionally require that witness to be fresh now;
// archive and finalizer readback retain the original confirmation indefinitely.
func NativePodConfirmedTermination(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint) (model.AdapterCapacityPodTerminationResponse, error) {
	var witness model.AdapterCapacityPodTerminationResponse
	if (checkpoint.State != "confirmed" && checkpoint.State != "released") || checkpoint.ConfirmedAt == nil || checkpoint.ConfirmedAt.IsZero() || len(checkpoint.NativeTerminationReceipt) == 0 || DecodeNativeCapacity(checkpoint.NativeTerminationReceipt, &witness) != nil || witness.Operation != ObserveNativePodTermination || witness.Status != "observed" || NativePodWitness(p, checkpoint, witness.Observation, *checkpoint.ConfirmedAt) != nil || witness.Observation.PodResourceVersion != checkpoint.PodResourceVersion {
		return witness, fmt.Errorf("durable exact native termination witness unavailable")
	}
	return witness, nil
}

// Release authority is bound to the actual generation and version in the full
// persisted witness, never to an increment guessed for a write request.
func ValidateNativePodReleaseRequest(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, req model.AdapterDestroyCapacityPodDrainProtectionRequest, now time.Time) error {
	witness, err := NativePodConfirmedTermination(p, checkpoint)
	if err != nil || NativePodWitness(p, checkpoint, witness.Observation, now) != nil || req.PodName != checkpoint.PodName || req.ExpectedPodUID != checkpoint.PodUID || req.ExpectedPodGeneration != witness.Observation.PodGeneration || req.ExpectedContainerID != checkpoint.ContainerID || !req.ExpectedContainerStartedAt.Equal(checkpoint.ContainerStartedAt) || req.ExpectedRestartCount != checkpoint.RestartCount || req.BindingName != p.HPAExecutionBinding.PodTerminationBinding || req.ExpectedPodResourceVersion != witness.Observation.PodResourceVersion || req.DryRun == nil || *req.DryRun {
		return fmt.Errorf("native release request differs from the fresh durable witness")
	}
	var challenge model.NativePodTerminationChallenge
	if json.Unmarshal(checkpoint.Challenge, &challenge) != nil {
		return fmt.Errorf("private challenge unavailable")
	}
	expected, _ := json.Marshal(challenge)
	actual, _ := json.Marshal(req.Challenge)
	if string(expected) != string(actual) {
		return fmt.Errorf("native release challenge differs from immutable origin")
	}
	return nil
}

// An inventory row cannot certify termination. It can only identify the same
// process/generation as an independently validated complete current witness.
func NativePodInventoryMatchesWitness(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, pod model.NativeTerminationObservation, witness model.AdapterCapacityPodTerminationResponse, now time.Time) error {
	if witness.Operation != ObserveNativePodTermination || witness.Status != "observed" || NativePodWitness(p, checkpoint, witness.Observation, now) != nil || nativePodMatchesProcess(p, checkpoint, pod, now) != nil || pod.PodGeneration != witness.Observation.PodGeneration {
		return fmt.Errorf("inventory differs from exact native termination witness")
	}
	return nil
}

// This confirms only removal of the already-witnessed exact protection target.
// Absence and replacement are not a new native lifetime or released capacity.
func NativePodReleaseTarget(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, observed model.NativeTerminationObservation, now time.Time) error {
	if p.HPAExecutionBinding == nil || p.AssessmentBinding == nil || observed.BindingName != p.HPAExecutionBinding.PodTerminationBinding || observed.Namespace != checkpoint.Namespace || observed.Namespace != p.AssessmentBinding.Snapshot.Namespace || observed.PodName != checkpoint.PodName || observed.ContainerName != checkpoint.ContainerName || observed.ContainerName != p.HPAExecutionBinding.ContainerName || observed.ImageDigest != checkpoint.ImageDigest || observed.ImageDigest != p.HPAExecutionBinding.ImageDigest || !Fresh(observed.ObservedAt, now, p.MaxEvidenceAgeSeconds) || observed.Protected {
		return fmt.Errorf("native release target is stale or outside the exact lifetime binding")
	}
	switch observed.State {
	case "absent":
		if observed.Reason == "native_name_absent" && observed.PodUID == "" {
			return nil
		}
	case "replaced":
		uid, err := uuid.Parse(observed.PodUID)
		if observed.Reason == "native_uid_replaced" && err == nil && uid != uuid.Nil && uid.String() == observed.PodUID && observed.PodUID != checkpoint.PodUID {
			return nil
		}
	case "unprotected":
		if observed.Reason == "native_capacity_finalizer_absent" && observed.ContainerState == "terminated" && observed.StartedAt != nil && observed.StartedAt.Equal(checkpoint.ContainerStartedAt) {
			witness, err := NativePodConfirmedTermination(p, checkpoint)
			if err == nil && nativePodMatchesProcess(p, checkpoint, observed, now) == nil && nativePodTerminationGeneration(p, checkpoint, observed) && observed.PodGeneration == witness.Observation.PodGeneration {
				return nil
			}
		}
	}
	return fmt.Errorf("native release lacks a fresh exact removal observation")
}

func nativeJoinTimestamp(joined, finished time.Time) bool {
	if joined.IsZero() || finished.IsZero() {
		return false
	}
	if finished.Nanosecond() == 0 {
		return !joined.Truncate(time.Second).After(finished)
	}
	return !joined.After(finished)
}
