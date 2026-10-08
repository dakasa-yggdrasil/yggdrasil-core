package capacity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"sort"
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
	if b == nil || s == nil || err != nil || id.String() != pod.PodUID || pod.PodName == "" || pod.PodGeneration < 0 || pod.PodResourceVersion == "" || pod.Namespace != s.Snapshot.Namespace || pod.WorkloadUID != s.Snapshot.WorkloadUID || pod.ContainerName != b.ContainerName || pod.ContainerID == "" || pod.ImageDigest != b.ImageDigest || pod.RestartCount < 0 || !Fresh(pod.ObservedAt, now, p.MaxEvidenceAgeSeconds) {
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
	if NativePodIdentity(p, observed, now) != nil || observed.PodUID != checkpoint.PodUID || observed.PodName != checkpoint.PodName || observed.PodGeneration != checkpoint.PodGeneration || observed.ContainerID != checkpoint.ContainerID || observed.RestartCount != checkpoint.RestartCount || observed.ImageDigest != checkpoint.ImageDigest {
		return fmt.Errorf("native lifetime differs from private checkpoint")
	}
	return nil
}
func NativePodWitness(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, observed model.NativeTerminationObservation, now time.Time) error {
	if NativePodMatchesCheckpoint(p, checkpoint, observed, now) != nil || !observed.Protected || observed.State != "terminated" || observed.ContainerState != "terminated" || observed.ExitCode == nil || *observed.ExitCode != 0 || observed.Signal == nil || *observed.Signal != 0 || observed.StartedAt == nil || !observed.StartedAt.Equal(checkpoint.ContainerStartedAt) || observed.FinishedAt == nil || observed.DeletionRequestedAt == nil || observed.Receipt == nil {
		return fmt.Errorf("current successful native termination unavailable")
	}
	var challenge model.NativePodTerminationChallenge
	if json.Unmarshal(checkpoint.Challenge, &challenge) != nil {
		return fmt.Errorf("private challenge unavailable")
	}
	receipt := observed.Receipt
	rawExpected, _ := json.Marshal(challenge)
	rawActual, _ := json.Marshal(receipt.NativePodTerminationChallenge)
	if string(rawExpected) != string(rawActual) || receipt.IntentGeneration != checkpoint.IntentGeneration || receipt.DrainNonce != checkpoint.DrainNonce || receipt.LaneRosterSHA256 != NativeRosterDigest(p.HPAExecutionBinding.Lanes) || receipt.JoinedAt.Before(challenge.IssuedAt) || receipt.JoinedAt.After(*observed.FinishedAt) || len(receipt.Lanes) != len(p.HPAExecutionBinding.Lanes) || len(observed.ReceiptSHA256) != 64 {
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
