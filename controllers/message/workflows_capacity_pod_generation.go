package message

import (
	"context"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// The adapter retains its exact-generation contract. If the immutable birth
// generation no longer reads, make at most one read for Kubernetes' first DELETE
// generation. This is not a new send permission or a rewritten checkpoint.
func observeBoundPodTermination(p model.CapacityPolicySpec, cp model.CapacityNativePodCheckpoint, read func(string, any, any) error) (model.AdapterCapacityPodTerminationResponse, error) {
	var out model.AdapterCapacityPodTerminationResponse
	req, err := boundPodObservationRequest(p, cp)
	if err != nil {
		return out, err
	}
	if err = read(capacity.ObserveNativePodTermination, req, &out); err == nil {
		return out, nil
	}
	if p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode || cp.PodGeneration < 1 || cp.PodGeneration == int64(1<<63-1) {
		return out, err
	}
	req.ExpectedPodGeneration++
	var retired model.AdapterCapacityPodTerminationResponse
	if err = read(capacity.ObserveNativePodTermination, req, &retired); err != nil {
		return retired, err
	}
	now := time.Now().UTC()
	_, retainedErr := capacity.NativePodConfirmedTermination(p, cp)
	if retired.Operation != capacity.ObserveNativePodTermination || retired.Status != "observed" || (capacity.NativePodWitness(p, cp, retired.Observation, now) != nil && (retainedErr != nil || capacity.NativePodReleaseTarget(p, cp, retired.Observation, now) != nil)) {
		return retired, errCapacityBoundAssessment
	}
	return retired, nil
}

// Confirmation writes the original witness and its actual database timestamp.
// Reload that durable record rather than synthesizing local confirmation facts.
func reloadConfirmedBoundPod(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, origin model.CapacityNativePodCheckpoint) (model.CapacityNativePodCheckpoint, error) {
	_, checkpoints, err := store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return model.CapacityNativePodCheckpoint{}, err
	}
	for _, cp := range checkpoints {
		if cp.PodUID != origin.PodUID {
			continue
		}
		witness, err := capacity.NativePodConfirmedTermination(p, cp)
		if err != nil || cp.State != "confirmed" || cp.PodGeneration != origin.PodGeneration || capacity.NativePodWitness(p, origin, witness.Observation, time.Now().UTC()) != nil {
			return model.CapacityNativePodCheckpoint{}, errCapacityBoundAssessment
		}
		return cp, nil
	}
	return model.CapacityNativePodCheckpoint{}, errCapacityBoundAssessment
}

func boundPodReleaseRequest(p model.CapacityPolicySpec, cp model.CapacityNativePodCheckpoint, now time.Time) (model.AdapterDestroyCapacityPodDrainProtectionRequest, error) {
	witness, err := capacity.NativePodConfirmedTermination(p, cp)
	if err != nil || cp.State != "confirmed" || capacity.NativePodWitness(p, cp, witness.Observation, now) != nil {
		return model.AdapterDestroyCapacityPodDrainProtectionRequest{}, errCapacityBoundAssessment
	}
	base, err := boundPodObservationRequest(p, cp)
	if err != nil {
		return model.AdapterDestroyCapacityPodDrainProtectionRequest{}, err
	}
	base.ExpectedPodGeneration = witness.Observation.PodGeneration
	no := false
	return model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: base, ExpectedPodResourceVersion: witness.Observation.PodResourceVersion, DryRun: &no}, nil
}
