package message

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"sort"
	"time"
)

type capacityBoundPrivateCall func(model.CapacityObservationAdapterBinding, string, map[string]any, any) (string, error)

// All targets, reads, challenges and requests are constructed in this private
// invocation. Workflow input supplies only the logical policy reference.
func runCapacityBoundExecution(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, assessment model.CapacityAssessment, hpa model.CapacityHPAEnvelopeResponse, call capacityBoundPrivateCall) (model.CapacityIntent, error) {
	if intent.Phase == "hold" || intent.Phase == "native_completed" {
		return intent, nil
	}
	var err error
	if intent.Phase == "proposed" {
		intent, err = store.Claim(ctx, policy, intent.Generation, assessment)
	} else {
		intent, err = store.ResumeNativeExecution(ctx, policy, intent.Generation)
	}
	if err != nil {
		return intent, err
	}
	binding := p.AssessmentBinding.Snapshot.Adapter
	observeHPA := func() (model.CapacityHPAEnvelopeResponse, error) {
		var response model.CapacityHPAEnvelopeResponse
		status, e := call(binding, capacity.ObserveHPAEnvelope, map[string]any{"namespace": p.AssessmentBinding.Snapshot.Namespace, "hpa_name": p.AssessmentBinding.Snapshot.HPAName}, &response)
		if e != nil || status != "observed" {
			return response, errCapacityBoundAssessment
		}
		return response, nil
	}
	observePod := func(checkpoint model.CapacityNativePodCheckpoint) (model.AdapterCapacityPodTerminationResponse, error) {
		var response model.AdapterCapacityPodTerminationResponse
		request, e := boundPodObservationRequest(p, checkpoint)
		if e != nil {
			return response, e
		}
		input, e := boundPrivateMap(request)
		if e != nil {
			return response, e
		}
		status, e := call(binding, capacity.ObserveNativePodTermination, input, &response)
		if e != nil || status != "observed" {
			return response, errCapacityBoundAssessment
		}
		return response, nil
	}
	inventory := func() (model.AdapterCapacityPodInventoryResponse, error) {
		var response model.AdapterCapacityPodInventoryResponse
		status, e := call(binding, capacity.ObserveNativePodInventory, map[string]any{"binding_name": p.HPAExecutionBinding.PodTerminationBinding}, &response)
		if e != nil || status != "observed" || capacity.NativePodInventory(p, response, time.Now().UTC()) != nil {
			return response, errCapacityBoundAssessment
		}
		return response, nil
	}
	commands, checkpoints, err := store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return intent, err
	}
	// No new command is issued while any old send outcome is unresolved.
	for _, command := range commands {
		if command.State == "confirmed" || command.State == "refused_no_redemption" {
			continue
		}
		if command.State == "issued" {
			refused, e := store.RevokeUnredeemedNativeCommand(ctx, policy, intent, command.CommandID)
			if e != nil {
				return intent, e
			}
			if refused {
				continue
			}
			command.State = "redeemed"
		}
		if command.State != "redeemed" && command.State != "uncertain" {
			return intent, fmt.Errorf("native command requires readonly reconciliation")
		}
		if command.Operation == capacity.EnsureBoundHPAEnvelope {
			observed, e := observeHPA()
			if e != nil {
				return intent, e
			}
			err = store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, observed)
		} else {
			var expected struct {
				ExpectedPodUID string `json:"expected_pod_uid"`
			}
			if json.Unmarshal(command.Request, &expected) != nil {
				return intent, errCapacityBoundAssessment
			}
			found := false
			for _, checkpoint := range checkpoints {
				if checkpoint.PodUID == expected.ExpectedPodUID {
					found = true
					observed, e := observePod(checkpoint)
					if e != nil {
						return intent, e
					}
					err = store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, observed)
					break
				}
			}
			if !found {
				return intent, errCapacityBoundAssessment
			}
		}
		if err != nil {
			return intent, err
		}
	}
	commands, checkpoints, err = store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return intent, err
	}
	hasCommand := func(operation, phase, uid string) bool {
		for _, c := range commands {
			if c.State == "confirmed" && c.Operation == operation && c.Phase == phase {
				if operation == capacity.EnsureBoundHPAEnvelope {
					return true
				}
				var req struct {
					ExpectedPodUID string `json:"expected_pod_uid"`
				}
				if json.Unmarshal(c.Request, &req) == nil && req.ExpectedPodUID == uid {
					return true
				}
			}
		}
		return false
	}
	refreshRequest := func(request any, observation any) (any, error) {
		switch req := request.(type) {
		case model.CapacityNativeHPARequest:
			observed, ok := observation.(model.CapacityHPAEnvelopeResponse)
			if !ok || observed.Observation.EnvelopeGeneration >= intent.NativeHPAGeneration {
				return nil, errCapacityBoundAssessment
			}
			fresh := model.CapacityAssessment{}
			for _, signal := range p.AssessmentBinding.Signals {
				var metric model.CapacityMetricRangeObservation
				status, e := call(signal.Adapter, capacity.ObserveMetricRange, map[string]any{"binding": signal.BindingName}, &metric)
				if e != nil || status != "succeeded" {
					return nil, errCapacityBoundAssessment
				}
				evidence, e := capacity.BoundMetricEvidence(p, signal, metric, time.Now().UTC())
				if e != nil {
					return nil, e
				}
				fresh.Evidence = append(fresh.Evidence, evidence)
			}
			var e error
			fresh.Snapshot, e = capacity.BoundHPASnapshot(p, observed, time.Now().UTC())
			if e != nil || capacity.ValidateAssessment(p, fresh, time.Now().UTC()) != nil {
				return nil, errCapacityBoundAssessment
			}
			decision, e := capacity.Assess(p, fresh, intent.Decision.Clock, time.Now().UTC())
			if e != nil || decision.Action != intent.Decision.Action || decision.Units != intent.Decision.Units {
				return nil, errCapacityBoundAssessment
			}
			req.ExpectedResourceVersion, req.ExpectedWorkloadResourceVersion = observed.Observation.ResourceVersion, observed.Observation.WorkloadResourceVersion
			return req, nil
		case model.AdapterEnsureCapacityPodDrainRequest:
			observed, ok := observation.(model.AdapterCapacityPodTerminationResponse)
			if !ok {
				return nil, errCapacityBoundAssessment
			}
			pod := observed.Observation
			if req.Phase == "protect" {
				fresh, e := inventory()
				if e != nil {
					return nil, e
				}
				found := false
				for _, current := range fresh.Pods {
					if current.PodUID == req.ExpectedPodUID {
						pod, found = current, true
					}
				}
				if !found {
					return nil, errCapacityBoundAssessment
				}
			}
			for _, checkpoint := range checkpoints {
				if checkpoint.PodUID == req.ExpectedPodUID {
					if capacity.NativePodMatchesCheckpoint(p, checkpoint, pod, time.Now().UTC()) != nil || pod.ContainerState != "running" || pod.StartedAt == nil || !pod.StartedAt.Equal(checkpoint.ContainerStartedAt) || pod.DeletionRequestedAt != nil || (req.Phase == "terminate" && !pod.Protected) {
						return nil, errCapacityBoundAssessment
					}
					req.ExpectedPodResourceVersion = pod.PodResourceVersion
					return req, nil
				}
			}
		case model.AdapterDestroyCapacityPodDrainProtectionRequest:
			observed, ok := observation.(model.AdapterCapacityPodTerminationResponse)
			if !ok {
				return nil, errCapacityBoundAssessment
			}
			for _, checkpoint := range checkpoints {
				if checkpoint.PodUID == req.ExpectedPodUID {
					if capacity.NativePodWitness(p, checkpoint, observed.Observation, time.Now().UTC()) != nil {
						return nil, errCapacityBoundAssessment
					}
					if e := store.ConfirmNativePodWitness(ctx, policy, intent, checkpoint.PodUID, observed); e != nil {
						return nil, e
					}
					req.ExpectedPodResourceVersion = observed.Observation.PodResourceVersion
					return req, nil
				}
			}
		}
		return nil, errCapacityBoundAssessment
	}
	execute := func(operation, subject string, request any, observe func() (any, error)) error {
		for sequence := 0; sequence < 4; sequence++ {
			observed, e := observe()
			if e != nil {
				return e
			}
			request, e = refreshRequest(request, observed)
			if e != nil {
				return e
			}
			input, e := boundPrivateMap(request)
			if e != nil {
				return e
			}
			raw, e := json.Marshal(input)
			if e != nil {
				return e
			}
			command, token, e := store.IssueNativeCommand(ctx, policy, intent, operation, subject, raw)
			if e != nil {
				return e
			}
			input["authority_token"] = token
			var discarded map[string]any
			// A transport result is not a native mutation result. Always reconcile with
			// an independent fixed native read, including after a lost RPC response.
			_, sendErr := call(binding, operation, input, &discarded)
			_ = sendErr
			refused, e := store.RevokeUnredeemedNativeCommand(ctx, policy, intent, command.CommandID)
			if e != nil {
				return e
			}
			if refused {
				continue
			}
			if e := store.MarkNativeCommandUncertain(ctx, command.CommandID); e != nil {
				return e
			}
			observed, e = observe()
			if e != nil {
				return e
			}
			if e := store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, observed); e != nil {
				return e
			}
			command.State = "confirmed"
			commands = append(commands, command)
			return nil
		}
		return fmt.Errorf("native phase exhausted its finite unredeemed permissions")
	}
	if intent.NativePodBaseline == nil {
		baseline, e := inventory()
		if e != nil {
			return intent, e
		}

		for _, pod := range baseline.Pods {
			intent.NativePodBaseline = append(intent.NativePodBaseline, pod.PodUID)
		}
		// A reservation reduction selects a bounded set of existing lifetimes.
		// The complete baseline remains retained so unobserved controller removals
		// block completion. New Deployment replacements are not released capacity.
		count := intent.BaselineSnapshot.Units - intent.Decision.Units
		if count > 0 {
			running := []model.NativeTerminationObservation{}
			for _, pod := range baseline.Pods {
				if pod.State == "running" && pod.DeletionRequestedAt == nil {
					running = append(running, pod)
				}
			}
			if count > len(running)-p.AssessmentBinding.Snapshot.ProtectedFloor {
				return intent, errCapacityBoundAssessment
			}
			sort.Slice(running, func(i, j int) bool { return running[i].PodUID < running[j].PodUID })
			for _, pod := range running[:count] {
				challenge, e := capacity.NativePodChallenge(p, intent, pod, time.Now().UTC())
				if e != nil {
					return intent, e
				}
				raw, _ := json.Marshal(challenge)
				checkpoint := model.CapacityNativePodCheckpoint{Namespace: pod.Namespace, PodName: pod.PodName, PodUID: pod.PodUID, PodResourceVersion: pod.PodResourceVersion, PodGeneration: pod.PodGeneration, WorkloadUID: pod.WorkloadUID, ContainerName: pod.ContainerName, ContainerID: pod.ContainerID, ContainerStartedAt: *pod.StartedAt, ImageDigest: pod.ImageDigest, RestartCount: pod.RestartCount, IntentGeneration: intent.Generation, DrainNonce: challenge.DrainNonce, Challenge: raw, State: "planned"}

				checkpoints = append(checkpoints, checkpoint)
			}
		}
		if e := store.SaveNativePodPlan(ctx, policy, intent, baseline, hpa, checkpoints); e != nil {
			return intent, e
		}
		intent.NativeHPAGeneration = hpa.Observation.EnvelopeGeneration + 1
		if intent.NativeHPAGeneration < intent.Generation {
			intent.NativeHPAGeneration = intent.Generation
		}
	}
	for index, checkpoint := range checkpoints {
		if checkpoint.State != "planned" {
			continue
		}
		request, e := boundPodDrainRequest(p, checkpoint, "protect")
		if e != nil {
			return intent, e
		}
		if hasCommand(capacity.EnsureNativePodDrain, "protect", checkpoint.PodUID) {
			return intent, errCapacityBoundAssessment
		}
		if e := execute(capacity.EnsureNativePodDrain, checkpoint.PodUID, request, func() (any, error) { return observePod(checkpoint) }); e != nil {
			return intent, e
		}
		checkpoint.State = "protected"
		observed, e := observePod(checkpoint)
		if e != nil {
			return intent, e
		}
		checkpoint.PodResourceVersion = observed.Observation.PodResourceVersion
		checkpoints[index] = checkpoint
	}
	if !hasCommand(capacity.EnsureBoundHPAEnvelope, "envelope", "") {
		hpa, err = observeHPA()
		if err != nil {
			return intent, err
		}
		snapshot, err := capacity.BoundHPASnapshot(p, hpa, time.Now().UTC())
		if err != nil {
			return intent, err
		}
		// Revalidate pressure at the actual mutation boundary; changed pressure
		// never grants a stale new reduction during recovery.
		assessment.Snapshot = snapshot
		if capacity.ValidateAssessment(p, assessment, time.Now().UTC()) != nil {
			return intent, errCapacityBoundAssessment
		}
		decision, e := capacity.Assess(p, assessment, intent.Decision.Clock, time.Now().UTC())
		if e != nil || decision.Action != intent.Decision.Action || decision.Units != intent.Decision.Units {
			return intent, errCapacityBoundAssessment
		}
		no := false
		mode := "upshift"
		if intent.Decision.Units < hpa.Observation.MinReplicas {
			mode = "downshift"
		}
		req := model.CapacityNativeHPARequest{Namespace: p.AssessmentBinding.Snapshot.Namespace, HPAName: p.AssessmentBinding.Snapshot.HPAName, ExpectedUID: hpa.Observation.HPAUID, ExpectedResourceVersion: hpa.Observation.ResourceVersion, ExpectedWorkloadUID: hpa.Observation.WorkloadUID, ExpectedWorkloadResourceVersion: hpa.Observation.WorkloadResourceVersion, Owner: p.AssessmentBinding.Snapshot.Owner, Generation: intent.NativeHPAGeneration, IdempotencyKey: fmt.Sprintf("native:%s:%d", policy.ID, intent.Generation), MinReplicas: intent.Decision.Units, MaxReplicas: hpa.Observation.MaxReplicas, Adopt: hpa.Observation.Owner == "", DryRun: &no, Mode: mode}
		if e := execute(capacity.EnsureBoundHPAEnvelope, req.ExpectedUID, req, func() (any, error) { return observeHPA() }); e != nil {
			return intent, e
		}
	}
	_, checkpoints, err = store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return intent, err
	}
	for _, checkpoint := range checkpoints {
		if checkpoint.State == "released" {
			continue
		}
		observed, e := observePod(checkpoint)
		if e != nil {
			return intent, e
		}
		if checkpoint.State == "protected" {
			checkpoint.PodResourceVersion = observed.Observation.PodResourceVersion
			req, e := boundPodDrainRequest(p, checkpoint, "terminate")
			if e != nil {
				return intent, e
			}
			if e := execute(capacity.EnsureNativePodDrain, checkpoint.PodUID, req, func() (any, error) { return observePod(checkpoint) }); e != nil {
				return intent, e
			}
			checkpoint.State = "terminating"
		}
		for checkpoint.State == "terminating" {
			observed, e = observePod(checkpoint)
			if e != nil {
				return intent, e
			}
			if capacity.NativePodWitness(p, checkpoint, observed.Observation, time.Now().UTC()) == nil {
				if e := store.ConfirmNativePodWitness(ctx, policy, intent, checkpoint.PodUID, observed); e != nil {
					return intent, e
				}
				checkpoint.State = "confirmed"
				checkpoint.PodResourceVersion = observed.Observation.PodResourceVersion
				break
			}
			select {
			case <-ctx.Done():
				return intent, fmt.Errorf("native current lifetime remains unknown")
			case <-time.After(time.Second):
			}
		}
		if checkpoint.State == "confirmed" {
			// Refresh the exact current terminated resourceVersion before permission.
			observed, e = observePod(checkpoint)
			if e != nil {
				return intent, e
			}
			if e := store.ConfirmNativePodWitness(ctx, policy, intent, checkpoint.PodUID, observed); e != nil {
				return intent, e
			}
			checkpoint.PodResourceVersion = observed.Observation.PodResourceVersion
			base, e := boundPodObservationRequest(p, checkpoint)
			if e != nil {
				return intent, e
			}
			no := false
			request := model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: base, ExpectedPodResourceVersion: checkpoint.PodResourceVersion, DryRun: &no}
			if e := execute(capacity.DestroyNativePodProtection, checkpoint.PodUID, request, func() (any, error) { return observePod(checkpoint) }); e != nil {
				return intent, e
			}
		}
	}
	finalInventory, err := inventory()
	if err != nil {
		return intent, err
	}
	if err := store.CompleteNativeExecution(ctx, policy, intent, finalInventory); err != nil {
		return intent, err
	}
	return store.Observe(ctx, policy)
}
func boundPrivateMap(value any) (map[string]any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = json.Unmarshal(raw, &out)
	delete(out, "authority_token")
	return out, err
}
func boundPodObservationRequest(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint) (model.AdapterObserveCapacityPodTerminationRequest, error) {
	var challenge model.NativePodTerminationChallenge
	if json.Unmarshal(checkpoint.Challenge, &challenge) != nil {
		return model.AdapterObserveCapacityPodTerminationRequest{}, errCapacityBoundAssessment
	}
	return model.AdapterObserveCapacityPodTerminationRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: checkpoint.PodName, ExpectedPodUID: checkpoint.PodUID, ExpectedPodGeneration: checkpoint.PodGeneration, ExpectedContainerID: checkpoint.ContainerID, ExpectedContainerStartedAt: checkpoint.ContainerStartedAt, ExpectedRestartCount: checkpoint.RestartCount, Challenge: challenge}, nil
}
func boundPodDrainRequest(p model.CapacityPolicySpec, checkpoint model.CapacityNativePodCheckpoint, phase string) (model.AdapterEnsureCapacityPodDrainRequest, error) {
	base, err := boundPodObservationRequest(p, checkpoint)
	no := false
	return model.AdapterEnsureCapacityPodDrainRequest{BindingName: base.BindingName, PodName: base.PodName, ExpectedPodUID: base.ExpectedPodUID, ExpectedPodGeneration: base.ExpectedPodGeneration, ExpectedPodResourceVersion: checkpoint.PodResourceVersion, ExpectedContainerID: base.ExpectedContainerID, ExpectedContainerStartedAt: base.ExpectedContainerStartedAt, ExpectedRestartCount: base.ExpectedRestartCount, Challenge: base.Challenge, Phase: phase, DryRun: &no}, err
}
