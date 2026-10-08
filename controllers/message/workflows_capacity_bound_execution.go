package message

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

type capacityBoundPrivateCall func(model.CapacityObservationAdapterBinding, string, map[string]any, any) (string, error)

// The fixed invocation owns every read and command. Reservations and retained
// process lifetimes are separate: controllers select victims; Core never issues
// Pod DELETE. Hold invocations still reconcile every immutable lifetime origin.
func runCapacityBoundExecution(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, intent model.CapacityIntent, assessment model.CapacityAssessment, hpa model.CapacityHPAEnvelopeResponse, call capacityBoundPrivateCall) (model.CapacityIntent, error) {
	if p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode {
		return intent, errCapacityBoundAssessment
	}
	var err error
	if store.AdmissionOnly {
		intent, err = store.AcquireNativeAdmissionExecution(ctx, policy, hpa)
	} else {
		intent, err = store.AcquireNativeLifetimeExecution(ctx, policy, intent, assessment)
	}
	if err != nil {
		return intent, err
	}
	if err := store.ArchiveNativeTerminalHistory(ctx, policy, intent); err != nil {
		return intent, err
	}
	binding := p.AssessmentBinding.Snapshot.Adapter
	read := func(operation string, request any, out any) error {
		input, e := boundPrivateMap(request)
		if e != nil {
			return e
		}
		status, e := call(binding, operation, input, out)
		if e != nil || status != "observed" {
			return errCapacityBoundAssessment
		}
		return nil
	}
	observeHPA := func() (model.CapacityHPAEnvelopeResponse, error) {
		var out model.CapacityHPAEnvelopeResponse
		e := read(capacity.ObserveHPAEnvelope, map[string]any{"namespace": p.AssessmentBinding.Snapshot.Namespace, "hpa_name": p.AssessmentBinding.Snapshot.HPAName}, &out)
		return out, e
	}
	type inventoryView struct {
		Pods   []model.NativeTerminationObservation
		Native *model.AdapterCapacityPodInventoryResponse
	}
	inventory := func() (inventoryView, error) {
		if store.AdmissionOnly {
			var out model.AdapterCapacityPodAdmissionCandidatesResponse
			e := read(capacity.ObserveNativePodAdmissionCandidates, model.AdapterObserveCapacityPodInventoryRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding}, &out)
			if e != nil || capacity.NativeAdmissionCandidates(p, out, time.Now().UTC()) != nil {
				return inventoryView{}, errCapacityBoundAssessment
			}
			return inventoryView{Pods: out.Candidates}, nil
		}
		var out model.AdapterCapacityPodInventoryResponse
		e := read(capacity.ObserveNativePodInventory, model.AdapterObserveCapacityPodInventoryRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding}, &out)
		if e != nil || capacity.NativePodInventory(p, out, time.Now().UTC()) != nil {
			return inventoryView{}, errCapacityBoundAssessment
		}
		return inventoryView{Pods: out.Pods, Native: &out}, nil
	}
	observePod := func(cp model.CapacityNativePodCheckpoint) (model.AdapterCapacityPodTerminationResponse, error) {
		var out model.AdapterCapacityPodTerminationResponse
		req, e := boundPodObservationRequest(p, cp)
		if e == nil {
			e = read(capacity.ObserveNativePodTermination, req, &out)
		}
		return out, e
	}
	observeAdmission := func(pod model.NativeTerminationObservation) (model.AdapterCapacityPodAdmissionResponse, error) {
		var out model.AdapterCapacityPodAdmissionResponse
		if pod.StartedAt == nil {
			return out, errCapacityBoundAssessment
		}
		req := model.AdapterObserveCapacityPodAdmissionRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: pod.PodName, ExpectedPodUID: pod.PodUID, ExpectedPodGeneration: pod.PodGeneration, ExpectedContainerID: pod.ContainerID, ExpectedContainerStartedAt: *pod.StartedAt, ExpectedRestartCount: pod.RestartCount}
		e := read(capacity.ObserveNativePodAdmission, req, &out)
		if e != nil || capacity.NativeProcessAdmission(p, out, time.Now().UTC()) != nil {
			return out, errCapacityBoundAssessment
		}
		return out, nil
	}
	checkpointPod := func(cp model.CapacityNativePodCheckpoint) model.NativeTerminationObservation {
		start := cp.ContainerStartedAt
		return model.NativeTerminationObservation{PodName: cp.PodName, PodUID: cp.PodUID, PodGeneration: cp.PodGeneration, ContainerID: cp.ContainerID, StartedAt: &start, RestartCount: cp.RestartCount}
	}
	commands, checkpoints, err := store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return intent, err
	}
	findCheckpoint := func(uid string) (model.CapacityNativePodCheckpoint, bool) {
		for _, cp := range checkpoints {
			if cp.PodUID == uid {
				return cp, true
			}
		}
		return model.CapacityNativePodCheckpoint{}, false
	}
	// Old redeemed outcomes permit native GET and durable readback only. They
	// never acquire new send permission merely because a lease/generation moved.
	for _, command := range commands {
		if command.State == "confirmed" || command.State == "refused_no_redemption" {
			continue
		}
		if command.State == "issued" {
			if command.IntentGeneration != intent.Generation {
				return intent, fmt.Errorf("historical issued native outcome requires readonly recovery")
			}
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
			return intent, errCapacityBoundAssessment
		}
		var observed any
		if command.Operation == capacity.EnsureBoundHPAEnvelope {
			observed, err = observeHPA()
		} else {
			var target struct {
				UID string `json:"expected_pod_uid"`
			}
			if json.Unmarshal(command.Request, &target) != nil {
				return intent, errCapacityBoundAssessment
			}
			cp, ok := findCheckpoint(target.UID)
			if !ok {
				return intent, errCapacityBoundAssessment
			}
			if command.Phase == "admit" {
				observed, err = observeAdmission(checkpointPod(cp))
			} else {
				observed, err = observePod(cp)
			}
		}
		if err != nil {
			return intent, err
		}
		if err = store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, observed); err != nil {
			return intent, err
		}
	}
	commands, checkpoints, err = store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return intent, err
	}
	hasEnvelope := func() bool {
		for _, command := range commands {
			if command.IntentGeneration == intent.Generation && command.Operation == capacity.EnsureBoundHPAEnvelope && command.State == "confirmed" {
				return true
			}
		}
		return false
	}
	// A finite retry is possible only after the old token was atomically proven
	// unredeemed. Each subsequent request uses new actual native reads.
	execute := func(operation, subject string, request any, refresh func(any) (any, error), after func() (any, error)) error {
		for sequence := 0; sequence < 4; sequence++ {
			fresh, e := refresh(request)
			if e != nil {
				return e
			}
			request = fresh
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
			_, _ = call(binding, operation, input, &discarded)
			refused, e := store.RevokeUnredeemedNativeCommand(ctx, policy, intent, command.CommandID)
			if e != nil {
				return e
			}
			if refused {
				continue
			}
			if e = store.MarkNativeCommandUncertain(ctx, command.CommandID); e != nil {
				return e
			}
			observed, e := after()
			if e != nil {
				return e
			}
			if e = store.ConfirmNativeCommand(ctx, policy, intent, command.CommandID, observed); e != nil {
				return e
			}
			command.State = "confirmed"
			commands = append(commands, command)
			return nil
		}
		return fmt.Errorf("native phase exhausted four unredeemed permissions")
	}
	release := func(cp model.CapacityNativePodCheckpoint) error {
		observed, e := observePod(cp)
		if e != nil {
			return e
		}
		if capacity.NativePodWitness(p, cp, observed.Observation, time.Now().UTC()) != nil {
			return fmt.Errorf("current retained native termination remains unknown")
		}
		if e = store.ConfirmNativePodWitness(ctx, policy, intent, cp.PodUID, observed); e != nil {
			return e
		}
		cp.State, cp.PodResourceVersion = "confirmed", observed.Observation.PodResourceVersion
		base, e := boundPodObservationRequest(p, cp)
		if e != nil {
			return e
		}
		no := false
		req := model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: base, ExpectedPodResourceVersion: cp.PodResourceVersion, DryRun: &no}
		return execute(capacity.DestroyNativePodProtection, cp.PodUID, req, func(value any) (any, error) {
			request := value.(model.AdapterDestroyCapacityPodDrainProtectionRequest)
			actual, e := observePod(cp)
			if e != nil || capacity.NativePodWitness(p, cp, actual.Observation, time.Now().UTC()) != nil {
				return nil, errCapacityBoundAssessment
			}
			if e = store.ConfirmNativePodWitness(ctx, policy, intent, cp.PodUID, actual); e != nil {
				return nil, e
			}
			request.ExpectedPodResourceVersion = actual.Observation.PodResourceVersion
			return request, nil
		}, func() (any, error) { return observePod(cp) })
	}
	// First reconcile all controller-selected retirements, including origins
	// created by older reservation decisions. Unknown/lost lifetimes are retained.
	retirementPending := false
	for _, cp := range checkpoints {
		if cp.State == "released" || cp.State == "planned" {
			continue
		}
		actual, e := observePod(cp)
		if e != nil {
			return intent, e
		}
		if capacity.NativePodWitness(p, cp, actual.Observation, time.Now().UTC()) == nil {
			if e = release(cp); e != nil {
				return intent, e
			}
			continue
		}
		if actual.Observation.State != "running" || actual.Observation.DeletionRequestedAt != nil || capacity.NativePodMatchesCheckpoint(p, cp, actual.Observation, time.Now().UTC()) != nil || actual.Observation.StartedAt == nil || !actual.Observation.StartedAt.Equal(cp.ContainerStartedAt) {
			retirementPending = true
		}
	}
	if retirementPending && !store.AdmissionOnly {
		if intent.Decision.Action == "hold" {
			if err = store.CompleteNativeReservationDecision(ctx, policy, intent); err == nil {
				return store.Observe(ctx, policy)
			}
		}
		return intent, fmt.Errorf("retained native lifetime is retiring or unknown; no reservation mutation permitted")
	}
	current, err := inventory()
	if err != nil {
		return intent, err
	}
	_, checkpoints, err = store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return intent, err
	}
	for _, pod := range current.Pods {
		cp, exists := findCheckpoint(pod.PodUID)
		if !exists {
			boot, e := observeAdmission(pod)
			if e != nil {
				return intent, e
			}
			cp, e = store.RegisterNativeLifetime(ctx, policy, intent, boot)
			if e != nil {
				return intent, e
			}
			checkpoints = append(checkpoints, cp)
		}
		if cp.State == "released" {
			return intent, fmt.Errorf("released native UID reappeared; origin cannot be revived")
		}
		if capacity.NativePodMatchesCheckpoint(p, cp, pod, time.Now().UTC()) != nil || pod.StartedAt == nil || !pod.StartedAt.Equal(cp.ContainerStartedAt) || pod.DeletionRequestedAt != nil {
			return intent, fmt.Errorf("current native process differs from retained origin")
		}
		if cp.State == "planned" {
			req, e := boundPodDrainRequest(p, cp, "protect")
			if e != nil {
				return intent, e
			}
			e = execute(capacity.EnsureNativePodDrain, cp.PodUID, req, func(value any) (any, error) {
				request := value.(model.AdapterEnsureCapacityPodDrainRequest)
				actual, e := observeAdmission(checkpointPod(cp))
				if e != nil || actual.Admission.ProcessNonce != cp.ProcessNonce || actual.Admission.State != "waiting_projection" {
					return nil, errCapacityBoundAssessment
				}
				request.ExpectedPodResourceVersion = actual.Observation.PodResourceVersion
				return request, nil
			}, func() (any, error) { return observePod(cp) })
			if e != nil {
				return intent, e
			}
			cp.State = "protected"
		}
	}
	// Project the complete finite candidate roster before awaiting native file
	// refreshes. Only actual SDK observations authorize the second phase; the
	// enclosing protected invocation deadline returns unknown on expiry.
	_, checkpoints, err = store.NativeLedger(ctx, policy, intent)
	if err != nil {
		return intent, err
	}
	for _, pod := range current.Pods {
		cp, exists := findCheckpoint(pod.PodUID)
		if !exists || (cp.State != "protected" && cp.State != "admitted") {
			return intent, errCapacityBoundAssessment
		}
		var actual model.AdapterCapacityPodAdmissionResponse
		for {
			actual, err = observeAdmission(checkpointPod(cp))
			if err != nil {
				return intent, err
			}
			if actual.Admission.State == "roots_open" {
				break
			}
			if actual.Admission.State != "waiting_projection" && actual.Admission.State != "projection_observed" {
				return intent, errCapacityBoundAssessment
			}
			select {
			case <-ctx.Done():
				return intent, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if err = store.AcknowledgeNativeProjection(ctx, policy, intent, cp.PodUID, actual); err != nil {
			return intent, err
		}
		if cp.State == "protected" {
			cp.PodResourceVersion = actual.Observation.PodResourceVersion
			req, e := boundPodDrainRequest(p, cp, "admit")
			if e != nil {
				return intent, e
			}
			e = execute(capacity.EnsureNativePodDrain, cp.PodUID, req, func(value any) (any, error) {
				request := value.(model.AdapterEnsureCapacityPodDrainRequest)
				fresh, e := observeAdmission(checkpointPod(cp))
				if e != nil || capacity.NativeProcessAdmissionCheckpoint(p, cp, fresh, time.Now().UTC()) != nil || fresh.Admission.State != "roots_open" {
					return nil, errCapacityBoundAssessment
				}
				if e = store.AcknowledgeNativeProjection(ctx, policy, intent, cp.PodUID, fresh); e != nil {
					return nil, e
				}
				request.ExpectedPodResourceVersion = fresh.Observation.PodResourceVersion
				return request, nil
			}, func() (any, error) { return observeAdmission(checkpointPod(cp)) })
			if e != nil {
				return intent, e
			}
		}
	}
	// Re-read complete membership and every actual SDK admission at the HPA
	// boundary. Birth protection/readiness gates retain concurrent new Pods.
	qualifyBaseline := func(hpa model.CapacityHPAEnvelopeResponse) error {
		baseline, e := inventory()
		if e != nil {
			return e
		}
		_, checkpoints, e = store.NativeLedger(ctx, policy, intent)
		if e != nil {
			return e
		}
		acks := map[string]model.AdapterCapacityPodAdmissionResponse{}
		for _, pod := range baseline.Pods {
			cp, ok := findCheckpoint(pod.PodUID)
			if !ok || cp.State != "admitted" {
				return errCapacityBoundAssessment
			}
			actual, e := observeAdmission(pod)
			if e != nil || capacity.NativeProcessAdmissionCheckpoint(p, cp, actual, time.Now().UTC()) != nil || !actual.Observation.AdmissionReady {
				return errCapacityBoundAssessment
			}
			acks[pod.PodUID] = actual
		}
		if baseline.Native == nil {
			return errCapacityBoundAssessment
		}
		return store.PlanNativeReservationEnvelope(ctx, policy, intent, hpa, *baseline.Native, acks)
	}
	if !store.AdmissionOnly && intent.Decision.Action != "hold" && !hasEnvelope() {
		hpa, err = observeHPA()
		if err != nil {
			return intent, err
		}
		if err = qualifyBaseline(hpa); err != nil {
			return intent, err
		}
		intent.NativeHPAGeneration = hpa.Observation.EnvelopeGeneration + 1
		if intent.NativeHPAGeneration < intent.Generation {
			intent.NativeHPAGeneration = intent.Generation
		}
		no := false
		mode := "upshift"
		if intent.Decision.Units < hpa.Observation.MinReplicas {
			mode = "downshift"
		}
		req := model.CapacityNativeHPARequest{Namespace: p.AssessmentBinding.Snapshot.Namespace, HPAName: p.AssessmentBinding.Snapshot.HPAName, ExpectedUID: hpa.Observation.HPAUID, ExpectedResourceVersion: hpa.Observation.ResourceVersion, ExpectedWorkloadUID: hpa.Observation.WorkloadUID, ExpectedWorkloadResourceVersion: hpa.Observation.WorkloadResourceVersion, Owner: p.AssessmentBinding.Snapshot.Owner, Generation: intent.NativeHPAGeneration, IdempotencyKey: fmt.Sprintf("native:%s:%d", policy.ID, intent.Generation), MinReplicas: intent.Decision.Units, MaxReplicas: hpa.Observation.MaxReplicas, Adopt: hpa.Observation.Owner == "", DryRun: &no, Mode: mode}
		err = execute(capacity.EnsureBoundHPAEnvelope, req.ExpectedUID, req, func(value any) (any, error) {
			request := value.(model.CapacityNativeHPARequest)
			freshHPA, e := observeHPA()
			if e != nil || freshHPA.Observation.EnvelopeGeneration >= intent.NativeHPAGeneration {
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
			fresh.Snapshot, e = capacity.BoundHPASnapshot(p, freshHPA, time.Now().UTC())
			if e != nil || capacity.ValidateAssessment(p, fresh, time.Now().UTC()) != nil {
				return nil, errCapacityBoundAssessment
			}
			decision, e := capacity.Assess(p, fresh, intent.Decision.Clock, time.Now().UTC())
			if e != nil || decision.Action != intent.Decision.Action || decision.Units != intent.Decision.Units {
				return nil, errCapacityBoundAssessment
			}
			if e = qualifyBaseline(freshHPA); e != nil {
				return nil, e
			}
			request.ExpectedResourceVersion, request.ExpectedWorkloadResourceVersion = freshHPA.Observation.ResourceVersion, freshHPA.Observation.WorkloadResourceVersion
			return request, nil
		}, func() (any, error) { return observeHPA() })
		if err != nil {
			return intent, err
		}
	}
	if err = store.CompleteNativeReservationDecision(ctx, policy, intent); err != nil {
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
func boundPodObservationRequest(p model.CapacityPolicySpec, cp model.CapacityNativePodCheckpoint) (model.AdapterObserveCapacityPodTerminationRequest, error) {
	var challenge model.NativePodTerminationChallenge
	if json.Unmarshal(cp.Challenge, &challenge) != nil {
		return model.AdapterObserveCapacityPodTerminationRequest{}, errCapacityBoundAssessment
	}
	return model.AdapterObserveCapacityPodTerminationRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: cp.PodGeneration, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: challenge}, nil
}
func boundPodDrainRequest(p model.CapacityPolicySpec, cp model.CapacityNativePodCheckpoint, phase string) (model.AdapterEnsureCapacityPodDrainRequest, error) {
	base, err := boundPodObservationRequest(p, cp)
	no := false
	return model.AdapterEnsureCapacityPodDrainRequest{BindingName: base.BindingName, PodName: base.PodName, ExpectedPodUID: base.ExpectedPodUID, ExpectedPodGeneration: base.ExpectedPodGeneration, ExpectedPodResourceVersion: cp.PodResourceVersion, ExpectedContainerID: base.ExpectedContainerID, ExpectedContainerStartedAt: base.ExpectedContainerStartedAt, ExpectedRestartCount: base.ExpectedRestartCount, Challenge: base.Challenge, Phase: phase, DryRun: &no}, err
}
