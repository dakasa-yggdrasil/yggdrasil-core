package message

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func capacityDeleteGenerationFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityNativePodCheckpoint, model.AdapterCapacityPodTerminationResponse, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	started, finished, deleted := now.Add(-time.Minute), now.Add(-time.Second), now.Add(-2*time.Second)
	zero := int32(0)
	p := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 60, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Namespace: "native", WorkloadUID: uuid.NewString()}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{Mode: capacity.HPALifetimeExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"workers"}}}
	challenge := model.NativePodTerminationChallenge{SchemaVersion: 2, Namespace: "native", PodName: "api", PodUID: uuid.NewString(), WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, ContainerName: "api", ImageDigest: p.HPAExecutionBinding.ImageDigest, IntentGeneration: 1, DrainNonce: uuid.NewString(), ProcessNonce: uuid.NewString(), IssuedAt: now.Add(-30 * time.Second), LaneRosterSHA256: capacity.NativeRosterDigest(p.HPAExecutionBinding.Lanes)}
	raw, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	cp := model.CapacityNativePodCheckpoint{Namespace: challenge.Namespace, PodName: challenge.PodName, PodUID: challenge.PodUID, PodGeneration: 1, WorkloadUID: challenge.WorkloadUID, ContainerName: challenge.ContainerName, ContainerID: "containerd://current", ContainerStartedAt: started, ImageDigest: challenge.ImageDigest, IntentGeneration: 1, DrainNonce: challenge.DrainNonce, ProcessNonce: challenge.ProcessNonce, Challenge: raw, State: "admitted"}
	pod := model.NativeTerminationObservation{BindingName: "api-native", Namespace: cp.Namespace, PodName: cp.PodName, PodUID: cp.PodUID, PodGeneration: 2, PodResourceVersion: "13", WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ContainerName: cp.ContainerName, ContainerID: cp.ContainerID, ImageID: "fixture@" + cp.ImageDigest, ImageDigest: cp.ImageDigest, ContainerState: "terminated", ExitCode: &zero, Signal: &zero, StartedAt: &started, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, State: "terminated", Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: finished, Lanes: map[string]string{"workers": "done"}, RootAdmission: "previously_opened"}, ReceiptSHA256: strings.Repeat("b", 64), ObservedAt: now}
	return p, cp, model.AdapterCapacityPodTerminationResponse{Operation: capacity.ObserveNativePodTermination, Status: "observed", Observation: pod}, now
}

func TestBoundPodDeleteGenerationReadIsBoundedAndRequiresWitness(t *testing.T) {
	for _, name := range []string{"first_delete", "birth_read_succeeds", "running", "unknown", "not_deleting", "missing_receipt", "wrong_challenge", "wrong_generation", "wrong_container", "restarted", "stale", "fallback_read_failure", "zero_birth", "overflow_birth", "unprotected_without_witness", "unprotected_confirmed", "absent_without_witness", "absent_confirmed"} {
		t.Run(name, func(t *testing.T) {
			p, cp, reply, now := capacityDeleteGenerationFixture(t)
			if name == "unprotected_confirmed" || name == "absent_confirmed" {
				cp.State, cp.ConfirmedAt, cp.PodResourceVersion = "confirmed", &now, reply.Observation.PodResourceVersion
				cp.NativeTerminationReceipt, _ = json.Marshal(reply)
			}
			switch name {
			case "birth_read_succeeds":
				reply.Observation.PodGeneration = 1
			case "running":
				reply.Observation.State, reply.Observation.ContainerState = "running", "running"
			case "unknown":
				reply.Observation.State = "unknown"
			case "not_deleting":
				reply.Observation.DeletionRequestedAt = nil
			case "missing_receipt":
				reply.Observation.Receipt = nil
			case "wrong_challenge":
				reply.Observation.Receipt.DrainNonce = uuid.NewString()
			case "wrong_generation":
				reply.Observation.PodGeneration = 3
			case "wrong_container":
				reply.Observation.ContainerID = "containerd://replacement"
			case "restarted":
				reply.Observation.RestartCount++
			case "stale":
				reply.Observation.ObservedAt = now.Add(-61 * time.Second)
			case "zero_birth":
				cp.PodGeneration = 0
			case "overflow_birth":
				cp.PodGeneration = int64(1<<63 - 1)
			case "unprotected_without_witness", "unprotected_confirmed":
				reply.Observation.Protected, reply.Observation.State, reply.Observation.Reason, reply.Observation.Receipt = false, "unprotected", "native_capacity_finalizer_absent", nil
			case "absent_without_witness", "absent_confirmed":
				reply.Observation.Protected, reply.Observation.State, reply.Observation.Reason, reply.Observation.PodUID = false, "absent", "native_name_absent", ""
			}
			birth := cp.PodGeneration
			reads := 0
			read := func(operation string, request any, out any) error {
				reads++
				req := request.(model.AdapterObserveCapacityPodTerminationRequest)
				if operation != capacity.ObserveNativePodTermination || req.ExpectedPodUID != cp.PodUID || req.ExpectedContainerID != cp.ContainerID || !req.ExpectedContainerStartedAt.Equal(cp.ContainerStartedAt) || req.ExpectedRestartCount != cp.RestartCount {
					t.Fatal("read widened the immutable process target")
				}
				if reads == 1 && req.ExpectedPodGeneration != birth || reads == 2 && req.ExpectedPodGeneration != birth+1 {
					t.Fatal("read did not use the original and exact first DELETE generations")
				}
				if name != "birth_read_succeeds" && reads == 1 || name == "fallback_read_failure" {
					return errors.New("exact adapter generation refused")
				}
				*out.(*model.AdapterCapacityPodTerminationResponse) = reply
				return nil
			}
			result, err := observeBoundPodTermination(p, cp, read)
			want := name == "first_delete" || name == "birth_read_succeeds" || name == "unprotected_confirmed" || name == "absent_confirmed"
			if (err == nil) != want {
				t.Fatal("unexpected bounded read decision", name, err)
			}
			expectedReads := 2
			if name == "birth_read_succeeds" || name == "zero_birth" || name == "overflow_birth" {
				expectedReads = 1
			}
			if reads != expectedReads || cp.PodGeneration != birth || want && result.Observation.PodGeneration != reply.Observation.PodGeneration {
				t.Fatal("read budget, original generation or actual observation changed")
			}
		})
	}
}

func TestBoundReleaseUsesFreshPersistedTerminationGeneration(t *testing.T) {
	for _, name := range []string{"actual_delete_generation", "missing_witness", "missing_confirmation", "stale_witness", "wrong_version", "wrong_generation", "released_checkpoint"} {
		t.Run(name, func(t *testing.T) {
			p, cp, witness, now := capacityDeleteGenerationFixture(t)
			cp.State, cp.ConfirmedAt, cp.PodResourceVersion = "confirmed", &now, witness.Observation.PodResourceVersion
			switch name {
			case "missing_confirmation":
				cp.ConfirmedAt = nil
			case "stale_witness":
				witness.Observation.ObservedAt = now.Add(-61 * time.Second)
			case "wrong_version":
				cp.PodResourceVersion = "different"
			case "wrong_generation":
				witness.Observation.PodGeneration = 3
			case "released_checkpoint":
				cp.State = "released"
			}
			cp.NativeTerminationReceipt, _ = json.Marshal(witness)
			if name == "missing_witness" {
				cp.NativeTerminationReceipt = nil
			}
			req, err := boundPodReleaseRequest(p, cp, now)
			if name != "actual_delete_generation" {
				if err == nil {
					t.Fatal("unproven or stale witness acquired a release request")
				}
				return
			}
			if err != nil || req.ExpectedPodGeneration != 2 || req.ExpectedPodResourceVersion != "13" || req.ExpectedPodUID != cp.PodUID || req.Challenge.ProcessNonce != cp.ProcessNonce || cp.PodGeneration != 1 {
				t.Fatal("release request lost actual witness or immutable origin", err)
			}
		})
	}
}

func TestReleaseRecoveryInventoryUsesIndependentlyWitnessedDeleteGeneration(t *testing.T) {
	for _, name := range []string{"exact_unknown_inventory", "birth_generation", "second_increment", "replacement", "incomplete"} {
		t.Run(name, func(t *testing.T) {
			p, cp, witness, now := capacityDeleteGenerationFixture(t)
			pod := witness.Observation
			pod.State, pod.ContainerState, pod.StartedAt, pod.Receipt = "unknown", "", nil, nil
			switch name {
			case "birth_generation":
				pod.PodGeneration = 1
			case "second_increment":
				pod.PodGeneration = 3
			case "replacement":
				pod.ContainerID = "containerd://replacement"
			}
			inventory := model.AdapterCapacityPodInventoryResponse{Operation: capacity.ObserveNativePodInventory, Status: "observed", BindingName: "api-native", Namespace: cp.Namespace, WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ListResourceVersion: "15", Complete: name != "incomplete", Pods: []model.NativeTerminationObservation{pod}, ObservedAt: now}
			_, _, _, err := capacityReleaseRecoveryFrame(p, cp, func() error { return nil }, func(model.CapacityNativePodCheckpoint) (model.AdapterCapacityPodTerminationResponse, error) {
				return witness, nil
			}, func() (model.CapacityHPAEnvelopeResponse, error) { return model.CapacityHPAEnvelopeResponse{}, nil }, func() (model.AdapterCapacityPodInventoryResponse, error) { return inventory, nil })
			if (err == nil) != (name == "exact_unknown_inventory") {
				t.Fatal("inventory independently certified or lost the complete termination witness", name, err)
			}
		})
	}
}
