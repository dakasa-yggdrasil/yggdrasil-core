package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeDeleteGenerationFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityNativePodCheckpoint, model.AdapterCapacityPodTerminationResponse, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	started, finished, deleted := now.Add(-time.Minute), now.Add(-time.Second), now.Add(-2*time.Second)
	zero := int32(0)
	p := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 60, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Namespace: "native", WorkloadUID: uuid.NewString()}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{Mode: HPALifetimeExecutionMode, PodTerminationBinding: "api-native", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"listener", "workers", "outbox", "scheduler", "rpc", "events", "projector"}}}
	challenge := model.NativePodTerminationChallenge{SchemaVersion: 2, Namespace: "native", PodName: "api", PodUID: uuid.NewString(), WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, ContainerName: "api", ImageDigest: p.HPAExecutionBinding.ImageDigest, IntentGeneration: 1, DrainNonce: uuid.NewString(), ProcessNonce: uuid.NewString(), IssuedAt: now.Add(-30 * time.Second), LaneRosterSHA256: NativeRosterDigest(p.HPAExecutionBinding.Lanes)}
	raw, err := json.Marshal(challenge)
	if err != nil {
		t.Fatal(err)
	}
	cp := model.CapacityNativePodCheckpoint{Namespace: challenge.Namespace, PodName: challenge.PodName, PodUID: challenge.PodUID, PodGeneration: 1, WorkloadUID: challenge.WorkloadUID, ContainerName: challenge.ContainerName, ContainerID: "containerd://current", ContainerStartedAt: started, ImageDigest: challenge.ImageDigest, IntentGeneration: 1, DrainNonce: challenge.DrainNonce, ProcessNonce: challenge.ProcessNonce, Challenge: raw, State: "admitted"}
	lanes := map[string]string{}
	for _, lane := range p.HPAExecutionBinding.Lanes {
		lanes[lane] = "done"
	}
	pod := model.NativeTerminationObservation{BindingName: "api-native", Namespace: cp.Namespace, PodName: cp.PodName, PodUID: cp.PodUID, PodGeneration: 2, PodResourceVersion: "13", WorkloadUID: cp.WorkloadUID, WorkloadResourceVersion: "10", ContainerName: cp.ContainerName, ContainerID: cp.ContainerID, ImageID: "fixture@" + cp.ImageDigest, ImageDigest: cp.ImageDigest, ContainerState: "terminated", ExitCode: &zero, Signal: &zero, StartedAt: &started, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, State: "terminated", Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: finished, Lanes: lanes, RootAdmission: "previously_opened"}, ReceiptSHA256: strings.Repeat("b", 64), ObservedAt: now}
	return p, cp, model.AdapterCapacityPodTerminationResponse{Operation: ObserveNativePodTermination, Status: "observed", Observation: pod}, now
}

func TestNativeFirstDeleteGenerationRequiresFullCurrentWitness(t *testing.T) {
	cases := []string{"first_delete", "same_generation", "zero_generation_unchanged", "zero_generation_incremented", "second_increment", "generation_reversed", "running", "unknown", "not_deleting", "zero_deletion", "missing_receipt", "missing_protection", "old_container", "restarted", "wrong_start", "wrong_image", "wrong_uid", "wrong_process", "wrong_nonce", "wrong_challenge", "incomplete_lanes", "failed_lane", "nonzero_exit", "nonzero_signal", "missing_finish", "stale", "future", "legacy_mode"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			p, cp, witness, now := nativeDeleteGenerationFixture(t)
			o := &witness.Observation
			switch name {
			case "same_generation":
				o.PodGeneration = cp.PodGeneration
			case "zero_generation_unchanged":
				cp.PodGeneration, o.PodGeneration = 0, 0
			case "zero_generation_incremented":
				cp.PodGeneration, o.PodGeneration = 0, 1
			case "second_increment":
				o.PodGeneration = cp.PodGeneration + 2
			case "generation_reversed":
				o.PodGeneration = 0
			case "running":
				o.State, o.ContainerState = "running", "running"
			case "unknown":
				o.State = "unknown"
			case "not_deleting":
				o.DeletionRequestedAt = nil
			case "zero_deletion":
				o.DeletionRequestedAt = &time.Time{}
			case "missing_receipt":
				o.Receipt = nil
			case "missing_protection":
				o.Protected = false
			case "old_container":
				o.ContainerID = "containerd://previous"
			case "restarted":
				o.RestartCount++
			case "wrong_start":
				start := cp.ContainerStartedAt.Add(time.Second)
				o.StartedAt = &start
			case "wrong_image":
				o.ImageID = "fixture@sha256:" + strings.Repeat("c", 64)
			case "wrong_uid":
				o.PodUID = uuid.NewString()
			case "wrong_process":
				o.Receipt.ProcessNonce = uuid.NewString()
			case "wrong_nonce":
				o.Receipt.DrainNonce = uuid.NewString()
			case "wrong_challenge":
				o.Receipt.IntentGeneration++
			case "incomplete_lanes":
				delete(o.Receipt.Lanes, "outbox")
			case "failed_lane":
				o.Receipt.Lanes["workers"] = "failed"
			case "nonzero_exit":
				one := int32(1)
				o.ExitCode = &one
			case "nonzero_signal":
				one := int32(1)
				o.Signal = &one
			case "missing_finish":
				o.FinishedAt = nil
			case "stale":
				o.ObservedAt = now.Add(-61 * time.Second)
			case "future":
				o.ObservedAt = now.Add(time.Hour)
			case "legacy_mode":
				p.HPAExecutionBinding.Mode = HPAExecutionMode
			}
			want := name == "first_delete" || name == "same_generation" || name == "zero_generation_unchanged"
			if err := NativePodWitness(p, cp, *o, now); (err == nil) != want {
				t.Fatal("unexpected native witness decision", name, err)
			}
			if name == "first_delete" && NativePodMatchesCheckpoint(p, cp, *o, now) == nil {
				t.Fatal("terminal exception weakened the globally strict checkpoint identity")
			}
			if cp.PodGeneration != 1 && name != "zero_generation_unchanged" && name != "zero_generation_incremented" {
				t.Fatal("immutable birth generation changed")
			}
		})
	}
}

func TestNativeDeleteGenerationReadbackRequiresDurableWitness(t *testing.T) {
	for _, name := range []string{"exact", "archived_origin", "birth_generation_readback", "extra_generation", "missing_witness", "missing_confirmation", "wrong_witness_version", "wrong_witness_operation", "wrong_witness_status", "invalid_witness", "stale_at_confirmation", "live_readback", "not_deleting", "wrong_id", "restarted", "wrong_start", "stale_readback"} {
		t.Run(name, func(t *testing.T) {
			p, cp, witness, now := nativeDeleteGenerationFixture(t)
			confirmedAt := now
			cp.State, cp.ConfirmedAt, cp.PodResourceVersion = "confirmed", &confirmedAt, witness.Observation.PodResourceVersion
			cp.NativeTerminationReceipt, _ = json.Marshal(witness)
			o := witness.Observation
			o.Protected, o.State, o.Reason, o.Receipt, o.FinishedAt = false, "unprotected", "native_capacity_finalizer_absent", nil, nil
			switch name {
			case "archived_origin":
				cp.State = "released"
				now = now.Add(24 * time.Hour)
				o.ObservedAt = now
			case "birth_generation_readback":
				o.PodGeneration = cp.PodGeneration
			case "extra_generation":
				o.PodGeneration++
			case "missing_witness":
				cp.NativeTerminationReceipt = nil
			case "missing_confirmation":
				cp.ConfirmedAt = nil
			case "wrong_witness_version":
				cp.PodResourceVersion = "different"
			case "wrong_witness_operation":
				witness.Operation = DestroyNativePodProtection
				cp.NativeTerminationReceipt, _ = json.Marshal(witness)
			case "wrong_witness_status":
				witness.Status = "released"
				cp.NativeTerminationReceipt, _ = json.Marshal(witness)
			case "invalid_witness":
				witness.Observation.Receipt.DrainNonce = uuid.NewString()
				cp.NativeTerminationReceipt, _ = json.Marshal(witness)
			case "stale_at_confirmation":
				witness.Observation.ObservedAt = now.Add(-61 * time.Second)
				cp.NativeTerminationReceipt, _ = json.Marshal(witness)
			case "live_readback":
				o.ContainerState = "running"
			case "not_deleting":
				o.DeletionRequestedAt = nil
			case "wrong_id":
				o.ContainerID = "containerd://replacement"
			case "restarted":
				o.RestartCount++
			case "wrong_start":
				start := cp.ContainerStartedAt.Add(time.Second)
				o.StartedAt = &start
			case "stale_readback":
				o.ObservedAt = now.Add(-61 * time.Second)
			}
			want := name == "exact" || name == "archived_origin"
			if err := NativePodReleaseTarget(p, cp, o, now); (err == nil) != want {
				t.Fatal("unexpected exact finalizer removal decision", name, err)
			}
			if cp.PodGeneration != 1 {
				t.Fatal("original generation was rewritten")
			}
		})
	}
}

func TestNativeReleaseAuthorityUsesFreshActualWitnessGeneration(t *testing.T) {
	for _, name := range []string{"exact", "birth_generation", "extra_generation", "wrong_container", "wrong_start", "restarted", "wrong_binding", "wrong_version", "wrong_challenge", "dry_run", "missing_dry_run", "missing_witness", "stale_witness"} {
		t.Run(name, func(t *testing.T) {
			p, cp, witness, now := nativeDeleteGenerationFixture(t)
			confirmedAt := now
			cp.State, cp.ConfirmedAt, cp.PodResourceVersion = "confirmed", &confirmedAt, witness.Observation.PodResourceVersion
			no := false
			req := model.AdapterDestroyCapacityPodDrainProtectionRequest{AdapterObserveCapacityPodTerminationRequest: model.AdapterObserveCapacityPodTerminationRequest{BindingName: p.HPAExecutionBinding.PodTerminationBinding, PodName: cp.PodName, ExpectedPodUID: cp.PodUID, ExpectedPodGeneration: 2, ExpectedContainerID: cp.ContainerID, ExpectedContainerStartedAt: cp.ContainerStartedAt, ExpectedRestartCount: cp.RestartCount, Challenge: witness.Observation.Receipt.NativePodTerminationChallenge}, ExpectedPodResourceVersion: cp.PodResourceVersion, DryRun: &no}
			switch name {
			case "birth_generation":
				req.ExpectedPodGeneration = cp.PodGeneration
			case "extra_generation":
				req.ExpectedPodGeneration++
			case "wrong_container":
				req.ExpectedContainerID = "containerd://replacement"
			case "wrong_start":
				req.ExpectedContainerStartedAt = req.ExpectedContainerStartedAt.Add(time.Second)
			case "restarted":
				req.ExpectedRestartCount++
			case "wrong_binding":
				req.BindingName = "other"
			case "wrong_version":
				req.ExpectedPodResourceVersion = "different"
			case "wrong_challenge":
				req.Challenge.DrainNonce = uuid.NewString()
			case "dry_run":
				yes := true
				req.DryRun = &yes
			case "missing_dry_run":
				req.DryRun = nil
			case "stale_witness":
				confirmedAt = now.Add(-61 * time.Second)
				witness.Observation.ObservedAt = confirmedAt
			}
			cp.NativeTerminationReceipt, _ = json.Marshal(witness)
			if name == "missing_witness" {
				cp.NativeTerminationReceipt = nil
			}
			if err := ValidateNativePodReleaseRequest(p, cp, req, now); (err == nil) != (name == "exact") {
				t.Fatal("release authority escaped the fresh persisted witness", name, err)
			}
		})
	}
}
