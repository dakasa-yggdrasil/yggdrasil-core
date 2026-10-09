package capacity

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestBoundNativeBindingAndCanonicalInput(t *testing.T) {
	p, _, _, _ := boundAssessmentFixture()
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native", Mode: HPAExecutionMode, PodTerminationBinding: "api", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"listener", "workers"}, ProjectionDirectory: "/native"}
	p.ExecutionEnabled = true
	if ValidatePolicy(p) != nil {
		t.Fatal("valid optional bound executor refused")
	}
	p.MutationBindings = []model.CapacityMutationBinding{{Name: "vm"}}
	if ValidatePolicy(p) == nil {
		t.Fatal("reserved envelope enabled VM mutation")
	}
	for _, input := range []map[string]any{{"binding_name": "api", "BINDING_NAME": "api"}, {"binding_name": "api", "binding_naſe": "api"}, {"binding_name": "api", "receipt": true}} {
		var out model.AdapterObserveCapacityPodInventoryRequest
		if DecodeNativeCapacity(input, &out) == nil {
			t.Fatal("noncanonical native schema accepted")
		}
	}
}

func TestNativeCapacityOptionalPointerNullRemainsUnknown(t *testing.T) {
	var inventory model.AdapterCapacityPodInventoryResponse
	if err := DecodeNativeCapacity(json.RawMessage(`{"pods":[{"receipt":null,"exit_code":null,"started_at":null}]}`), &inventory); err != nil || len(inventory.Pods) != 1 || inventory.Pods[0].Receipt != nil || inventory.Pods[0].ExitCode != nil || inventory.Pods[0].StartedAt != nil {
		t.Fatal("missing native optional facts became an object or a value", err)
	}
	p, _, _, now := boundAssessmentFixture()
	if NativePodWitness(p, model.CapacityNativePodCheckpoint{}, inventory.Pods[0], now) == nil {
		t.Fatal("optional null native facts certified a terminated lifetime")
	}
	for _, raw := range []string{`{"receipt":false}`, `{"receipt":"done"}`, `{"receipt":{"SCHEMA_VERSION":1}}`, `{"receipt":{"schema_verſion":1}}`} {
		var observation model.NativeTerminationObservation
		if DecodeNativeCapacity(json.RawMessage(raw), &observation) == nil {
			t.Fatal("nonnull native receipt bypassed closed object validation", raw)
		}
	}
	var required model.AdapterObserveCapacityPodTerminationRequest
	if DecodeNativeCapacity(json.RawMessage(`{"challenge":null}`), &required) == nil {
		t.Fatal("required challenge was normalized from null")
	}
}
func TestBoundNativeWitnessRequiresCurrentFullLifetime(t *testing.T) {
	p, _, _, now := boundAssessmentFixture()
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{AdapterPrincipalID: "native", Mode: HPAExecutionMode, PodTerminationBinding: "api", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64), Lanes: []string{"listener", "workers"}, ProjectionDirectory: "/native"}
	p.ExecutionEnabled = true
	p.AssessmentBinding.Snapshot.WorkloadUID = uuid.NewString()
	podUID := uuid.NewString()
	start := now.Add(-time.Minute)
	finished := now
	code, signal := int32(0), int32(0)
	deleted := now.Add(-time.Second)
	challenge := model.NativePodTerminationChallenge{SchemaVersion: 1, Namespace: p.AssessmentBinding.Snapshot.Namespace, PodName: "api-1", PodUID: podUID, WorkloadUID: p.AssessmentBinding.Snapshot.WorkloadUID, ContainerName: "api", ImageDigest: p.HPAExecutionBinding.ImageDigest, IntentGeneration: 1, DrainNonce: uuid.NewString(), IssuedAt: now.Add(-2 * time.Second), LaneRosterSHA256: NativeRosterDigest(p.HPAExecutionBinding.Lanes)}
	raw, _ := json.Marshal(challenge)
	checkpoint := model.CapacityNativePodCheckpoint{Namespace: challenge.Namespace, PodName: challenge.PodName, PodUID: podUID, PodGeneration: 0, WorkloadUID: challenge.WorkloadUID, ContainerName: "api", ContainerID: "containerd://actual", ContainerStartedAt: start, ImageDigest: challenge.ImageDigest, IntentGeneration: 1, DrainNonce: challenge.DrainNonce, Challenge: raw, State: "terminating"}
	for _, mode := range []string{"exact", "nonzero", "restart", "old_container", "failed", "incomplete", "nonce", "generation", "missing_time", "missing_exit", "missing_receipt", "missing_finalizer"} {
		t.Run(mode, func(t *testing.T) {
			o := model.NativeTerminationObservation{BindingName: "api", Namespace: challenge.Namespace, PodName: challenge.PodName, PodUID: podUID, PodGeneration: 0, PodResourceVersion: "4", WorkloadUID: challenge.WorkloadUID, ContainerName: "api", ContainerID: checkpoint.ContainerID, ImageDigest: challenge.ImageDigest, ImageID: "fixture@" + challenge.ImageDigest, ContainerState: "terminated", State: "terminated", ExitCode: &code, Signal: &signal, StartedAt: &start, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, ObservedAt: now, ReceiptSHA256: strings.Repeat("b", 64), Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: now.Add(-time.Second), Lanes: map[string]string{"listener": "done", "workers": "inactive"}}}
			switch mode {
			case "nonzero":
				bad := int32(1)
				o.ExitCode = &bad
			case "restart":
				o.RestartCount++
			case "old_container":
				o.ContainerID = "containerd://other"
			case "failed":
				o.Receipt.Lanes["workers"] = "failed"
			case "incomplete":
				delete(o.Receipt.Lanes, "workers")
			case "nonce":
				o.Receipt.DrainNonce = uuid.NewString()
			case "generation":
				o.Receipt.IntentGeneration++
			case "missing_time":
				o.FinishedAt = nil
			case "missing_exit":
				o.ExitCode = nil
			case "missing_receipt":
				o.Receipt = nil
			case "missing_finalizer":
				o.Protected = false
			}
			err := NativePodWitness(p, checkpoint, o, now)
			if (mode == "exact") != (err == nil) {
				t.Fatal("unsafe/missing native proof", mode, err)
			}
		})
	}
}

func TestBoundNativeTimestampIntervalBoundaries(t *testing.T) {
	finished := time.Unix(100, 0).UTC()
	if !nativeJoinTimestamp(finished.Add(time.Second-time.Nanosecond), finished) {
		t.Fatal("same native second refused")
	}
	if nativeJoinTimestamp(finished.Add(time.Second), finished) {
		t.Fatal("later native second accepted")
	}
	if nativeJoinTimestamp(finished.Add(501*time.Millisecond), finished.Add(500*time.Millisecond)) {
		t.Fatal("precise native timestamp widened")
	}
}

func TestNativeReleaseRequiresFreshExactTarget(t *testing.T) {
	p, _, _, now := boundAssessmentFixture()
	p.HPAExecutionBinding = &model.CapacityHPAExecutionBinding{PodTerminationBinding: "api", ContainerName: "api", ImageDigest: "sha256:" + strings.Repeat("a", 64)}
	checkpoint := model.CapacityNativePodCheckpoint{Namespace: p.AssessmentBinding.Snapshot.Namespace, PodName: "api-1", PodUID: uuid.NewString(), ContainerName: "api", ImageDigest: p.HPAExecutionBinding.ImageDigest}
	base := model.NativeTerminationObservation{BindingName: "api", Namespace: checkpoint.Namespace, PodName: checkpoint.PodName, ContainerName: "api", ImageDigest: checkpoint.ImageDigest, State: "absent", Reason: "native_name_absent", ObservedAt: now}
	if NativePodReleaseTarget(p, checkpoint, base, now) != nil {
		t.Fatal("fresh bound absence refused after durable lifetime proof")
	}
	for _, mode := range []string{"stale", "future", "binding", "namespace", "pod_name", "container", "image", "protected", "reason", "foreign_absence_uid", "same_uid_replacement", "invalid_replacement_uid"} {
		t.Run(mode, func(t *testing.T) {
			changed := base
			switch mode {
			case "stale":
				changed.ObservedAt = now.Add(-time.Duration(p.MaxEvidenceAgeSeconds+1) * time.Second)
			case "future":
				changed.ObservedAt = now.Add(time.Hour)
			case "binding":
				changed.BindingName = "other"
			case "namespace":
				changed.Namespace = "other"
			case "pod_name":
				changed.PodName = "other"
			case "container":
				changed.ContainerName = "other"
			case "image":
				changed.ImageDigest = "sha256:" + strings.Repeat("b", 64)
			case "protected":
				changed.Protected = true
			case "reason":
				changed.Reason = "timeout"
			case "foreign_absence_uid":
				changed.PodUID = uuid.NewString()
			case "same_uid_replacement":
				changed.State, changed.Reason, changed.PodUID = "replaced", "native_uid_replaced", checkpoint.PodUID
			case "invalid_replacement_uid":
				changed.State, changed.Reason, changed.PodUID = "replaced", "native_uid_replaced", "missing"
			}
			if NativePodReleaseTarget(p, checkpoint, changed, now) == nil {
				t.Fatal("foreign or stale observation confirmed native release", mode)
			}
		})
	}
	replaced := base
	replaced.State, replaced.Reason, replaced.PodUID = "replaced", "native_uid_replaced", uuid.NewString()
	if NativePodReleaseTarget(p, checkpoint, replaced, now) != nil {
		t.Fatal("fresh same-name replacement did not retire the already-witnessed old UID")
	}
}
