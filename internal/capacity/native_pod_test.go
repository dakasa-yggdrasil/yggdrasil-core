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
	for _, mode := range []string{"exact", "nonzero", "restart", "old_container", "failed", "incomplete", "nonce", "generation", "missing_time", "missing_exit", "missing_finalizer"} {
		t.Run(mode, func(t *testing.T) {
			o := model.NativeTerminationObservation{BindingName: "api", Namespace: challenge.Namespace, PodName: challenge.PodName, PodUID: podUID, PodGeneration: 0, PodResourceVersion: "4", WorkloadUID: challenge.WorkloadUID, ContainerName: "api", ContainerID: checkpoint.ContainerID, ImageDigest: challenge.ImageDigest, ContainerState: "terminated", State: "terminated", ExitCode: &code, Signal: &signal, StartedAt: &start, FinishedAt: &finished, DeletionRequestedAt: &deleted, Protected: true, ObservedAt: now, ReceiptSHA256: strings.Repeat("b", 64), Receipt: &model.NativePodTerminationReceipt{NativePodTerminationChallenge: challenge, JoinedAt: now.Add(-time.Second), Lanes: map[string]string{"listener": "done", "workers": "inactive"}}}
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
