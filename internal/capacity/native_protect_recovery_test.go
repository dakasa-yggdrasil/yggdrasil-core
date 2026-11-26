package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeProtectRecoveryBinding(t *testing.T) {
	p := model.CapacityPolicySpec{ExecutionEnabled: true, AssessmentBinding: &model.CapacityBoundAssessmentBinding{}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{Mode: HPALifetimeExecutionMode, AdmissionMode: "process_v2"}}
	policy := model.Manifest{ID: uuid.New(), Checksum: strings.Repeat("a", 64)}
	b := model.CapacityUnredeemedProtectRecoveryBinding{Schema: UnredeemedProtectRecoverySchema, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, OperatorID: uuid.NewString(), PodUID: uuid.NewString(), CheckpointSHA256: strings.Repeat("b", 64), ExpectedIntentGeneration: 2, ExpectedIntentFencingToken: 11712, Confirmation: "RECOVER ONLY THIS PROTECT"}
	for i := 0; i < 4; i++ {
		b.Commands = append(b.Commands, model.CapacityUnredeemedProtectReference{CommandID: uuid.NewString(), RecordSHA256: strings.Repeat("c", 64)})
	}
	if err := ValidateUnredeemedProtectRecoveryBinding(policy, p, b); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"schema", "policy", "checksum", "operator", "pod", "checkpoint", "generation", "fence", "three", "five", "duplicate", "digest", "confirmation"} {
		t.Run(name, func(t *testing.T) {
			x := b
			x.Commands = append([]model.CapacityUnredeemedProtectReference(nil), b.Commands...)
			switch name {
			case "schema":
				x.Schema = "native_pre_registration_abort_recovery_v1"
			case "policy":
				x.PolicyID = uuid.NewString()
			case "checksum":
				x.PolicyChecksum = "other"
			case "operator":
				x.OperatorID = "machine"
			case "pod":
				x.PodUID = "same-name"
			case "checkpoint":
				x.CheckpointSHA256 = ""
			case "generation":
				x.ExpectedIntentGeneration = 0
			case "fence":
				x.ExpectedIntentFencingToken = 0
			case "three":
				x.Commands = x.Commands[:3]
			case "five":
				x.Commands = append(x.Commands, x.Commands[0])
			case "duplicate":
				x.Commands[1] = x.Commands[0]
			case "digest":
				x.Commands[0].RecordSHA256 = strings.Repeat("C", 64)
			case "confirmation":
				x.Confirmation = "assert joined\n"
			}
			if ValidateUnredeemedProtectRecoveryBinding(policy, p, x) == nil {
				t.Fatal("unbound human proof accepted")
			}
		})
	}
	var closed model.CapacityUnredeemedProtectRecoveryBinding
	raw, _ := json.Marshal(b)
	var with map[string]any
	if json.Unmarshal(raw, &with) != nil {
		t.Fatal("fixture")
	}
	with["sdk_joined"] = true
	if DecodeNativeCapacity(with, &closed) == nil {
		t.Fatal("caller supplied SDK proof")
	}
}

func TestNativeProtectRecoveryFreshSameSDK(t *testing.T) {
	for _, name := range []string{"exact", "stale", "future", "cid", "start", "nonce", "roster", "rv", "uid", "image", "restart", "deleting", "roots_open", "projection", "receipt", "finished", "exit", "planned"} {
		t.Run(name, func(t *testing.T) {
			p, cp, witness, now := nativeDeleteGenerationFixture(t)
			p.HPAExecutionBinding.AdmissionMode = "process_v2"
			cp.State = "planned"
			pod := witness.Observation
			pod.PodGeneration, pod.ContainerState, pod.State = cp.PodGeneration, "running", "running"
			pod.ExitCode, pod.Signal, pod.FinishedAt, pod.DeletionRequestedAt, pod.Receipt, pod.ReceiptSHA256 = nil, nil, nil, nil, nil, ""
			boot := model.AdapterCapacityPodAdmissionResponse{Operation: ObserveNativePodAdmission, Status: "observed", Observation: pod, Admission: model.NativeProcessAdmissionObservation{SchemaVersion: 2, Namespace: pod.Namespace, PodName: pod.PodName, PodUID: pod.PodUID, ImageDigest: pod.ImageDigest, LaneRosterSHA256: NativeRosterDigest(p.HPAExecutionBinding.Lanes), ProcessNonce: cp.ProcessNonce, ObservedAt: now, State: "waiting_projection"}}
			switch name {
			case "stale":
				boot.Admission.ObservedAt = now.Add(-time.Hour)
			case "future":
				boot.Admission.ObservedAt = now.Add(time.Hour)
			case "cid":
				boot.Observation.ContainerID = "containerd://replacement"
			case "start":
				at := cp.ContainerStartedAt.Add(time.Second)
				boot.Observation.StartedAt = &at
			case "nonce":
				boot.Admission.ProcessNonce = uuid.NewString()
			case "roster":
				boot.Admission.LaneRosterSHA256 = strings.Repeat("f", 64)
			case "rv":
				boot.Observation.PodResourceVersion = ""
			case "uid":
				boot.Observation.PodUID = uuid.NewString()
			case "image":
				boot.Observation.ImageDigest = "sha256:" + strings.Repeat("f", 64)
			case "restart":
				boot.Observation.RestartCount++
			case "deleting":
				boot.Observation.DeletionRequestedAt = &now
			case "roots_open":
				boot.Admission.State = "roots_open"
			case "projection":
				boot.Admission.Challenge = &model.NativePodTerminationChallenge{}
			case "receipt":
				boot.Observation.Receipt = witness.Observation.Receipt
			case "finished":
				boot.Observation.FinishedAt = &now
			case "exit":
				zero := int32(0)
				boot.Observation.ExitCode = &zero
			case "planned":
				cp.State = "admitted"
			}
			if err := ValidateUnredeemedProtectRecoveryBoot(p, cp, boot, now); (err == nil) != (name == "exact") {
				t.Fatalf("same fresh waiting SDK validation: %v", err)
			}
		})
	}
}
