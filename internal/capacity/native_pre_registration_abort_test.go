package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeAbortFixture() (model.Manifest, model.CapacityPolicySpec, model.CapacityNativeAbortProof) {
	now := time.Now().UTC()
	start, finish, deleted := now.Add(-time.Minute), now.Add(-20*time.Second), now.Add(-10*time.Second)
	policy := model.Manifest{ID: uuid.New(), Checksum: strings.Repeat("a", 64)}
	workload := uuid.NewString()
	image := "sha256:" + strings.Repeat("b", 64)
	p := model.CapacityPolicySpec{Owner: "operator", MaxEvidenceAgeSeconds: 60, AssessmentBinding: &model.CapacityBoundAssessmentBinding{Snapshot: model.CapacityHPAMinimumBinding{Namespace: "platform", WorkloadUID: workload}}, HPAExecutionBinding: &model.CapacityHPAExecutionBinding{Mode: HPALifetimeExecutionMode, AdmissionMode: "process_v2", ContainerName: "api", ImageDigest: image, PodTerminationBinding: "native"}}
	b := model.CapacityNativeAbortBinding{Schema: NativePreRegistrationAbortSchema, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, Generation: 1, Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), IntegrationTypeID: uuid.NewString(), InstanceChecksum: strings.Repeat("c", 64), TypeChecksum: strings.Repeat("d", 64)}, AdapterPrincipalID: "abort-adapter", AdapterSourceCommit: strings.Repeat("e", 40), OperatorID: uuid.NewString(), BindingName: "native", Namespace: "platform", PodName: "api-original", PodUID: uuid.NewString(), WorkloadUID: workload, ReplicaSetUID: uuid.NewString(), ContainerName: "api", ImageDigest: image, PodSpecSHA256: strings.Repeat("f", 64), Confirmation: "ABORT ORIGINAL UNREGISTERED BIRTH"}
	exit, signal := int32(1), int32(0)
	o := model.NativePreRegistrationAbortObservation{NativeTerminationObservation: model.NativeTerminationObservation{BindingName: b.BindingName, Namespace: b.Namespace, PodName: b.PodName, PodUID: b.PodUID, PodResourceVersion: "10", WorkloadUID: b.WorkloadUID, ContainerName: b.ContainerName, ContainerID: "containerd://original", ImageID: "fixture@" + image, ImageDigest: image, ContainerState: "terminated", State: "failed_deleting", ExitCode: &exit, Signal: &signal, StartedAt: &start, FinishedAt: &finish, DeletionRequestedAt: &deleted, Protected: true, ObservedAt: now.Add(-time.Millisecond)}, ReplicaSetUID: b.ReplicaSetUID, PodSpecSHA256: b.PodSpecSHA256, PodPhase: "Failed", BirthWorkloadUID: workload, ChallengeState: "absent"}
	return policy, p, model.CapacityNativeAbortProof{Schema: NativePreRegistrationAbortSchema, Binding: b, Observation: o, FencingToken: 68, AuthoredAt: now}
}

func TestNativePreRegistrationAbortSeparateProof(t *testing.T) {
	for _, name := range []string{"exact", "prior_lifetime", "prior_archive", "prior_legacy", "prior_identity", "orphan_hot", "archived_command", "scope_pending", "running", "successful_exit", "restart", "replacement", "spec_drift", "challenge", "protect_owner", "birth_identity", "sdk_receipt", "missing_termination", "wrong_policy", "expired_evidence"} {
		t.Run(name, func(t *testing.T) {
			policy, p, proof := nativeAbortFixture()
			switch name {
			case "prior_lifetime":
				proof.ZeroHistory.Lifetimes = 1
			case "prior_archive":
				proof.ZeroHistory.LifetimeArchives = 1
			case "prior_legacy":
				proof.ZeroHistory.LegacyCheckpoints = 1
			case "prior_identity":
				proof.ZeroHistory.CommandIdentities = 1
			case "orphan_hot":
				proof.ZeroHistory.HotCommands = 1
			case "archived_command":
				proof.ZeroHistory.ArchivedCommands = 1
			case "scope_pending":
				proof.ScopeUnsettledCommands = 1
			case "running":
				proof.Observation.ContainerState = "running"
			case "successful_exit":
				z := int32(0)
				proof.Observation.ExitCode = &z
			case "restart":
				proof.Observation.RestartCount = 1
			case "replacement":
				proof.Observation.PodUID = uuid.NewString()
			case "spec_drift":
				proof.Observation.PodSpecSHA256 = strings.Repeat("0", 64)
			case "challenge":
				proof.Observation.ChallengeState = "present"
			case "protect_owner":
				proof.Observation.ProtectionOwner = "operator"
			case "birth_identity":
				proof.Observation.BirthWorkloadUID = uuid.NewString()
			case "sdk_receipt":
				proof.Observation.Receipt = &model.NativePodTerminationReceipt{}
			case "missing_termination":
				proof.Observation.FinishedAt = nil
			case "wrong_policy":
				proof.Binding.PolicyID = uuid.NewString()
			case "expired_evidence":
				proof.AuthoredAt = time.Now().Add(-2 * time.Minute)
			}
			err := ValidateNativeAbortProof(policy, p, proof, time.Now().UTC())
			if (err == nil) != (name == "exact") {
				t.Fatalf("native abort eligibility mismatch %s", name)
			}
			if NativePodWitness(p, model.CapacityNativePodCheckpoint{}, proof.Observation.NativeTerminationObservation, time.Now()) == nil {
				t.Fatal("abort proof became successful lane witness")
			}
		})
	}
}

func TestNativePreRegistrationAbortClosedWireAndRemoval(t *testing.T) {
	policy, p, proof := nativeAbortFixture()
	_ = policy
	no := false
	request := model.AdapterDestroyCapacityPodUnregisteredProtectionRequest{ExpectedPodUID: proof.Binding.PodUID, ExpectedPodResourceVersion: "10", Proof: proof, DryRun: &no}
	raw, _ := json.Marshal(request)
	var decoded model.AdapterDestroyCapacityPodDrainProtectionRequest
	if DecodeNativeCapacity(json.RawMessage(raw), &decoded) == nil {
		t.Fatal("new proof accepted by old closed drain release")
	}
	var exact model.AdapterDestroyCapacityPodUnregisteredProtectionRequest
	if DecodeNativeCapacity(json.RawMessage(raw), &exact) != nil {
		t.Fatal("closed abort wire refused")
	}
	var extra map[string]any
	_ = json.Unmarshal(raw, &extra)
	extra["lanes_joined"] = true
	if DecodeNativeCapacity(extra, &exact) == nil {
		t.Fatal("caller lane assertion accepted")
	}
	r := model.AdapterCapacityPodUnregisteredTerminalResponse{Operation: ObserveNativeUnregisteredTerminal, Status: "observed", Observation: proof.Observation}
	if ValidateNativeAbortRemoval(p, proof.Binding, r, time.Now()) == nil {
		t.Fatal("still-protected original marked removed")
	}
	r.Observation.Protected = false
	if ValidateNativeAbortRemoval(p, proof.Binding, r, time.Now()) != nil {
		t.Fatal("exact native finalizer removal refused")
	}
	r.Observation.PodUID = uuid.NewString()
	if ValidateNativeAbortRemoval(p, proof.Binding, r, time.Now()) == nil {
		t.Fatal("replacement marked original settlement")
	}
}
