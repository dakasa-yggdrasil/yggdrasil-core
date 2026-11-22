package capacity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativeAbortRecoveryFixture() (model.Manifest, model.CapacityPolicySpec, model.CapacityNativeAbortRecoveryProof) {
	policy, p, original := nativeAbortFixture()
	start, finish, deleted := original.AuthoredAt.Add(-10*time.Minute), original.AuthoredAt.Add(-8*time.Minute), original.AuthoredAt.Add(-7*time.Minute)
	original.Observation.StartedAt, original.Observation.FinishedAt, original.Observation.DeletionRequestedAt = &start, &finish, &deleted
	b := model.CapacityNativeAbortRecoveryBinding{Schema: NativePreRegistrationAbortRecoverySchema, Native: original.Binding, ParentCommandID: uuid.NewString(), ParentFencingToken: 68, ParentExpiresAt: original.AuthoredAt.Add(-3 * time.Minute), ExpectedIntentFencingToken: 68}
	lineage := model.CapacityNativeAbortRecoveryLineage{ParentCommandID: b.ParentCommandID, ParentSequence: 1, PriorState: "uncertain", AdministrativeState: "refused_no_redemption", ParentFencingToken: b.ParentFencingToken, ParentExpiresAt: b.ParentExpiresAt, DispositionAt: original.AuthoredAt}
	proof := model.CapacityNativeAbortRecoveryProof{Schema: NativePreRegistrationAbortRecoverySchema, Binding: b, Observation: original.Observation, History: model.CapacityNativeAbortZeroHistory{CommandIdentities: 1, ArchivedCommands: 1}, Lineage: lineage, FencingToken: 69, AuthoredAt: original.AuthoredAt}
	return policy, p, proof
}

func TestNativeAbortUnredeemedRecoveryProof(t *testing.T) {
	for _, name := range []string{"exact", "hidden_parent", "parent_hot", "extra_archive", "prior_lifetime", "pending_scope", "unexpired_parent", "foreign_parent", "fake_effect", "third_sequence", "old_fence", "wrong_policy", "sdk_receipt", "mixed_v1", "stale_witness"} {
		t.Run(name, func(t *testing.T) {
			policy, p, proof := nativeAbortRecoveryFixture()
			switch name {
			case "hidden_parent":
				proof.History = model.CapacityNativeAbortZeroHistory{}
			case "parent_hot":
				proof.History.HotCommands, proof.History.ArchivedCommands = 1, 0
			case "extra_archive":
				proof.History.ArchivedCommands++
			case "prior_lifetime":
				proof.History.Lifetimes++
			case "pending_scope":
				proof.ScopeUnsettledCommands++
			case "unexpired_parent":
				proof.Binding.ParentExpiresAt = proof.AuthoredAt.Add(time.Minute)
				proof.Lineage.ParentExpiresAt = proof.Binding.ParentExpiresAt
			case "foreign_parent":
				proof.Lineage.ParentCommandID = uuid.NewString()
			case "fake_effect":
				proof.Lineage.AdministrativeState = "confirmed"
			case "third_sequence":
				proof.Lineage.ParentSequence = 2
			case "old_fence":
				proof.FencingToken--
			case "wrong_policy":
				proof.Binding.Native.PolicyID = uuid.NewString()
			case "sdk_receipt":
				proof.Observation.Receipt = &model.NativePodTerminationReceipt{}
			case "mixed_v1":
				proof.Schema = NativePreRegistrationAbortSchema
			case "stale_witness":
				proof.Observation.ObservedAt = proof.AuthoredAt.Add(-2 * time.Minute)
			}
			if (ValidateNativeAbortRecoveryProof(policy, p, proof, proof.AuthoredAt) == nil) != (name == "exact") {
				t.Fatal("unredeemed recovery history or native eligibility was weakened")
			}
		})
	}
}

func TestNativeAbortUnredeemedRecoveryClosedWire(t *testing.T) {
	_, _, proof := nativeAbortRecoveryFixture()
	no := false
	request := model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest{ExpectedPodUID: proof.Binding.Native.PodUID, ExpectedPodResourceVersion: proof.Observation.PodResourceVersion, Proof: proof, DryRun: &no}
	raw, err := json.Marshal(request)
	var decoded model.AdapterDestroyCapacityPodUnregisteredProtectionRecoveryRequest
	if err != nil || DecodeNativeCapacity(json.RawMessage(raw), &decoded) != nil || decoded.Proof.Observation.Receipt != nil || decoded.Proof.History.CommandIdentities != 1 || decoded.Proof.History.ArchivedCommands != 1 {
		t.Fatal("canonical recovery history/null receipt unavailable")
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("canonical fixture unavailable")
	}
	fields["proof"].(map[string]any)["zero_history"] = map[string]any{}
	if DecodeNativeCapacity(fields, &decoded) == nil {
		t.Fatal("recovery proof silently accepted a fabricated v1 zero-history field")
	}
	var legacy model.AdapterDestroyCapacityPodUnregisteredProtectionRequest
	if DecodeNativeCapacity(json.RawMessage(raw), &legacy) == nil {
		t.Fatal("new recovery proof downgraded to the unchanged zero-history contract")
	}
}
