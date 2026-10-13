package capacity

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func vmObservationFixture() (model.CapacityPolicySpec, model.CapacityMutationBinding, model.CapacityVMFleetInventory, time.Time) {
	now := time.Now().UTC()
	b := model.CapacityMutationBinding{Name: "vm", IntegrationInstanceID: "instance", ScopeChecksum: strings.Repeat("a", 64), ProfileName: "workers", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 1, MaxSlots: 3}
	for slot := 1; slot <= 3; slot++ {
		spec := &model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, ProfileChecksum: strings.Repeat("b", 64), AdmissionChecksum: strings.Repeat("c", 64), Slot: slot, NativeName: fmt.Sprintf("workers-%d", slot), BootstrapSHA256: strings.Repeat("d", 64)}
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpec: spec, DesiredSpecSHA256: fmt.Sprintf("%064x", slot)})
	}
	inv := model.CapacityVMFleetInventory{IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: b.Slots[0].DesiredSpec.ProfileChecksum, AdmissionChecksum: b.Slots[0].DesiredSpec.AdmissionChecksum, ProfileName: b.ProfileName, ProtectedSlots: 1, MaxSlots: 3, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano), MissingSlots: []int{3}}
	for _, slot := range b.Slots[:2] {
		s := model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: fmt.Sprint(slot.Slot), CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, Name: slot.DesiredSpec.NativeName, Status: "off", Labels: map[string]string{"yggdrasil.io/owner": "native-owner", "yggdrasil.io/scope": vmLabelDigest(b.ScopeChecksum), "yggdrasil.io/spec": vmLabelDigest(slot.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": fmt.Sprint(slot.Slot)}, PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt}
		inv.Members = append(inv.Members, model.CapacityVMFleetInventoryMember{Slot: slot.Slot, Protected: slot.Slot <= b.ProtectedSlots, DesiredSpec: *slot.DesiredSpec, RequestSHA256: slot.DesiredSpecSHA256, Server: s})
	}
	return model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 60}, b, inv, now
}

func TestVMInventoryProofsKeepNativeMembershipSeparateFromReadiness(t *testing.T) {
	p, b, inv, now := vmObservationFixture()
	proofs, err := VMInventoryProofs(p, b, inv, "", 0, now, "receipt:native")
	if err != nil || len(proofs) != 2 || !proofs[0].OwnerVerified || !proofs[0].SpecVerified || proofs[0].ActionsTerminal {
		t.Fatal("physical membership changed into useful/action evidence", proofs, err)
	}
	for _, mode := range []string{"partition", "duplicate_id", "drift", "physical_missing", "warmth", "fencing", "business", "atomic", "stale", "empty_profile_drift"} {
		t.Run(mode, func(t *testing.T) {
			p, b, inv, now := vmObservationFixture()
			switch mode {
			case "partition":
				inv.MissingSlots = nil
			case "duplicate_id":
				inv.Members[1].Server.ID = inv.Members[0].Server.ID
			case "drift":
				inv.Members[1].DesiredSpec.ProfileChecksum = strings.Repeat("e", 64)
			case "physical_missing":
				inv.Members[0].Server.PhysicalSpecVerified = false
			case "warmth":
				inv.WarmReadinessEvidence = true
			case "fencing":
				inv.ProviderFencingEvidence = true
			case "business":
				inv.BusinessReadyEvidence = true
			case "atomic":
				inv.AtomicProviderSnapshot = true
			case "stale":
				inv.ObservationStartedAt = now.Add(-time.Minute * 2).Format(time.RFC3339Nano)
			case "empty_profile_drift":
				inv.Members = nil
				inv.MissingSlots = []int{1, 2, 3}
				inv.ProfileChecksum = ""
			}
			if _, err := VMInventoryProofs(p, b, inv, "", 0, now, "receipt:native"); err == nil {
				t.Fatal("unsafe inventory accepted")
			}
		})
	}
}

func TestVMFailedCandidateCannotBeDroppedOrRegistered(t *testing.T) {
	p, b, inv, now := vmObservationFixture()
	parent := "grant-parent"
	member := inv.Members[1]
	member.Unresolved = true
	member.Server.PhysicalSpecVerified = false
	member.Server.CompensationIdentityVerified = true
	member.Server.Labels["yggdrasil.io/intent"] = parent
	action := model.CapacityVMActionObservation{ID: "action", Status: "error", Command: "create_vm", ResourceID: member.Server.ID, StartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), FinishedAt: now.Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano)}
	candidate := model.CapacityVMFailedCreationCandidate{ParentGrantID: parent, Plan: model.CapacityVMFleetPlan{DesiredSpec: member.DesiredSpec, RequestSHA256: member.RequestSHA256, Server: &member.Server, CompensationIdentityVerified: true, ObservedAt: inv.ObservedAt}, Actions: model.CapacityVMActionCollection{ResourceID: member.Server.ID, ResourceCreatedAt: member.Server.CreatedAt, CreationGrantID: parent, Actions: []model.CapacityVMActionObservation{action}, Complete: true, ObservedAt: inv.ObservedAt}, ActionHistoryComplete: true, ActionsTerminal: true, ActionsFailed: true}
	inv.Members[1], inv.FailedCreation = member, &candidate
	proofs, err := VMInventoryProofs(p, b, inv, parent, 2, now, "receipt:native")
	if err != nil || len(proofs) != 1 {
		t.Fatal("unresolved partial member became registered", proofs, err)
	}
	proof, err := VMFailedCreationProof(p, b, candidate, parent, 2, now, "receipt:native")
	if err != nil || proof.SpecVerified || !proof.CompensationIdentityVerified || !proof.ActionHistoryComplete {
		t.Fatal(proof, err)
	}
	inv.Members = inv.Members[:1]
	inv.MissingSlots = []int{2, 3}
	if _, err = VMInventoryProofs(p, b, inv, parent, 2, now, "receipt:native"); err == nil {
		t.Fatal("candidate silently replaced with missing slot")
	}
	candidate.Actions.Actions[0].Status = "success"
	if _, err = VMFailedCreationProof(p, b, candidate, parent, 2, now, "receipt:native"); err == nil {
		t.Fatal("failed boolean replaced native terminal error")
	}
}

func TestVMClosedDecodeAndAbsentDestroyProof(t *testing.T) {
	var inv model.CapacityVMFleetInventory
	if DecodeVMObservation(map[string]any{"complete": true, "password": "unexpected"}, &inv) == nil {
		t.Fatal("unknown field entered closed native protocol")
	}
	p, b, _, now := vmObservationFixture()
	spec := *b.Slots[1].DesiredSpec
	spec.Capability = VMObserveServer
	spec.ExpectedResourceID = "native-2"
	spec.ExpectedResourceCreatedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
	r := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: "grant", BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, Capability: b.DestroyCapability, ExpectedResourceID: spec.ExpectedResourceID, ExpectedResourceCreatedAt: spec.ExpectedResourceCreatedAt, RequestSHA256: "destroy-digest"}, Outcome: "accepted", TransportCompleted: true, AuxiliaryInventoryComplete: true, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "ip", RequiresAbsence: true}}}
	plan := model.CapacityVMFleetPlan{DesiredSpec: spec, ObservedAt: now.Format(time.RFC3339Nano), AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{{Kind: "primary_ip", ID: "ip", Absent: true, ObservedAt: now.Format(time.RFC3339Nano)}}}
	proof, err := VMServerPlanProof(p, b, plan, r, "absent", now, "receipt:native")
	if err != nil || !proof.ResourceAbsent || proof.ActionsTerminal || len(proof.AuxiliaryAbsent) != 1 {
		t.Fatal(proof, err)
	}
	plan.AuxiliaryResources = nil
	if _, err = VMServerPlanProof(p, b, plan, r, "absent", now, "receipt:native"); err == nil {
		t.Fatal("missing independently billable resource absence accepted")
	}
}
