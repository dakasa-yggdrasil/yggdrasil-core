package capacity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These are already approved public contracts on distinct physical instances.
// No new Guest artifact, approval, provider response or enrollment is invented.
func guestCohortPublicPolicies(t *testing.T) (model.CapacityPolicySpec, model.CapacityPolicySpec) {
	t.Helper()
	read := func(name string) model.CapacityPolicySpec {
		raw, err := os.ReadFile("testdata/" + name + "-notify-hetzner-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		var p model.CapacityPolicySpec
		if json.Unmarshal(raw, &p) != nil || ValidateGuestNotifyReconcileBinding(p) != nil {
			t.Fatal("complete public HZN contract required")
		}
		return p
	}
	old, head := read("original"), read("b509")
	if old.MutationBindings[0].IntegrationInstanceID == head.MutationBindings[0].IntegrationInstanceID || old.MutationBindings[0].ScopeChecksum == head.MutationBindings[0].ScopeChecksum {
		t.Fatal("test needs distinct approved physical contracts")
	}
	head.GuestContractSuccessor = &model.CapacityGuestContractSuccessor{Schema: GuestContractSuccessorSchema, RetainedPolicyContracts: []model.CapacityGuestRetainedPolicyContract{{PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("a", 64), ContractSHA256: GuestProductionProfileContractSHA256(old, *old.GuestRetirementBinding, "hetzner")}}}
	return old, head
}

func guestCohortInventory(p model.CapacityPolicySpec, now time.Time, slots ...int) model.CapacityVMFleetInventory {
	b := p.MutationBindings[0]
	s := b.Slots[0].DesiredSpec
	inv := model.CapacityVMFleetInventory{IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: s.ProfileChecksum, AdmissionChecksum: s.AdmissionChecksum, ProfileName: b.ProfileName, ProtectedSlots: b.ProtectedSlots, MaxSlots: b.MaxSlots, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano)}
	seen := map[int]bool{}
	for _, slot := range slots {
		seen[slot] = true
		d := b.Slots[slot-1]
		inv.Members = append(inv.Members, model.CapacityVMFleetInventoryMember{Slot: slot, DesiredSpec: *d.DesiredSpec, RequestSHA256: d.DesiredSpecSHA256, Server: model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: fmt.Sprint(700000 + slot), CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, Name: d.DesiredSpec.NativeName, Status: "off", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: map[string]string{"yggdrasil.io/owner": p.Owner, "yggdrasil.io/scope": vmLabelDigest(b.ScopeChecksum), "yggdrasil.io/spec": vmLabelDigest(d.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": fmt.Sprint(slot)}}})
	}
	for slot := 1; slot <= b.MaxSlots; slot++ {
		if !seen[slot] {
			inv.MissingSlots = append(inv.MissingSlots, slot)
		}
	}
	return inv
}

func testGuestContractInventoryUnion(t *testing.T) {
	t.Helper()
	old, head := guestCohortPublicPolicies(t)
	now := time.Now().UTC()
	policy := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "cohort-shape-only"}, Checksum: strings.Repeat("4", 64)}
	contracts := []model.CapacityPolicySpec{head, old}
	inventories := []GuestContractInventory{{GuestProductionProfileContractSHA256(head, *head.GuestRetirementBinding, "hetzner"), guestCohortInventory(head, now, 2)}, {GuestProductionProfileContractSHA256(old, *old.GuestRetirementBinding, "hetzner"), guestCohortInventory(old, now, 1)}}
	before, _ := json.Marshal(contracts)
	snapshot, missing, err := GuestContractReconcileSnapshot(policy, head, contracts, inventories, now)
	if err != nil || snapshot.Units != 2 || !reflect.DeepEqual(missing, []int{3, 4, 5, 6, 7, 8}) || !strings.HasPrefix(snapshot.ResourceUID, "original-vm-contract-cohorts:") {
		t.Fatal("head missing slot1 must retain old S1 and new S2", snapshot, missing, err)
	}
	for _, fault := range []string{"missing_receipt", "duplicate_slot", "duplicate_native_id", "foreign_hash", "wrong_scope", "incomplete", "unresolved", "wrong_order", "duplicate_contract"} {
		var views []model.CapacityPolicySpec
		var reads []GuestContractInventory
		raw, _ := json.Marshal(contracts)
		if json.Unmarshal(raw, &views) != nil {
			t.Fatal("views")
		}
		raw, _ = json.Marshal(inventories)
		if json.Unmarshal(raw, &reads) != nil {
			t.Fatal("reads")
		}
		switch fault {
		case "missing_receipt":
			reads = reads[:1]
		case "duplicate_slot":
			reads[1].Inventory = guestCohortInventory(old, now, 2)
		case "duplicate_native_id":
			reads[1].Inventory.Members[0].Server.ID = reads[0].Inventory.Members[0].Server.ID
		case "foreign_hash":
			reads[1].ContractSHA256 = strings.Repeat("f", 64)
		case "wrong_scope":
			reads[1].Inventory.ScopeChecksum = reads[0].Inventory.ScopeChecksum
		case "incomplete":
			reads[1].Inventory.Complete = false
		case "unresolved":
			reads[1].Inventory.Members[0].Unresolved = true
		case "wrong_order":
			reads[0], reads[1] = reads[1], reads[0]
		case "duplicate_contract":
			views = append(views, views[1])
			reads = append(reads, reads[1])
		}
		if _, _, e := GuestContractReconcileSnapshot(policy, head, views, reads, now); e == nil {
			t.Fatal("incomplete/ambiguous union accepted", fault)
		}
	}
	// Native member order cannot manufacture a different logical fingerprint.
	inventories[0].Inventory = guestCohortInventory(head, now, 3, 2)
	one, _, err := GuestContractReconcileSnapshot(policy, head, contracts, inventories, now)
	if err != nil {
		t.Fatal(err)
	}
	inventories[0].Inventory.Members[0], inventories[0].Inventory.Members[1] = inventories[0].Inventory.Members[1], inventories[0].Inventory.Members[0]
	two, _, err := GuestContractReconcileSnapshot(policy, head, contracts, inventories, now)
	if err != nil || !reflect.DeepEqual(one, two) {
		t.Fatal("native order changed logical identity", err)
	}
	legacy := guestCohortInventory(old, now, 1)
	want, err := GuestReconcileSnapshot(policy, old, legacy, now)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := GuestContractReconcileSnapshot(policy, old, []model.CapacityPolicySpec{old}, []GuestContractInventory{{GuestProductionProfileContractSHA256(old, *old.GuestRetirementBinding, "hetzner"), legacy}}, now)
	if err != nil || !reflect.DeepEqual(want, got) {
		t.Fatal("legacy singleton identity changed", err)
	}
	after, _ := json.Marshal(contracts)
	if !bytes.Equal(before, after) {
		t.Fatal("inventory projection mutated immutable contract")
	}
}

func testGuestContractDeclarationAndView(t *testing.T) {
	t.Helper()
	old, head := guestCohortPublicPolicies(t)
	if ValidateGuestContractSuccessor(head) != nil {
		t.Fatal("closed declaration")
	}
	oldWire, _ := json.Marshal(old)
	headWire, _ := json.Marshal(head)
	view, err := GuestContractView(head, old)
	if err != nil || !reflect.DeepEqual(view.MutationBindings, old.MutationBindings) || !reflect.DeepEqual(view.GuestRetirementBinding, old.GuestRetirementBinding) || view.MinSamples != head.MinSamples || GuestPolicyContinuous(old, head) {
		t.Fatal("view rewrote authority or weakened legacy continuity", err)
	}
	for _, fault := range []string{"schema", "empty", "duplicate_id", "duplicate_hash", "bad_id", "unknown_checksum"} {
		p := guestPolicyContinuityClone(t, head)
		switch fault {
		case "schema":
			p.GuestContractSuccessor.Schema = "other"
		case "empty":
			p.GuestContractSuccessor.RetainedPolicyContracts = nil
		case "duplicate_id":
			r := p.GuestContractSuccessor.RetainedPolicyContracts[0]
			r.ContractSHA256 = strings.Repeat("f", 64)
			p.GuestContractSuccessor.RetainedPolicyContracts = append(p.GuestContractSuccessor.RetainedPolicyContracts, r)
		case "duplicate_hash":
			r := p.GuestContractSuccessor.RetainedPolicyContracts[0]
			r.PolicyID = uuid.NewString()
			p.GuestContractSuccessor.RetainedPolicyContracts = append(p.GuestContractSuccessor.RetainedPolicyContracts, r)
		case "bad_id":
			p.GuestContractSuccessor.RetainedPolicyContracts[0].PolicyID = "not-a-uuid"
		case "unknown_checksum":
			p.GuestContractSuccessor.RetainedPolicyContracts[0].PolicyChecksum = ""
		}
		if ValidateGuestContractSuccessor(p) == nil {
			t.Fatal("open successor declaration accepted", fault)
		}
	}
	for _, fault := range []string{"environment", "dimension", "workflow", "provider", "region", "binding", "max_slots", "protected"} {
		p := guestPolicyContinuityClone(t, head)
		switch fault {
		case "environment":
			p.Environment = "other"
		case "dimension":
			p.Dimension = "other"
		case "workflow":
			p.Workflow.Name = "other"
		case "provider":
			p.Profiles[0].Provider = "aws"
		case "region":
			p.Profiles[0].Region = "other"
		case "binding":
			p.MutationBindings[0].Name = "other"
		case "max_slots":
			p.MutationBindings[0].MaxSlots--
		case "protected":
			p.MutationBindings[0].ProtectedSlots++
		}
		if _, e := GuestContractView(p, old); e == nil {
			t.Fatal("cross logical scope view accepted", fault)
		}
	}
	if raw, _ := json.Marshal(old); string(raw) != string(oldWire) {
		t.Fatal("birth changed")
	}
	if raw, _ := json.Marshal(head); string(raw) != string(headWire) {
		t.Fatal("head changed")
	}
	legacy, _ := json.Marshal(model.CapacityPolicySpec{})
	if strings.Contains(string(legacy), "guest_contract_successor") {
		t.Fatal("legacy wire gained selector")
	}
}

func testGuestContractLegacySixMap(t *testing.T) {
	t.Helper()
	if len(guestB509ProtocolProfileApprovals) != 6 || guestProtocolCompatibilityMapSHA256(guestB509ProtocolProfileApprovals) != GuestB509ProtocolCompatibilityMapSHA256 || GuestB509ProtocolCompatibilityMapSHA256 != "d51495ae4e1a1e3cde3cf2713e0a2cf3e333bc5326d85c46dccb005d8de7af65" {
		t.Fatal("six-contract historical map changed")
	}
	old, head := guestCohortPublicPolicies(t)
	for _, p := range []model.CapacityPolicySpec{old, head} {
		b := *p.GuestRetirementBinding
		issuer := b.CoreAuthoritySourceCommit // Declared historical issuer; public contract stays intact.
		if !GuestBindingApprovedByCompatibilityMap(p, b, issuer, GuestB509ProtocolCompatibilityMapSHA256) {
			t.Fatal("approved old contract lost historical issuer map")
		}
		b.GuestSourceCommit = strings.Repeat("f", 40)
		if GuestBindingApprovedByCompatibilityMap(p, b, issuer, GuestB509ProtocolCompatibilityMapSHA256) {
			t.Fatal("old map admitted a new Guest")
		}
	}
}
