//go:build linux && nativequalification

package message

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestSourceNativeReadoptionUsesCanonicalApprovedPlan(t *testing.T) {
	spec := model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: "ensure_vm", IntegrationInstanceID: uuid.NewString(), ScopeChecksum: strings.Repeat("a", 64), ProfileChecksum: strings.Repeat("b", 64), AdmissionChecksum: strings.Repeat("c", 64), ProfileName: "base", Slot: 2, NativeName: "node-2", BootstrapSHA256: strings.Repeat("d", 64)}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	// The authority digest is the canonical sorted closed map, not struct order.
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture decode")
	}
	canonical, _ := json.Marshal(fields)
	sum := sha256.Sum256(canonical)
	b := model.CapacityMutationBinding{Name: "fleet", IntegrationInstanceID: spec.IntegrationInstanceID, ScopeChecksum: spec.ScopeChecksum, ProfileName: spec.ProfileName, MaxSlots: 2, EnsureCapability: "ensure_vm", DestroyCapability: "destroy_vm", Slots: []model.CapacityMutationSlotBinding{{Slot: 2, DesiredSpec: &spec, DesiredSpecSHA256: fmt.Sprintf("%x", sum)}}}
	p := model.CapacityPolicySpec{MutationBindings: []model.CapacityMutationBinding{b}}
	plan, err := capacity.PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw})
	if err != nil {
		t.Fatal("approved create", err)
	}
	if capacity.BusinessCreationSHA256(raw) == plan.RequestSHA256 {
		t.Fatal("fixture does not expose encoding mismatch")
	}
	proof := model.CapacityMutationProof{BindingName: b.Name, Slot: 2, RequestSHA256: plan.RequestSHA256}
	got, err := sourceNativeReadoptionDesired(p, b, proof)
	if err != nil || string(got) != string(raw) {
		t.Fatal("canonical original was refused", err)
	}
	for _, bad := range []model.CapacityMutationProof{{BindingName: "other", Slot: 2, RequestSHA256: plan.RequestSHA256}, {BindingName: b.Name, Slot: 1, RequestSHA256: plan.RequestSHA256}, {BindingName: b.Name, Slot: 2, RequestSHA256: capacity.BusinessCreationSHA256(raw)}} {
		if _, err := sourceNativeReadoptionDesired(p, b, bad); err == nil {
			t.Fatal("foreign original projection accepted")
		}
	}
	changed := spec
	changed.NativeName = "changed"
	changedB := b
	changedB.Slots = append([]model.CapacityMutationSlotBinding(nil), b.Slots...)
	changedB.Slots[0].DesiredSpec = &changed
	if _, err := sourceNativeReadoptionDesired(p, changedB, proof); err == nil {
		t.Fatal("unapproved desired projection accepted")
	}
}
