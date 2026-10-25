package capacity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestCapacityMutationClosedProjection(t *testing.T) {
	id := uuid.NewString()
	spec := model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: "ensure_vm", IntegrationInstanceID: id, ScopeChecksum: strings.Repeat("a", 64), ProfileChecksum: strings.Repeat("b", 64), AdmissionChecksum: strings.Repeat("c", 64), ProfileName: "burst", Slot: 1, NativeName: "approved-slot-1", BootstrapSHA256: strings.Repeat("d", 64)}
	canonical, err := canonicalMutationProjection(spec)
	if err != nil {
		t.Fatal(err)
	}
	approved := spec
	p := model.CapacityPolicySpec{MutationBindings: []model.CapacityMutationBinding{{Name: "fleet", IntegrationInstanceID: id, ScopeChecksum: spec.ScopeChecksum, ProfileName: "burst", MaxSlots: 1, EnsureCapability: "ensure_vm", DestroyCapability: "destroy_vm", Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpecSHA256: fmt.Sprintf("%x", sha256.Sum256(canonical)), DesiredSpec: &approved}}}}}
	issue := model.CapacityMutationIssue{BindingName: "fleet", DesiredSpec: canonical}
	if _, err = PrepareMutationPlan(p, issue); err != nil {
		t.Fatal("approved closed projection", err)
	}
	missing := p
	missing.MutationBindings = append([]model.CapacityMutationBinding(nil), p.MutationBindings...)
	missing.MutationBindings[0].Slots = []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpecSHA256: p.MutationBindings[0].Slots[0].DesiredSpecSHA256}}
	if _, err := PrepareMutationPlan(missing, issue); err == nil {
		t.Fatal("digest-only slot silently admitted")
	}
	for _, key := range []string{"password", "credentials", "token", "cloud_init", "extra"} {
		t.Run("unknown_"+key, func(t *testing.T) {
			var fields map[string]any
			if err := json.Unmarshal(canonical, &fields); err != nil {
				t.Fatal(err)
			}
			fields[key] = "must never enter an authority digest"
			raw, _ := json.Marshal(fields)
			if _, err := PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: "fleet", DesiredSpec: raw}); err == nil {
				t.Fatal("unapproved field reached authority")
			}
		})
	}
	for _, raw := range []string{"null", "[]", string(canonical) + "{}", strings.Replace(string(canonical), `"slot":1`, `"slot":1.5`, 1)} {
		if _, err := PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: "fleet", DesiredSpec: json.RawMessage(raw)}); err == nil {
			t.Fatal("malformed or noninteger projection admitted")
		}
	}
	for _, nativeName := range []string{"__GENERATE__:postgres", "with spaces", "a/b", strings.Repeat("n", 64)} {
		changed := approved
		changed.NativeName = nativeName
		raw, _ := json.Marshal(changed)
		if _, err := PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: "fleet", DesiredSpec: raw}); err == nil {
			t.Fatal("noncanonical native name admitted", nativeName)
		}
	}
	spec.Capability = "destroy_vm"
	spec.ExpectedResourceID = "immutable-native-id"
	spec.ExpectedResourceCreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	issue.DesiredSpec, _ = json.Marshal(spec)
	destroy, err := PrepareMutationPlan(p, issue)
	if err != nil || destroy.RequestSHA256 != "" {
		t.Fatal("runtime tuple supplied a destroy digest before ledger binding", destroy, err)
	}
	if _, err := BindMutationDestroyPlan(destroy, "replacement-id", spec.ExpectedResourceCreatedAt); err == nil {
		t.Fatal("caller identity replaced registered immutable membership")
	}
	destroy, err = BindMutationDestroyPlan(destroy, spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt)
	if err != nil || destroy.RequestSHA256 == p.MutationBindings[0].Slots[0].DesiredSpecSHA256 || destroy.ExpectedResourceID != spec.ExpectedResourceID {
		t.Fatal("destroy tuple must bind a distinct digest of the approved base", destroy, err)
	}
	spec.BootstrapSHA256 = strings.Repeat("e", 64)
	issue.DesiredSpec, _ = json.Marshal(spec)
	if _, err := PrepareMutationPlan(p, issue); err == nil {
		t.Fatal("changed physical revision approved itself")
	}
}
