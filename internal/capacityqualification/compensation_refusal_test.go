//go:build nativequalification

package capacityqualification

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestCompensationBindingDisabledRefusal(t *testing.T) {
	id := uuid.NewString()
	ensure := model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: "ensure_vm", IntegrationInstanceID: id, ScopeChecksum: strings.Repeat("a", 64), ProfileChecksum: strings.Repeat("b", 64), AdmissionChecksum: strings.Repeat("c", 64), ProfileName: "burst", Slot: 1, NativeName: "approved-slot-1", BootstrapSHA256: strings.Repeat("d", 64)}
	canonical, err := json.Marshal(map[string]any{"schema_version": ensure.SchemaVersion, "capability": ensure.Capability, "integration_instance_id": ensure.IntegrationInstanceID, "scope_checksum": ensure.ScopeChecksum, "profile_checksum": ensure.ProfileChecksum, "admission_checksum": ensure.AdmissionChecksum, "profile_name": ensure.ProfileName, "slot": ensure.Slot, "native_name": ensure.NativeName, "bootstrap_sha256": ensure.BootstrapSHA256})
	if err != nil {
		t.Fatal(err)
	}
	binding := model.CapacityMutationBinding{Name: "fleet", IntegrationInstanceID: id, ScopeChecksum: ensure.ScopeChecksum, ProfileName: ensure.ProfileName, MaxSlots: 1, EnsureCapability: "ensure_vm", DestroyCapability: "destroy_vm", Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpecSHA256: fmt.Sprintf("%x", sha256.Sum256(canonical)), DesiredSpec: &ensure}}}
	policy := model.CapacityPolicySpec{MutationBindings: []model.CapacityMutationBinding{binding}}
	destroy := ensure
	destroy.Capability = binding.DestroyCapability
	destroy.ExpectedResourceID = "synthetic-resource"
	destroy.ExpectedResourceCreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(destroy)
	if err != nil {
		t.Fatal(err)
	}
	issue := model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: raw}
	if _, err = capacity.PrepareCompensationPlan(policy, issue); !IsCompensationPlanNotEnabledDestroy(err) {
		t.Fatalf("disabled binding did not return the expected fixed refusal: %v", err)
	}
	policy.MutationBindings[0].CompensationEnabled = true
	if _, err = capacity.PrepareCompensationPlan(policy, issue); err != nil {
		t.Fatalf("enabled control did not reach an accepted plan: %v", err)
	}
	ensureRaw, err := json.Marshal(ensure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = capacity.PrepareCompensationPlan(policy, model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: ensureRaw}); !IsCompensationPlanNotEnabledDestroy(err) {
		t.Fatalf("enabled binding plus ensure must yield the same planner refusal: %v", err)
	}
	for _, err := range []error{nil, errors.New("capacity execution is disabled"), errors.New("capacity intent conflict"), errors.New("capacity compensation requires an explicitly enabled destroy binding plus extra")} {
		if IsCompensationPlanNotEnabledDestroy(err) {
			t.Fatalf("unrelated refusal accepted as binding-disabled: %v", err)
		}
	}
}
