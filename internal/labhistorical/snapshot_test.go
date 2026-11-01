package labhistorical

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func fixture(t *testing.T) ([]byte, model.CapacityVMFleetInventory, time.Time) {
	t.Helper()
	policy, err := os.ReadFile("testdata/aws-policy-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	inv := model.CapacityVMFleetInventory{IntegrationInstanceID: InstanceID, ScopeChecksum: ScopeChecksum, ProfileChecksum: ProfileSHA, AdmissionChecksum: AdmissionSHA, ProfileName: "notify-aws-elastic", ProtectedSlots: 1, MaxSlots: 8, MissingSlots: []int{1, 2, 3, 4, 5, 6, 7, 8}, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano)}
	return policy, inv, now
}

func TestDiagnosticHistoricalEmptyAndRejectedAlternatives(t *testing.T) {
	for _, kind := range []string{"exact", "instance_v4", "scope_v4", "old", "future", "incomplete", "missing_slot", "duplicate_slot", "provider_fence", "warm", "business", "profile", "admission", "member", "altered_policy", "unknown_field", "duplicate_field", "trailing_json"} {
		t.Run(kind, func(t *testing.T) {
			policy, inv, now := fixture(t)
			switch kind {
			case "instance_v4":
				inv.IntegrationInstanceID = "72ddfa74-c8f2-4e42-98a1-0d1d771afcdf"
			case "scope_v4":
				inv.ScopeChecksum = "f67f5c64c8e066709727e12968f62dfb8c2a6e2bdc4573ff7b608720b31847e1"
			case "old":
				inv.ObservationStartedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			case "future":
				inv.ObservedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
			case "incomplete":
				inv.Complete = false
			case "missing_slot":
				inv.MissingSlots = inv.MissingSlots[:7]
			case "duplicate_slot":
				inv.MissingSlots[7] = 1
			case "provider_fence":
				inv.ProviderFencingEvidence = true
			case "warm":
				inv.WarmReadinessEvidence = true
			case "business":
				inv.BusinessReadyEvidence = true
			case "profile":
				inv.ProfileChecksum = ScopeChecksum
			case "admission":
				inv.AdmissionChecksum = ScopeChecksum
			case "member":
				inv.Members = []model.CapacityVMFleetInventoryMember{{Slot: 1}}
			case "altered_policy":
				policy = append(policy, []byte("x")...)
			}
			wire, err := json.Marshal(inv)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unknown_field" {
				wire = append(wire[:len(wire)-1], []byte(`,"invented_proof":true}`)...)
			}
			if kind == "duplicate_field" {
				wire = append(wire[:len(wire)-1], []byte(`,"complete":true}`)...)
			}
			if kind == "trailing_json" {
				wire = append(wire, []byte(` {}`)...)
			}
			snapshot, err := DiagnosticSnapshot(policy, wire, now)
			if kind == "exact" {
				if err != nil || snapshot.Units != 0 || snapshot.ResourceUID != "original-vm-profile:"+InstanceID+":"+ScopeChecksum {
					t.Fatalf("exact historical fixture refused: %+v %v", snapshot, err)
				}
			} else if err == nil {
				t.Fatalf("unsafe %s accepted: %+v", kind, snapshot)
			}
		})
	}
}
