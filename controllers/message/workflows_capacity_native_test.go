package message

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestCapacityNativeCatalogUsesActualRegistrationContract(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_hetzner_type_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document model.ManifestDocument
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	ts, err := manifest.ParseIntegrationTypeSpec(document.Spec)
	if err != nil || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		t.Fatal("real adapter registry is invalid", err)
	}
	for _, op := range []string{"observe_fleet_inventory", "observe_failed_server_creation", "observe_servers", "observe_server_action"} {
		if !capacityNativeCatalogOperation(ts, op) {
			t.Fatal("real observer action unavailable", op)
		}
	}
	if capacityNativeCatalogOperation(ts, "ensure_server") || capacityNativeCatalogOperation(ts, "destroy_server") {
		t.Fatal("native observation can choose a mutator")
	}
	for i := range ts.ActionCatalog {
		if ts.ActionCatalog[i].Name == "observe_fleet_inventory" {
			ts.ActionCatalog[i].Category = "permission"
		}
	}
	if capacityNativeCatalogOperation(ts, "observe_fleet_inventory") {
		t.Fatal("permission action became dispatched observer")
	}
}

func TestCapacityNativeFailedReadbackPinsStoredLifetimeAndKnownActions(t *testing.T) {
	r := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: "parent", RequestSHA256: "digest"}, ActionID: "known", NativeReadback: &model.CapacityMutationProof{ResourceID: "native", ResourceCreatedAt: "2026-10-08T00:00:00Z", ObservedCreationGrantID: "parent", ActionIDs: []string{"known", "next"}}}
	c := model.CapacityVMFailedCreationCandidate{ParentGrantID: "parent", Plan: model.CapacityVMFleetPlan{RequestSHA256: "digest", Server: &model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: "native", CreatedAt: "2026-10-08T00:00:00Z"}}}, Actions: model.CapacityVMActionCollection{Actions: []model.CapacityVMActionObservation{{ID: "known"}, {ID: "next"}}}}
	if !capacityNativeFailedReadbackMatches(r, &c) {
		t.Fatal("same immutable lifetime rejected")
	}
	raw, _ := json.Marshal(c)
	var changed model.CapacityVMFailedCreationCandidate
	json.Unmarshal(raw, &changed)
	changed.Plan.Server.CreatedAt = "2026-10-08T00:00:01Z"
	if capacityNativeFailedReadbackMatches(r, &changed) {
		t.Fatal("stored readback lifetime was replaced")
	}
	c.Actions.Actions = c.Actions.Actions[:1]
	if capacityNativeFailedReadbackMatches(r, &c) {
		t.Fatal("stored action coverage was dropped")
	}
}
