package message

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeReadinessCatalogPreservesExactOneSendPairAndIndependentRead(t *testing.T) {
	fixture := model.IntegrationTypeManifestSpec{Capabilities: []string{"execute"}, ResourceTypes: []model.IntegrationResourceType{{Name: "native_worker_probe_resource", DefaultActions: []string{capacity.EnsureNativeWorkerProbeResource, capacity.DestroyNativeWorkerProbeResource, capacity.ObserveNativeWorkerProbeResource}}}, ActionCatalog: []model.IntegrationActionDefinition{{Name: capacity.EnsureNativeWorkerProbeResource, Category: "capability", ResourceTypes: []string{"native_worker_probe_resource"}}, {Name: capacity.DestroyNativeWorkerProbeResource, Category: "capability", ResourceTypes: []string{"native_worker_probe_resource"}}, {Name: capacity.ObserveNativeWorkerProbeResource, Category: "capability", ResourceTypes: []string{"native_worker_probe_resource"}, Idempotent: true}}}
	for _, op := range []string{capacity.EnsureNativeWorkerProbeResource, capacity.DestroyNativeWorkerProbeResource, capacity.ObserveNativeWorkerProbeResource} {
		if !nativeProbeCatalogOperation(fixture, op) {
			t.Fatal("real dedicated resource operation refused", op)
		}
		for _, fault := range []string{"duplicate_action", "wrong_replay_semantics", "generic_resource", "missing_default_action", "duplicate_resource", "reactor", "no_execute"} {
			t.Run(op+"/"+fault, func(t *testing.T) {
				raw, err := json.Marshal(fixture)
				if err != nil {
					t.Fatal(err)
				}
				var mutated model.IntegrationTypeManifestSpec
				if json.Unmarshal(raw, &mutated) != nil {
					t.Fatal("fixture clone")
				}
				index := -1
				for i, a := range mutated.ActionCatalog {
					if a.Name == op {
						index = i
					}
				}
				switch fault {
				case "duplicate_action":
					mutated.ActionCatalog = append(mutated.ActionCatalog, mutated.ActionCatalog[index])
				case "wrong_replay_semantics":
					mutated.ActionCatalog[index].Idempotent = !mutated.ActionCatalog[index].Idempotent
				case "generic_resource":
					mutated.ActionCatalog[index].ResourceTypes = []string{"object"}
				case "missing_default_action":
					mutated.ResourceTypes[0].DefaultActions = nil
				case "duplicate_resource":
					mutated.ResourceTypes = append(mutated.ResourceTypes, mutated.ResourceTypes[0])
				case "reactor":
					mutated.ActionCatalog[index].Category = "reactor"
				case "no_execute":
					mutated.Capabilities = nil
				}
				if nativeProbeCatalogOperation(mutated, op) {
					t.Fatal("unqualified catalog/replay role accepted", fault)
				}
			})
		}
	}
	for _, legacy := range []string{"ensure_object", "destroy_object", "observe_object", "ensure_native_worker_pool", "observe_native_worker_phase", "ensure_native_worker"} {
		if nativeProbeCatalogOperation(fixture, legacy) {
			t.Fatal("dedicated diagnostic path gained other resource authority", legacy)
		}
	}
	if _, err := NewNativeWorkerReadinessSDKPorts(nil, nil, "", nil, nil, nil); err == nil {
		t.Fatal("unconfigured protected source ports became callable")
	}
}
