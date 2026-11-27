package message

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativePhysicalPrivateRPCRefusesAliasedAndReboundReply(t *testing.T) {
	b := model.CapacityNativeWorkerPhysicalReadBinding{Profile: "aws", Provider: "aws", Region: "us-east-1", Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 7, Checksum: strings.Repeat("a", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("b", 64)}, BindingName: "independent-read", SourceCommit: strings.Repeat("c", 40), ScopeSHA256: strings.Repeat("d", 64), Capability: capacity.ObserveNativeWorkerPhysical}
	request := model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: uuid.NewString(), ResourceID: "i-0123456789abcdef0", LaunchSHA256: strings.Repeat("e", 64)}
	o := model.CapacityNativeWorkerPhysicalObservation{SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: request}
	raw, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := nativePhysicalReadReply(b, request, "observed", json.RawMessage(raw)); e != nil || got.Requested != request {
		t.Fatal("exact protected RPC reply was lost", e)
	}
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"extraBindingDigest", strings.Replace(string(raw), `"binding_scope_sha256":`, `"observer_scope_sha256":"invented","binding_scope_sha256":`, 1)},
		{"duplicateScope", strings.Replace(string(raw), `"binding_scope_sha256":`, `"binding_scope_sha256":"invented","binding_scope_sha256":`, 1)},
		{"caseAlias", strings.Replace(string(raw), `"binding_scope_sha256"`, `"BindingScopeSHA256"`, 1)},
		{"nestedSelectorDuplicate", strings.Replace(string(raw), `"resource_id":"i-0123456789abcdef0"`, `"resource_id":"i-foreign","resource_id":"i-0123456789abcdef0"`, 1)},
		{"trailingJSON", string(raw) + ` {}`},
		{"wrongNumericVersion", strings.Replace(string(raw), `"version":7`, `"version":8`, 1)},
		{"changedCompiledSource", strings.Replace(string(raw), b.SourceCommit, strings.Repeat("f", 40), 1)},
		{"changedFileScope", strings.Replace(string(raw), b.ScopeSHA256, strings.Repeat("f", 64), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := nativePhysicalReadReply(b, request, "observed", json.RawMessage(tc.raw)); e == nil {
				t.Fatal("unbound or ambiguous reader response accepted")
			}
		})
	}
	if _, e := nativePhysicalReadReply(b, request, "succeeded", json.RawMessage(raw)); e == nil {
		t.Fatal("generic status masqueraded as an observed independent read")
	}
	if _, e := NewNativeWorkerPhysicalReadFunc(nil, nil)(t.Context(), b, request); e == nil {
		t.Fatal("uninstalled private database composition became an RPC capability")
	}
}

func TestNativePhysicalAWS58CatalogCrossesTheExistingPrivateResolverPredicate(t *testing.T) {
	// Exact native_worker catalog fragment from integration-aws Main58
	// 3dd75e462448c8596a3380bd95edcf40fdc55f30 internal/adapter/spec.go:
	// Describe resource at888 and action at6171. The complete pinned instance
	// and type are still checked by the existing resolver before hydration.
	const raw = `{"capabilities":["execute"],"resource_types":[{"name":"native_worker","canonical_prefix":"thirdparty.aws.native.worker","identity_template":"native_worker.{region}.{attempt_id}","discoverable":false,"default_actions":["ensure_native_worker","observe_native_worker"]}],"action_catalog":[{"name":"observe_native_worker","resource_types":["native_worker"],"idempotent":true,"category":"capability"}]}`
	var catalog model.IntegrationTypeManifestSpec
	if json.Unmarshal([]byte(raw), &catalog) != nil {
		t.Fatal("invalid original catalog fragment")
	}
	if !capacityBoundCatalogOperation(catalog, capacity.ObserveNativeWorkerPhysical) || !capacityNativeCatalogOperation(catalog, capacity.ObserveNativeWorkerPhysical) {
		t.Fatal("actual AWS58 read catalog cannot pass the pre-hydration resolver")
	}
	for _, fault := range []string{"noExecute", "wrongResource", "notDefault", "permission", "mutator"} {
		var bad model.IntegrationTypeManifestSpec
		if json.Unmarshal([]byte(raw), &bad) != nil {
			t.Fatal("bad fixture")
		}
		operation := capacity.ObserveNativeWorkerPhysical
		switch fault {
		case "noExecute":
			bad.Capabilities = nil
		case "wrongResource":
			bad.ActionCatalog[0].ResourceTypes = []string{"compute_offer"}
		case "notDefault":
			bad.ResourceTypes[0].DefaultActions = []string{"ensure_native_worker"}
		case "permission":
			bad.ActionCatalog[0].Category = "permission"
		case "mutator":
			operation = "ensure_native_worker"
			bad.ActionCatalog[0].Name = operation
		}
		if capacityBoundCatalogOperation(bad, operation) {
			t.Fatal("unregistered or mutable catalog crossed the physical read boundary", fault)
		}
	}
}
