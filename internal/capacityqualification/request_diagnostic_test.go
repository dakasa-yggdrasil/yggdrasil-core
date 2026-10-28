//go:build nativequalification

package capacityqualification

import (
	"encoding/json"
	"testing"

	contractdocs "github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// TestExecuteRequestMatchesClosedContracts uses the actual fixed Describe
// type and the same request fields as the native workflow read. It is an
// isolated serialization test, not a broker/QEMU execution claim.
func TestExecuteRequestMatchesClosedContracts(t *testing.T) {
	d, err := NativeDescribe()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var spec model.IntegrationTypeManifestSpec
	if err = json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	typID, instanceID := uuid.New(), uuid.New()
	typ := model.ManifestReference{ID: typID, Kind: "integration_type", Namespace: "synthetic-ci", Name: "original-native-qemu", Version: 1}
	instance := model.ManifestReference{ID: instanceID, Kind: "integration_instance", Namespace: "synthetic-ci", Name: "original-native-qemu", Version: 1}
	req := model.AdapterExecuteIntegrationRequest{Operation: capacity.VMObserveServer, Capability: capacity.VMObserveServer, Input: map[string]any{"profile": "native-qemu", "slot": 2, "grant_id": uuid.NewString(), "expected_resource_id": uuid.NewString(), "expected_resource_created_at": "2026-10-28T13:58:33Z"}, Integration: model.AdapterExecuteIntegrationContext{Type: typ, TypeSpec: spec, Instance: instance, InstanceSpec: model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typID.String()}}}}
	if err = contractdocs.Validate(contractdocs.FamilyIntegrationAdapterV1, "adapterExecuteIntegrationRequest", req); err != nil {
		t.Fatalf("source execute contract: %v", err)
	}
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip model.AdapterExecuteIntegrationRequest
	if err = capacity.DecodeGuestLifecycle(wire, &roundtrip); err != nil {
		t.Fatalf("closed consumer request: %v", err)
	}
	if roundtrip.Operation != capacity.VMObserveServer || roundtrip.Capability != capacity.VMObserveServer || roundtrip.Input["slot"] != float64(2) || len(roundtrip.Auth) != 0 || len(roundtrip.Metadata) != 0 {
		t.Fatal("decoded source request differs")
	}
}
