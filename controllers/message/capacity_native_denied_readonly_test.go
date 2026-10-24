//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeDeniedReadonlyExactRoleAndSourceCatalog(t *testing.T) {
	source := strings.Repeat("f", 40)
	raw, err := json.Marshal(expectedNativeDeniedReadonlyDescription(source))
	if err != nil || validateNativeDeniedReadonlyDescription(raw, source) != nil {
		t.Fatal("dedicated catalog refused", err)
	}
	var original map[string]any
	if json.Unmarshal(raw, &original) != nil {
		t.Fatal("fixture")
	}
	for key := range original {
		changed := make(map[string]any)
		for k, v := range original {
			changed[k] = v
		}
		delete(changed, key)
		body, _ := json.Marshal(changed)
		if validateNativeDeniedReadonlyDescription(body, source) == nil {
			t.Fatal("missing mandatory role field accepted", key)
		}
	}
	for key, wrong := range map[string]any{"provider": "aws", "version": "1.65.5", "source_commit": nativeDeniedAWSObserverSource, "transport": "rabbitmq", "operation": "create_ec2_instance", "normal_adapter_operations": true, "AMQP_registered": true, "native_mutations": 1, "original_adapter_source_commit": source} {
		changed := make(map[string]any)
		for k, v := range original {
			changed[k] = v
		}
		changed[key] = wrong
		body, _ := json.Marshal(changed)
		if validateNativeDeniedReadonlyDescription(body, source) == nil {
			t.Fatal("foreign role/source accepted", key)
		}
	}
	for _, invalid := range []string{"", "future", originalCreateDispositionAWSObserverSource, nativeDeniedAWSObserverSource} {
		if validateNativeDeniedReadonlyDescription(raw, invalid) == nil || nativeDeniedReadonlySourceReady(invalid) {
			t.Fatal("historical/unpublished source became dedicated", invalid)
		}
	}
	if describeNativeDeniedReadonly(nil, source) == nil {
		t.Fatal("missing owner admitted")
	}
	if _, err := executeNativeDeniedReadonly(context.Background(), nativeDeniedResolvedObserver{}, nil); err == nil {
		t.Fatal("missing request admitted")
	}
}

func TestNativeDeniedReadonlyHistoricalCoreWireProtocolProjection(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_aws_denied_historical_1654_type_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	gold, err := os.ReadFile("testdata/native_denied_1654_AWS_protocol_projection.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec model.IntegrationTypeManifestSpec
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("actual historical fixture")
	}
	projected, err := nativeDeniedHistoricalAWSWireType(spec)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if json.Unmarshal(gold, &expected) != nil || !reflect.DeepEqual(projected, expected) {
		t.Fatal("actual Core model cannot reach exact AWS protocol DTO")
	}
	if spec.Adapter.Version != "1.65.4" || projected["adapter"].(map[string]any)["version"] != "1.65.4" {
		t.Fatal("historical creator relabelled")
	}
	if _, exists := projected["credential_policy"]; exists {
		t.Fatal("Core-only metadata leaked into strict AWS DTO")
	}
	if _, exists := projected["guardian_support"]; exists {
		t.Fatal("Core-only metadata leaked into strict AWS DTO")
	}
	// Core-added action/UI declarations remain in the authenticated full catalog
	// but have no field in the historical AWS execution DTO.
	spec.ActionCatalog[0].InputSchema = map[string]any{"type": "object"}
	for key, p := range spec.CredentialSchema.Properties {
		p.Label = "Core-only UI"
		spec.CredentialSchema.Properties[key] = p
		break
	}
	again, err := nativeDeniedHistoricalAWSWireType(spec)
	if err != nil || !reflect.DeepEqual(again, expected) {
		t.Fatal("explicit protocol projection drift", err)
	}
}

func TestNativeDeniedReadonlyEnvelopePreservesHistoricalIdentityAndInput(t *testing.T) {
	observer := nativeDeniedResolvedObserver{}
	observer.typeSpec = model.IntegrationTypeManifestSpec{Provider: "aws", Adapter: model.IntegrationAdapterSpec{Version: "1.65.4"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "static"}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "static"}}
	observer.instanceSpec = model.IntegrationInstanceManifestSpec{Config: map[string]any{"original_capacity": map[string]any{"adapter_source_commit": originalCreateDispositionAWSObserverSource}}, Credentials: map[string]any{"DECLARED": "not-a-real-credential"}}
	fixed := map[string]any{"schema": "aws_original_authorization_denied_read_request_v1", "grant_created_at": "2026-10-23T22:50:12.95767Z"}
	request, err := nativeDeniedReadonlyEnvelope(observer, fixed)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var got model.AdapterExecuteIntegrationRequest
	if json.Unmarshal(body, &got) != nil || got.Operation != originalCreateDispositionOperation || got.Capability != originalCreateDispositionOperation || !reflect.DeepEqual(got.Input, fixed) || !reflect.DeepEqual(got.Integration.InstanceSpec, observer.instanceSpec) || got.Integration.TypeSpec.Adapter.Version != "1.65.4" {
		t.Fatal("historical request changed in dedicated routing")
	}
	fixed["grant_created_at"] = "changed"
	if got.Input["grant_created_at"] == fixed["grant_created_at"] {
		t.Fatal("wire input aliases caller map")
	}
}
