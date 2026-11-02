//go:build !nativequalification

package message

import (
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalAWS1655NormalSupplierKeepsExactSourceAndLifecycle(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_aws_denied_source_expected_1655_type_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exact", "old_source", "foreign_source", "missing_ensure_ec2_instance", "missing_observe_ec2_instance", "missing_terminate_ec2_instance", "missing_observe_fleet_inventory", "foreign_transport"} {
		t.Run(name, func(t *testing.T) {
			ts, e := manifest.ParseIntegrationTypeSpec(raw)
			if e != nil || ts.Adapter.Version != "1.65.5" {
				t.Fatal("authentic published catalog", e)
			}
			source := originalAWS1655SupplierSource
			switch name {
			case "old_source":
				source = originalCreateDispositionAWSObserverSource
			case "foreign_source":
				source = strings.Repeat("f", 40)
			case "foreign_transport":
				ts.Adapter.Transport = "rabbitmq"
			default:
				if strings.HasPrefix(name, "missing_") {
					operation := strings.TrimPrefix(name, "missing_")
					for i, a := range ts.ActionCatalog {
						if a.Name == operation {
							ts.ActionCatalog = append(ts.ActionCatalog[:i], ts.ActionCatalog[i+1:]...)
							break
						}
					}
				}
			}
			want := name == "exact"
			if originalGuestSupplierCatalogSourceFor("aws", ts, source) != want || productionRetirementCatalogV2("aws", ts) != (name == "exact" || name == "old_source" || name == "foreign_source") {
				t.Fatal("new supplier source/lifecycle crossed", name)
			}
			if want {
				instance := model.IntegrationInstanceManifestSpec{Config: map[string]any{"original_capacity": map[string]any{"mode": "original_aws_ec2_capacity_v1", "adapter_source_commit": source}}}
				if !originalGuestSupplierSourceConfigFor("aws", instance, source) || originalGuestSupplierSourceConfigFor("aws", instance, originalCreateDispositionAWSObserverSource) {
					t.Fatal("current IID config relabelled historical source")
				}
			}
			if dispositionObserverCatalog("aws", ts) {
				t.Fatal("normal1655 became historical1654 accepted observer")
			}
		})
	}
}
