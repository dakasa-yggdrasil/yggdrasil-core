//go:build !nativequalification

package message

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestOriginalAWSGuestSupplierUsesActualClosedCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_aws_type_v130.json")
	if err != nil {
		t.Fatal(err)
	}
	var original model.Manifest
	if json.Unmarshal(raw, &original) != nil {
		t.Fatal("physical sanitized AWS type fixture invalid")
	}
	legacy, err := manifest.ParseIntegrationTypeSpec(original.Spec)
	if err != nil || legacy.Adapter.Version != "1.59.1" {
		t.Fatal("physical AWS source witness drift", err)
	}
	if originalAWSGuestSupplierCatalog(legacy) {
		t.Fatal("legacy name-adopting AWS supplier became original capacity")
	}
	for _, kind := range []string{"candidate", "wrong_provider", "old_version", "wrong_transport", "foreign_endpoint", "missing_observe", "missing_native_resource", "duplicate_ensure"} {
		t.Run(kind, func(t *testing.T) {
			ts, err := manifest.ParseIntegrationTypeSpec(original.Spec)
			if err != nil {
				t.Fatal(err)
			}
			// Proposed source contract extends existing capabilities; no fake SQL
			// grant/profile is manufactured and no production catalog is changed.
			ts.Adapter.Version = "1.61.0"
			switch kind {
			case "wrong_provider":
				ts.Provider = "hetzner"
			case "old_version":
				ts.Adapter.Version = "1.59.1"
			case "wrong_transport":
				ts.Adapter.Transport = "rabbitmq"
			case "foreign_endpoint":
				ts.Adapter.Endpoints.Execute = "/other"
			case "missing_observe":
				for i := range ts.ActionCatalog {
					if ts.ActionCatalog[i].Name == "observe_ec2_instance" {
						ts.ActionCatalog = append(ts.ActionCatalog[:i], ts.ActionCatalog[i+1:]...)
						break
					}
				}
			case "missing_native_resource":
				for i := range ts.ResourceTypes {
					if ts.ResourceTypes[i].Name == "ec2_instance" {
						ts.ResourceTypes[i].DefaultActions = []string{"ensure_ec2_instance"}
					}
				}
			case "duplicate_ensure":
				for _, action := range ts.ActionCatalog {
					if action.Name == "ensure_ec2_instance" {
						ts.ActionCatalog = append(ts.ActionCatalog, action)
						break
					}
				}
			}
			if originalAWSGuestSupplierCatalog(ts) != (kind == "candidate") {
				t.Fatal("AWS closed catalog admission mismatch", kind)
			}
		})
	}
}

func TestOriginalAWSGuestSupplierRequiresIndependentSourcePin(t *testing.T) {
	source := strings.Repeat("a", 40)
	for _, kind := range []string{"exact", "wrong_mode", "wrong_source", "missing", "workflow_input"} {
		t.Run(kind, func(t *testing.T) {
			config := map[string]any{"mode": "original_aws_ec2_capacity_v1", "adapter_source_commit": source}
			spec := model.IntegrationInstanceManifestSpec{Config: map[string]any{"original_capacity": config}}
			switch kind {
			case "wrong_mode":
				config["mode"] = "generic"
			case "wrong_source":
				config["adapter_source_commit"] = strings.Repeat("b", 40)
			case "missing":
				delete(config, "adapter_source_commit")
			case "workflow_input":
				spec.Config = config
			}
			if originalGuestSupplierSourceConfigFor("aws", spec, source) != (kind == "exact") {
				t.Fatal("AWS source pin inferred from input", kind)
			}
		})
	}
}
