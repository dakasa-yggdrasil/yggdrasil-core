//go:build !nativequalification

package message

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestOriginalGuestSupplierPinsPublicAdapterSource(t *testing.T) {
	for _, name := range []string{"exact", "missing", "foreign", "malformed", "workflow_input"} {
		t.Run(name, func(t *testing.T) {
			source := strings.Repeat("a", 40)
			config := map[string]any{"original_create_source_commit": source}
			spec := model.IntegrationInstanceManifestSpec{Config: map[string]any{"fleet": config}}
			switch name {
			case "missing":
				delete(config, "original_create_source_commit")
			case "foreign":
				config["original_create_source_commit"] = strings.Repeat("b", 40)
			case "malformed":
				source = "head"
			case "workflow_input":
				spec.Config = map[string]any{"original_create_source_commit": source}
			}
			if originalGuestSupplierSourceConfig(spec, source) != (name == "exact") {
				t.Fatal("adapter source pin admission mismatch")
			}
		})
	}
}

func TestProductionOriginalGuestWitnessRefusesUnsupportedSources(t *testing.T) {
	for _, provider := range []string{"aws", "native-qemu", ""} {
		if repository.OriginalGuestCreateWitnessProviderEnabled(provider) {
			t.Fatalf("production gained an unimplemented original create witness: %q", provider)
		}
	}
}

func TestOriginalGuestSupplierRequiresActualClosedCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../repository/testdata/capacity_hetzner_type_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var original model.Manifest
	if err = json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original", "provider", "transport", "version", "ensure_not_idempotent", "missing_observation", "duplicate_action"} {
		t.Run(name, func(t *testing.T) {
			ts, err := manifest.ParseIntegrationTypeSpec(original.Spec)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "provider":
				ts.Provider = "aws"
			case "transport":
				ts.Adapter.Transport = "http_json"
			case "version":
				ts.Adapter.Version = "0.1.1"
			case "ensure_not_idempotent":
				for n := range ts.ActionCatalog {
					if ts.ActionCatalog[n].Name == "ensure_server" {
						ts.ActionCatalog[n].Idempotent = false
					}
				}
			case "missing_observation":
				for n := range ts.ActionCatalog {
					if ts.ActionCatalog[n].Name == "observe_server_action" {
						ts.ActionCatalog[n].Name = "unreviewed_observation"
					}
				}
			case "duplicate_action":
				for _, a := range ts.ActionCatalog {
					if a.Name == "ensure_server" {
						ts.ActionCatalog = append(ts.ActionCatalog, a)
						break
					}
				}
			}
			if originalGuestSupplierCatalog(ts) != (name == "original") {
				t.Fatalf("unexpected catalog admission for %s", name)
			}
		})
	}
}
