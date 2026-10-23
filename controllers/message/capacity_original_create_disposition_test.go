//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func dispositionCatalogFixture(t *testing.T, provider string) model.IntegrationTypeManifestSpec {
	t.Helper()
	file := "capacity_hetzner_type_v1.json"
	version, kind, transport := "0.3.5", "server", "rabbitmq"
	if provider == "aws" {
		file = "capacity_aws_type_v130.json"
		version, kind, transport = "1.65.3", "ec2_instance", "http_json"
	}
	raw, err := os.ReadFile("../../repository/testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var m model.Manifest
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("invalid retained catalog fixture")
	}
	spec, err := manifest.ParseIntegrationTypeSpec(m.Spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Adapter.Version, spec.Adapter.Transport = version, transport
	add := func(name string) {
		found := false
		for _, a := range spec.ActionCatalog {
			if a.Name == name {
				found = true
			}
		}
		if !found {
			spec.ActionCatalog = append(spec.ActionCatalog, model.IntegrationActionDefinition{Name: name, ResourceTypes: []string{kind}, Idempotent: true})
		}
		for i := range spec.ResourceTypes {
			if spec.ResourceTypes[i].Name == kind {
				found = false
				for _, op := range spec.ResourceTypes[i].DefaultActions {
					if op == name {
						found = true
					}
				}
				if !found {
					spec.ResourceTypes[i].DefaultActions = append(spec.ResourceTypes[i].DefaultActions, name)
				}
			}
		}
	}
	add(originalCreateDispositionOperation)
	if provider == "aws" {
		add("observe_fleet_inventory")
	} else {
		add("destroy_server")
		add("observe_server_retirement")
	}
	return spec
}

func TestOriginalDispositionObserverCatalogAndSupplierRemainClosed(t *testing.T) {
	for _, provider := range []string{"hetzner", "aws"} {
		for _, mode := range []string{"exact", "old_version", "foreign_version", "foreign_transport", "foreign_endpoint", "missing_action", "duplicate_action", "not_idempotent", "unbound_resource"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				spec := dispositionCatalogFixture(t, provider)
				switch mode {
				case "old_version":
					if provider == "aws" {
						spec.Adapter.Version = "1.64.0"
					} else {
						spec.Adapter.Version = "0.3.4"
					}
				case "foreign_version":
					spec.Adapter.Version = "99.0.0"
				case "foreign_transport":
					spec.Adapter.Transport = "foreign"
				case "foreign_endpoint":
					if provider == "aws" {
						spec.Adapter.Endpoints.Execute = "/foreign"
					} else {
						spec.Adapter.Transport = "foreign"
					}
				case "missing_action":
					for i, a := range spec.ActionCatalog {
						if a.Name == originalCreateDispositionOperation {
							spec.ActionCatalog = append(spec.ActionCatalog[:i], spec.ActionCatalog[i+1:]...)
							break
						}
					}
				case "duplicate_action":
					for _, a := range spec.ActionCatalog {
						if a.Name == originalCreateDispositionOperation {
							spec.ActionCatalog = append(spec.ActionCatalog, a)
							break
						}
					}
				case "not_idempotent":
					for i := range spec.ActionCatalog {
						if spec.ActionCatalog[i].Name == originalCreateDispositionOperation {
							spec.ActionCatalog[i].Idempotent = false
						}
					}
				case "unbound_resource":
					for i := range spec.ActionCatalog {
						if spec.ActionCatalog[i].Name == originalCreateDispositionOperation {
							spec.ActionCatalog[i].ResourceTypes = []string{"foreign"}
						}
					}
				}
				want := mode == "exact" && len(dispositionObserverSource(provider)) == 40
				if dispositionObserverCatalog(provider, spec) != want {
					t.Fatal("observer admitted an unreviewed catalog/source", mode)
				}
			})
		}
		spec := dispositionCatalogFixture(t, provider)
		if !originalGuestSupplierCatalogFor(provider, spec) || !productionRetirementCatalogV2(provider, spec) {
			t.Fatal("new version lost existing lifecycle contract", provider)
		}
		source := dispositionObserverSource(provider)
		if originalGuestSupplierCatalogSourceFor(provider, spec, strings.Repeat("f", 40)) {
			t.Fatal("unreviewed new supplier source accepted", provider)
		}
		if len(source) == 40 && !originalGuestSupplierCatalogSourceFor(provider, spec, source) {
			t.Fatal("reviewed new supplier source refused", provider)
		}
	}
}

func TestOriginalDispositionAWSObserverVersionSourcePairs(t *testing.T) {
	current := dispositionCatalogFixture(t, "aws")
	historical := []struct{ version, source string }{
		{"1.65.1", originalCreateDispositionAWS1651Source},
		{"1.65.2", originalCreateDispositionAWS1652Source},
	}
	for _, pair := range historical {
		legacy := current
		legacy.Adapter.Version = pair.version
		if dispositionObserverCatalog("aws", legacy) {
			t.Fatal("historical observer became the current disposition observer", pair.version)
		}
		if !originalGuestSupplierCatalogFor("aws", legacy) || !productionRetirementCatalogV2("aws", legacy) || !originalGuestSupplierCatalogSourceFor("aws", legacy, pair.source) {
			t.Fatal("historical supplier/retirement source pair changed", pair.version)
		}
		for _, source := range []string{originalCreateDispositionAWSObserverSource, strings.Repeat("f", 40)} {
			if originalGuestSupplierCatalogSourceFor("aws", legacy, source) {
				t.Fatal("historical version accepted crossed source", pair.version)
			}
		}
		if originalGuestSupplierCatalogSourceFor("aws", current, pair.source) {
			t.Fatal("current observer accepted historical source", pair.version)
		}
	}
	for _, pair := range historical {
		other := current
		other.Adapter.Version = pair.version
		for _, foreign := range historical {
			if foreign.version != pair.version && originalGuestSupplierCatalogSourceFor("aws", other, foreign.source) {
				t.Fatal("historical pairs crossed", pair.version, foreign.version)
			}
		}
	}
	if originalGuestSupplierCatalogSourceFor("aws", current, strings.Repeat("f", 40)) {
		t.Fatal("unreviewed current source accepted")
	}
}

func TestOriginalDispositionAWS1653RequiresWholeLifecycleCatalog(t *testing.T) {
	for _, version := range []string{"1.65.2", "1.65.3"} {
		for _, operation := range []string{"ensure_ec2_instance", "observe_ec2_instance", "terminate_ec2_instance", "observe_fleet_inventory"} {
			t.Run(version+"/missing_"+operation, func(t *testing.T) {
				spec := dispositionCatalogFixture(t, "aws")
				spec.Adapter.Version = version
				for i, a := range spec.ActionCatalog {
					if a.Name == operation {
						spec.ActionCatalog = append(spec.ActionCatalog[:i], spec.ActionCatalog[i+1:]...)
						break
					}
				}
				if originalGuestSupplierCatalogFor("aws", spec) || productionRetirementCatalogV2("aws", spec) {
					t.Fatal("incomplete lifecycle catalog accepted")
				}
			})
		}
	}
}

func TestOriginalDispositionBridgeRefusesUnownedCallsAndForeignOutput(t *testing.T) {
	if _, err := RecordOriginalCreateDisposition(context.Background(), nil, nil, "220f344f-4ea9-4fbc-a195-2c1b1c5212b6", "root"); err == nil {
		t.Fatal("nil bridge became authority")
	}
	var out model.CapacityOriginalCreateDispositionObservation
	if capacityDecodeDisposition(map[string]any{"resource_absence_complete": true, "Root_claim": true}, &out) == nil {
		t.Fatal("caller selected unknown authority fields")
	}
	for _, provider := range []string{"aws", "hetzner"} {
		source := dispositionObserverSource(provider)
		field := "fleet"
		config := map[string]any{"original_create_source_commit": source}
		if provider == "aws" {
			field = "original_capacity"
			config = map[string]any{"mode": "original_aws_ec2_capacity_v1", "adapter_source_commit": source}
		}
		spec := model.IntegrationInstanceManifestSpec{Config: map[string]any{field: config}}
		if originalGuestSupplierSourceConfigFor(provider, spec, source) != (len(source) == 40) {
			t.Fatal("observer source gate changed", provider)
		}
	}
}

func TestOriginalDispositionPrivateReadCannotEscapeThroughGenericExecute(t *testing.T) {
	op := originalCreateDispositionOperation
	for _, v := range []struct {
		name, operation, capability string
		policy                      integrationExecutionPolicy
		allowed                     bool
	}{
		{"ordinary", "ensure_server", "ensure_server", integrationExecutionPolicy{}, true},
		{"generic_operation", op, "", integrationExecutionPolicy{}, false},
		{"generic_capability", "observe_servers", op, integrationExecutionPolicy{}, false},
		{"sensitive_permission", op, op, integrationExecutionPolicy{allowSensitiveOutput: true}, false},
		{"case_or_whitespace", " " + strings.ToUpper(op) + " ", "", integrationExecutionPolicy{}, false},
		{"private_exact", op, op, integrationExecutionPolicy{originalCreateDisposition: true}, true},
		{"private_other_operation", "ensure_server", "ensure_server", integrationExecutionPolicy{originalCreateDisposition: true}, false},
		{"private_mismatched_alias", op, "observe_servers", integrationExecutionPolicy{originalCreateDisposition: true}, false},
	} {
		t.Run(v.name, func(t *testing.T) {
			req := model.ExecuteIntegrationRequest{Operation: v.operation, Capability: v.capability, Metadata: map[string]any{"originalCreateDisposition": true}}
			if originalDispositionExecutionAllowed(req, v.policy) != v.allowed {
				t.Fatal("private native body read escaped", v.name)
			}
			if !v.allowed {
				// A nil context/transport would panic if the call crossed the
				// central guard. Rejection must precede any native owner.
				if _, err := executeIntegrationThroughResolvedWithPolicy(nil, nil, req, model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, 0, v.policy); err == nil {
					t.Fatal("central private read guard not applied")
				}
			}
		})
	}
}
