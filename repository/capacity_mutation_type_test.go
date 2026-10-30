package repository

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func mutationTypeFixture() model.IntegrationTypeManifestSpec {
	return model.IntegrationTypeManifestSpec{
		Provider:         "fixture",
		Adapter:          model.IntegrationAdapterSpec{Transport: "rabbitmq", Version: "0.1.0", TimeoutSeconds: 65, Queues: model.IntegrationAdapterQueue{Describe: "fixture.describe", Execute: "fixture.execute"}},
		Capabilities:     []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"},
		InstanceSchema:   model.IntegrationSchemaSpec{Mode: "none"},
		ResourceTypes:    []model.IntegrationResourceType{{Name: "server", CanonicalPrefix: "thirdparty.fixture.server", IdentityTemplate: "server.{id}", DefaultActions: []string{"ensure_server", "destroy_server"}}},
		ActionCatalog: []model.IntegrationActionDefinition{
			{Name: "ensure_server", ResourceTypes: []string{"server"}, Idempotent: true},
			{Name: "destroy_server", ResourceTypes: []string{"server"}, Idempotent: true},
		},
		Discovery:     model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"},
		Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.fixture.custom"},
		Execution:     model.IntegrationExecutionSpec{SupportsDryRun: true, IdempotentActions: []string{"ensure_server", "destroy_server"}},
	}
}

func TestCapacityMutationRegisteredTypeContract(t *testing.T) {
	b := model.CapacityMutationBinding{EnsureCapability: "ensure_server", DestroyCapability: "destroy_server"}
	for _, tc := range []struct {
		name   string
		change func(*model.IntegrationTypeManifestSpec)
		valid  bool
	}{
		{"registered_transport_and_catalog", func(*model.IntegrationTypeManifestSpec) {}, true},
		{"explicit_capability_category", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog[0].Category = "capability" }, true},
		{"resource_actions_are_not_transport_capabilities", func(s *model.IntegrationTypeManifestSpec) {
			s.Capabilities = []string{"ensure_server", "destroy_server"}
		}, false},
		{"execute_transport_missing", func(s *model.IntegrationTypeManifestSpec) { s.Capabilities = []string{"describe"} }, false},
		{"execute_queue_missing", func(s *model.IntegrationTypeManifestSpec) { s.Adapter.Queues.Execute = "" }, false},
		{"ensure_catalog_missing", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog = s.ActionCatalog[1:] }, false},
		{"destroy_catalog_missing", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog = s.ActionCatalog[:1] }, false},
		{"catalog_wrong_resource", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog[0].ResourceTypes = []string{"other"} }, false},
		{"catalog_unscoped_action", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog[0].ResourceTypes = nil }, false},
		{"ensure_default_missing", func(s *model.IntegrationTypeManifestSpec) {
			s.ResourceTypes[0].DefaultActions = []string{"destroy_server"}
		}, false},
		{"destroy_default_missing", func(s *model.IntegrationTypeManifestSpec) {
			s.ResourceTypes[0].DefaultActions = []string{"ensure_server"}
		}, false},
		{"permission_is_not_dispatched", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog[0].Category = "permission" }, false},
		{"reactor_is_not_dispatched", func(s *model.IntegrationTypeManifestSpec) { s.ActionCatalog[1].Category = "reactor" }, false},
		{"duplicate_catalog_refused", func(s *model.IntegrationTypeManifestSpec) {
			s.ActionCatalog = append(s.ActionCatalog, s.ActionCatalog[0])
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mutationTypeFixture()
			tc.change(&s)
			raw, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			provider, resource, err := capacityMutationTypeIdentity(raw, b)
			if tc.valid {
				if err != nil || provider != "fixture" || resource != "server" {
					t.Fatal(provider, resource, err)
				}
			} else if !errors.Is(err, ErrCapacityConflict) || provider != "" || resource != "" {
				t.Fatal("invalid registered action authorized", provider, resource, err)
			}
		})
	}
}

func TestCapacityMutationActualHetznerType(t *testing.T) {
	// Copied byte-for-byte from integration-hetzner cddc784604e7bdb26717c36c2cff242558a781aa.
	// This is an adapter registration contract, not an invented transport fixture.
	raw, err := os.ReadFile("testdata/capacity_hetzner_type_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Spec json.RawMessage `json:"spec"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	spec, err := manifest.ParseIntegrationTypeSpec(doc.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = manifest.ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatal(err)
	}
	provider, resource, err := capacityMutationTypeIdentity(doc.Spec, model.CapacityMutationBinding{EnsureCapability: "ensure_server", DestroyCapability: "destroy_server"})
	if err != nil || provider != "hetzner" || resource != "server" {
		t.Fatal(provider, resource, err)
	}
}
