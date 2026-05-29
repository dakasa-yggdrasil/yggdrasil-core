package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateIntegrationTypeSpec(t *testing.T) {
	spec := integrationTypeSpecFixture()

	if err := ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatalf("ValidateIntegrationTypeSpec error: %v", err)
	}
}

func TestValidateIntegrationTypeSpecRequiresCapabilityQueue(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Adapter.Queues.Execute = ""

	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected missing execute queue to fail validation")
	}
}

func TestValidateIntegrationTypeSpecAllowsHTTPJSONEndpoints(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Adapter.Transport = "http_json"
	spec.Adapter.Queues = model.IntegrationAdapterQueue{}
	spec.Adapter.Endpoints = model.IntegrationAdapterRoute{
		Describe: "/describe",
		Discover: "/discover",
		Read:     "/read",
		Execute:  "/execute",
		Sync:     "/sync",
		Health:   "/health",
	}

	if err := ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatalf("ValidateIntegrationTypeSpec(http_json) error: %v", err)
	}
}

func TestValidateIntegrationTypeSpecRejectsUnknownActionResourceType(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.ActionCatalog[0].ResourceTypes = []string{"unknown"}

	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected unknown resource type reference to fail validation")
	}
}

func TestValidateIntegrationTypeSpecRejectsCredentialPolicyConflict(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.CredentialPolicy = model.IntegrationCredentialPolicySpec{
		Source: "none",
	}

	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected conflicting credential policy to fail validation")
	}
}

// §15 amplification — Display/Icon optional but validated.

func TestValidateIntegrationTypeSpec_AcceptsValidDisplay(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Display = &model.IntegrationDisplaySpec{
		Subtitle: "Código, revisões e acesso aos repositórios.",
		SubtitleLocale: map[string]string{
			"pt-BR": "Código, revisões e acesso aos repositórios.",
			"en-US": "Code, reviews, and repository access.",
		},
	}
	if err := ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatalf("expected display block to be accepted, got: %v", err)
	}
}

func TestValidateIntegrationTypeSpec_RejectsDisplayWithoutSubtitle(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Display = &model.IntegrationDisplaySpec{}
	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected empty display block to be rejected")
	}
}

func TestValidateIntegrationTypeSpec_RejectsInvalidLocaleKey(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Display = &model.IntegrationDisplaySpec{
		SubtitleLocale: map[string]string{"PT_BR": "x"},
	}
	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected invalid locale key to be rejected")
	}
}

func TestValidateIntegrationTypeSpec_AcceptsValidIcon(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Icon = &model.IntegrationIconSpec{
		URL:       "data:image/svg+xml;utf8,<svg/>",
		Accent:    "#7c8cff",
		AriaLabel: "GitHub",
	}
	if err := ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatalf("expected icon block to be accepted, got: %v", err)
	}
}

func TestValidateIntegrationTypeSpec_AcceptsHTTPSIcon(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Icon = &model.IntegrationIconSpec{
		URL: "https://example.com/logo.svg",
	}
	if err := ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatalf("expected https icon URL to be accepted, got: %v", err)
	}
}

func TestValidateIntegrationTypeSpec_AcceptsRelativeIcon(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Icon = &model.IntegrationIconSpec{
		URL: "/brand/github.svg",
	}
	if err := ValidateIntegrationTypeSpec(spec); err != nil {
		t.Fatalf("expected relative icon URL to be accepted, got: %v", err)
	}
}

func TestValidateIntegrationTypeSpec_RejectsIconWithBadURL(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Icon = &model.IntegrationIconSpec{URL: "ftp://nope.example/x.svg"}
	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected non-http/data/relative icon URL to be rejected")
	}
}

func TestValidateIntegrationTypeSpec_RejectsIconWithBadAccent(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Icon = &model.IntegrationIconSpec{
		URL:    "/brand/x.svg",
		Accent: "purple",
	}
	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected non-hex accent to be rejected")
	}
}

func TestValidateIntegrationTypeSpec_RejectsIconWithMissingURL(t *testing.T) {
	spec := integrationTypeSpecFixture()
	spec.Icon = &model.IntegrationIconSpec{Accent: "#abcdef"}
	if err := ValidateIntegrationTypeSpec(spec); err == nil {
		t.Fatal("expected icon without URL to be rejected")
	}
}

func TestIntegrationTypeDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(integrationTypeSpecFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "integration_type",
		Metadata: model.ManifestMetadataInput{
			Name:      "github",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(integration_type) error: %v", err)
	}
}

func integrationTypeSpecFixture() model.IntegrationTypeManifestSpec {
	return model.IntegrationTypeManifestSpec{
		Provider: "github",
		Adapter: model.IntegrationAdapterSpec{
			Transport:      "rabbitmq",
			Version:        "1.0.0",
			TimeoutSeconds: 30,
			Queues: model.IntegrationAdapterQueue{
				Describe: "yggdrasil.adapter.github.describe",
				Discover: "yggdrasil.adapter.github.discover",
				Read:     "yggdrasil.adapter.github.read",
				Execute:  "yggdrasil.adapter.github.execute",
				Sync:     "yggdrasil.adapter.github.sync",
				Health:   "yggdrasil.adapter.github.health",
			},
		},
		Capabilities: []string{"describe", "discover", "read", "execute", "sync", "health"},
		CredentialPolicy: model.IntegrationCredentialPolicySpec{
			Source:            "inline_or_secret_ref",
			MaterializeInline: true,
		},
		CredentialSchema: model.IntegrationSchemaSpec{
			Mode:     "secret_ref",
			Required: []string{"app_id", "installation_id", "private_key_ref"},
			Properties: map[string]model.IntegrationSchemaProperty{
				"app_id": {
					Type: "string",
				},
				"installation_id": {
					Type: "string",
				},
				"private_key_ref": {
					Type:   "string",
					Secret: true,
				},
			},
		},
		InstanceSchema: model.IntegrationSchemaSpec{
			Mode:     "inline",
			Required: []string{"organization"},
			Properties: map[string]model.IntegrationSchemaProperty{
				"organization": {
					Type: "string",
				},
			},
		},
		ResourceTypes: []model.IntegrationResourceType{
			{
				Name:             "repository",
				CanonicalPrefix:  "thirdparty.github.org",
				IdentityTemplate: "repo.{organization}.{name}",
				Discoverable:     true,
				DefaultActions:   []string{"read", "create", "update", "delete", "grant", "revoke"},
			},
		},
		ActionCatalog: []model.IntegrationActionDefinition{
			{
				Name:          "grant",
				Description:   "Grant one repository permission",
				ResourceTypes: []string{"repository"},
				Idempotent:    true,
			},
			{
				Name:          "revoke",
				Description:   "Revoke one repository permission",
				ResourceTypes: []string{"repository"},
				Idempotent:    true,
			},
		},
		Discovery: model.IntegrationDiscoverySpec{
			Mode:             "hybrid",
			Cursor:           "incremental",
			SupportsWebhooks: true,
		},
		Normalization: model.IntegrationNormalizationSpec{
			ExternalIDPath:         "node_id",
			NamePath:               "name",
			OwnerPath:              "organization.login",
			FallbackResourcePrefix: "thirdparty.github.custom",
		},
		Execution: model.IntegrationExecutionSpec{
			SupportsDryRun:    true,
			IdempotentActions: []string{"grant", "revoke", "sync"},
		},
		Extensions: model.IntegrationExtensionsSpec{
			AllowCustomResourceTypes: true,
			AllowCustomActions:       true,
			PreserveRawPayload:       true,
		},
	}
}
