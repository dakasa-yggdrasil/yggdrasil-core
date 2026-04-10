package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateIntegrationInstanceSpec(t *testing.T) {
	spec := integrationInstanceSpecFixture()

	if err := ValidateIntegrationInstanceSpec(spec); err != nil {
		t.Fatalf("ValidateIntegrationInstanceSpec error: %v", err)
	}
}

func TestValidateIntegrationInstanceSpecRequiresTypeRef(t *testing.T) {
	spec := integrationInstanceSpecFixture()
	spec.TypeRef = model.ManifestSelector{}

	if err := ValidateIntegrationInstanceSpec(spec); err == nil {
		t.Fatal("expected missing type_ref to fail validation")
	}
}

func TestValidateIntegrationInstanceSpecAllowsCredentialsRef(t *testing.T) {
	spec := integrationInstanceSpecFixture()
	spec.Credentials = nil
	spec.CredentialsRef = "secret://github/platform"

	if err := ValidateIntegrationInstanceSpec(spec); err != nil {
		t.Fatalf("ValidateIntegrationInstanceSpec(credentials_ref) error: %v", err)
	}
}

func TestValidateIntegrationInstanceSpecRejectsInvalidCredentialsRef(t *testing.T) {
	spec := integrationInstanceSpecFixture()
	spec.CredentialsRef = "vault://github/platform"

	if err := ValidateIntegrationInstanceSpec(spec); err == nil {
		t.Fatal("expected invalid credentials_ref to fail validation")
	}
}

func TestIntegrationInstanceDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(integrationInstanceSpecFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "integration_instance",
		Metadata: model.ManifestMetadataInput{
			Name:      "github-dakasa-prod",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(integration_instance) error: %v", err)
	}
}

func integrationInstanceSpecFixture() model.IntegrationInstanceManifestSpec {
	return model.IntegrationInstanceManifestSpec{
		TypeRef: model.ManifestSelector{
			Name:      "github",
			Namespace: "global",
		},
		Status: "active",
		Owners: []string{"team:platform"},
		Credentials: map[string]any{
			"private_key_ref": "secret://github/private-key",
			"app_id":          "123456",
		},
		Config: map[string]any{
			"organization": "dakasa",
		},
		Discovery: model.IntegrationInstanceDiscoverySpec{
			Enabled:             true,
			Mode:                "hybrid",
			SyncIntervalSeconds: 300,
		},
		Execution: model.IntegrationInstanceExecutionSpec{
			DefaultDryRun: false,
			MaxBatchSize:  100,
		},
	}
}
