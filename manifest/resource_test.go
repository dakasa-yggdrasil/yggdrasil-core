package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateResourceSpec(t *testing.T) {
	spec := resourceSpecFixture()

	if err := ValidateResourceSpec(spec); err != nil {
		t.Fatalf("ValidateResourceSpec error: %v", err)
	}
}

func TestValidateResourceSpecRequiresInstanceRefForIntegration(t *testing.T) {
	spec := resourceSpecFixture()
	spec.Source.IntegrationInstanceRef = nil

	if err := ValidateResourceSpec(spec); err == nil {
		t.Fatal("expected missing integration_instance_ref to fail validation")
	}
}

func TestResourceDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(resourceSpecFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "resource",
		Metadata: model.ManifestMetadataInput{
			Name:      "github-dakasa-api-repo",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(resource) error: %v", err)
	}
}

func resourceSpecFixture() model.ResourceManifestSpec {
	return model.ResourceManifestSpec{
		Resource:    "thirdparty.github.org.dakasa.repo.api",
		Type:        "repository",
		DisplayName: "dakasa/api",
		Actions:     []string{"read", "update", "grant", "revoke"},
		Owners:      []string{"team:platform"},
		Source: model.ResourceSourceSpec{
			Kind: "integration",
			IntegrationTypeRef: &model.ManifestSelector{
				Name:      "github",
				Namespace: "global",
			},
			IntegrationInstanceRef: &model.ManifestSelector{
				Name:      "github-dakasa-prod",
				Namespace: "global",
			},
			ExternalID:   "R_kgDOExample",
			ExternalType: "repository",
		},
		Attributes: map[string]any{
			"visibility": "private",
			"archived":   false,
		},
		Raw: map[string]any{
			"provider": "github",
		},
	}
}
