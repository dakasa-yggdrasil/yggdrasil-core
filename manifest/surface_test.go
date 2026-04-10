package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateSurfaceSpec(t *testing.T) {
	spec := surfaceSpecFixture()

	if err := ValidateSurfaceSpec(spec); err != nil {
		t.Fatalf("ValidateSurfaceSpec error: %v", err)
	}
}

func TestValidateSurfaceSpecRejectsDirectIntegrationBinding(t *testing.T) {
	spec := surfaceSpecFixture()
	spec.IntegrationBinding = "surface_direct"

	if err := ValidateSurfaceSpec(spec); err == nil {
		t.Fatal("expected unsupported integration binding to fail validation")
	}
}

func TestValidateSurfaceSpecRejectsInvalidCoreContract(t *testing.T) {
	spec := surfaceSpecFixture()
	spec.CoreContracts = append(spec.CoreContracts, "github")

	if err := ValidateSurfaceSpec(spec); err == nil {
		t.Fatal("expected invalid core contract to fail validation")
	}
}

func TestSurfaceDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(surfaceSpecFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "surface",
		Metadata: model.ManifestMetadataInput{
			Name:      "yggdrasil-auth-surface",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(surface) error: %v", err)
	}
}

func surfaceSpecFixture() model.SurfaceManifestSpec {
	return model.SurfaceManifestSpec{
		Category: "auth",
		Owners:   []string{"team:platform"},
		Replaces: []string{"auth", "identities"},
		Runtime: model.SurfaceRuntimeSpec{
			Kind:       "http_api",
			Exposure:   "collaborator",
			Port:       9090,
			BasePath:   "/",
			HealthPath: "/healthz",
		},
		CoreContracts:      []string{"authorization", "auth", "collaborator", "surface"},
		IntegrationBinding: "core_only",
		Capabilities: []model.SurfaceCapabilitySpec{
			{
				Name:     "collaborator-auth",
				Kind:     "auth_flow",
				Audience: "collaborator",
			},
			{
				Name:     "login",
				Kind:     "endpoint",
				Audience: "collaborator",
				Path:     "/api/v1/auth/login",
				Methods:  []string{"POST"},
			},
			{
				Name:     "session",
				Kind:     "endpoint",
				Audience: "collaborator",
				Path:     "/api/v1/auth/session",
				Methods:  []string{"GET"},
			},
			{
				Name:     "logout",
				Kind:     "endpoint",
				Audience: "collaborator",
				Path:     "/api/v1/auth/logout",
				Methods:  []string{"POST"},
			},
		},
	}
}
