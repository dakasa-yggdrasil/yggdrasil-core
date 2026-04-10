package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateIntegrationInstanceCredentialStorage(t *testing.T) {
	t.Parallel()

	typeSpec := integrationTypeSpecFixture()
	typeSpec.CredentialPolicy = model.IntegrationCredentialPolicySpec{
		Source:            "secret_ref",
		MaterializeInline: true,
	}

	err := ValidateIntegrationInstanceCredentialStorage(model.IntegrationInstanceManifestSpec{
		CredentialsRef: "secret://global/github-app",
	}, typeSpec)
	if err != nil {
		t.Fatalf("ValidateIntegrationInstanceCredentialStorage(secret_ref) error: %v", err)
	}

	err = ValidateIntegrationInstanceCredentialStorage(model.IntegrationInstanceManifestSpec{
		Credentials: map[string]any{"token": "abc"},
	}, typeSpec)
	if err == nil {
		t.Fatal("expected inline credentials to fail for secret_ref storage policy")
	}
}

func TestValidateHydratedIntegrationInstanceInputs(t *testing.T) {
	t.Parallel()

	typeSpec := integrationTypeSpecFixture()
	err := ValidateHydratedIntegrationInstanceInputs(model.IntegrationInstanceManifestSpec{
		Credentials: map[string]any{
			"app_id":          "123456",
			"installation_id": "654321",
			"private_key_ref": "pem-data",
		},
		Config: map[string]any{
			"organization": "dakasa",
		},
	}, typeSpec)
	if err != nil {
		t.Fatalf("ValidateHydratedIntegrationInstanceInputs(valid) error: %v", err)
	}

	err = ValidateHydratedIntegrationInstanceInputs(model.IntegrationInstanceManifestSpec{
		Credentials: map[string]any{
			"app_id":          "123456",
			"installation_id": true,
			"private_key_ref": "pem-data",
		},
		Config: map[string]any{
			"organization": "dakasa",
		},
	}, typeSpec)
	if err == nil {
		t.Fatal("expected invalid credential type to fail validation")
	}
}
