package manifest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestIntegrationSchemaPropertyUIMetadataRoundTrip is the §15
// (INTEGRATION_CONTRACT) acceptance test: every UI hint declared by an
// adapter must survive JSON marshal/unmarshal verbatim so surfaces can
// render forms generically without per-provider hardcoding.
//
// Mirrors the example payload in §15 of INTEGRATION_CONTRACT.md.
func TestIntegrationSchemaPropertyUIMetadataRoundTrip(t *testing.T) {
	max := 80
	prop := model.IntegrationSchemaProperty{
		Type:        "string",
		Description: "Find this in EFI Pix dashboard → Settings → API Credentials",
		Secret:      false,
		Label:       "EFI Client Key ID",
		LabelLocale: map[string]string{
			"pt-BR": "EFI: Chave de cliente",
			"en-US": "EFI: Client key",
		},
		Placeholder: "Client_Id_xxxxxxxxxxxx",
		PlaceholderLocale: map[string]string{
			"pt-BR": "Client_Id_xxxxxxxxxxxx",
		},
		DescriptionLocale: map[string]string{
			"pt-BR": "Encontre em: EFI Pix dashboard → Configurações → Credenciais API",
		},
		Group: "EFI Credentials",
		GroupLocale: map[string]string{
			"pt-BR": "Credenciais EFI",
		},
		Order:     1,
		Sensitive: false,
		Format:    "password",
		Pattern:   "^Client_Id_[A-Za-z0-9]+$",
		MaxLength: &max,
		DependsOn: &model.IntegrationSchemaDependency{
			Field: "mtls_enabled",
			Value: true,
		},
	}

	raw, err := json.Marshal(prop)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	encoded := string(raw)
	for _, fragment := range []string{
		`"label":"EFI Client Key ID"`,
		`"label_locale":`,
		`"placeholder":"Client_Id_xxxxxxxxxxxx"`,
		`"placeholder_locale":`,
		`"description_locale":`,
		`"group":"EFI Credentials"`,
		`"group_locale":`,
		`"order":1`,
		`"format":"password"`,
		`"pattern":"^Client_Id_[A-Za-z0-9]+$"`,
		`"max_length":80`,
		`"depends_on":`,
		`"field":"mtls_enabled"`,
	} {
		if !strings.Contains(encoded, fragment) {
			t.Errorf("expected JSON to contain %q, got %s", fragment, encoded)
		}
	}

	var decoded model.IntegrationSchemaProperty
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Label != "EFI Client Key ID" {
		t.Errorf("Label drift: got %q", decoded.Label)
	}
	if decoded.LabelLocale["pt-BR"] != "EFI: Chave de cliente" {
		t.Errorf("LabelLocale[pt-BR] drift: got %q", decoded.LabelLocale["pt-BR"])
	}
	if decoded.Placeholder != "Client_Id_xxxxxxxxxxxx" {
		t.Errorf("Placeholder drift: got %q", decoded.Placeholder)
	}
	if decoded.Group != "EFI Credentials" {
		t.Errorf("Group drift: got %q", decoded.Group)
	}
	if decoded.Order != 1 {
		t.Errorf("Order drift: got %d", decoded.Order)
	}
	if decoded.Sensitive {
		t.Errorf("Sensitive drift: got true")
	}
	if decoded.Format != "password" {
		t.Errorf("Format drift: got %q", decoded.Format)
	}
	if decoded.MaxLength == nil || *decoded.MaxLength != 80 {
		t.Errorf("MaxLength drift: got %v", decoded.MaxLength)
	}
	if decoded.DependsOn == nil {
		t.Fatalf("DependsOn drift: expected non-nil")
	}
	if decoded.DependsOn.Field != "mtls_enabled" {
		t.Errorf("DependsOn.Field drift: got %q", decoded.DependsOn.Field)
	}
	if decoded.DependsOn.Value != true {
		t.Errorf("DependsOn.Value drift: got %v", decoded.DependsOn.Value)
	}
}

// TestIntegrationSchemaPropertyMinimal verifies the backward-compat invariant:
// an adapter that supplies only legacy fields (no §15 UI metadata) marshals
// without ANY of the new keys appearing in the output (omitempty contract).
func TestIntegrationSchemaPropertyMinimal(t *testing.T) {
	prop := model.IntegrationSchemaProperty{
		Type:   "string",
		Secret: true,
	}
	raw, err := json.Marshal(prop)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := string(raw)

	for _, fragment := range []string{
		`"label"`,
		`"label_locale"`,
		`"placeholder"`,
		`"placeholder_locale"`,
		`"description_locale"`,
		`"group"`,
		`"group_locale"`,
		`"order"`,
		`"sensitive"`,
		`"depends_on"`,
		`"format"`,
		`"pattern"`,
		`"max_length"`,
	} {
		if strings.Contains(encoded, fragment) {
			t.Errorf("expected omitempty to drop %q from %s", fragment, encoded)
		}
	}
}

// TestValidateIntegrationInputValuesAcceptsUIMetadata asserts that the
// existing validator does not reject inputs declared with the new UI
// metadata fields — backward compatibility is mandatory.
func TestValidateIntegrationInputValuesAcceptsUIMetadata(t *testing.T) {
	max := 80
	schema := model.IntegrationSchemaSpec{
		Mode:     "inline",
		Required: []string{"efi_client_key_id"},
		Properties: map[string]model.IntegrationSchemaProperty{
			"efi_client_key_id": {
				Type:      "string",
				Label:     "EFI Client Key ID",
				Sensitive: true,
				Format:    "password",
				MaxLength: &max,
			},
		},
	}
	values := map[string]any{
		"efi_client_key_id": "Client_Id_abc123",
	}

	if err := ValidateIntegrationInputValues("integration credentials", schema, values); err != nil {
		t.Fatalf("validator should accept UI metadata fields: %v", err)
	}
}
