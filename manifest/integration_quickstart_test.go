package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateIntegrationQuickstartSpec(t *testing.T) {
	if err := ValidateIntegrationQuickstartSpec(integrationQuickstartFixture()); err != nil {
		t.Fatalf("ValidateIntegrationQuickstartSpec error: %v", err)
	}
}

func TestValidateIntegrationQuickstartSpecRequiresAtLeastOneProvider(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers = nil

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected empty providers list to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsInvalidProviderID(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].ID = "Bad ID"

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected invalid provider id to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsDuplicateProviderIDs(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers = append(spec.Providers, spec.Providers[0])

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected duplicate provider id to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsUnknownRequirementKind(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Requires = []model.QuickstartRequirement{{Kind: "bogus", Name: "x"}}

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected unknown requirement kind to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRequiresFamilyName(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Requires = []model.QuickstartRequirement{{Kind: "integration_family"}}

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected missing requirement name to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRequiresCapabilityName(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Requires = []model.QuickstartRequirement{{Kind: "cluster_capability"}}

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected missing capability name to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsInputWithoutLabel(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs[0].Label = ""

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected input without label to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsInvalidInputID(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs[0].ID = "Bad-ID"

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected invalid input id to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsDuplicateInputs(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs = append(spec.Providers[0].Inputs, spec.Providers[0].Inputs[0])

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected duplicate input id to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsUnknownInputType(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs[0].Type = "decimal"

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected unknown input type to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRequiresChoicesForSelectType(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs[0].Type = "select"
	spec.Providers[0].Inputs[0].Choices = nil

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected select input without choices to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsInvalidValidatorRegex(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Inputs[0].Validate = &model.QuickstartValidate{Regex: "([unterminated"}

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected invalid validate regex to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRequiresAtLeastOneStep(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Steps = nil

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected provider without steps to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsDuplicateStepIDs(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Steps = append(spec.Providers[0].Steps, spec.Providers[0].Steps[0])

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected duplicate step id to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsStepWithoutUses(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].Steps[0].Uses = nil

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected step without uses to fail validation")
	}
}

func TestValidateIntegrationQuickstartSpecRejectsSmokeTestWithoutUses(t *testing.T) {
	spec := integrationQuickstartFixture()
	spec.Providers[0].SmokeTest = &model.QuickstartSmokeTest{Description: "ping"}

	if err := ValidateIntegrationQuickstartSpec(spec); err == nil {
		t.Fatal("expected smoke_test without uses to fail validation")
	}
}

func TestIntegrationQuickstartDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(integrationQuickstartFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "integration_quickstart",
		Metadata: model.ManifestMetadataInput{
			Name:      "secrets-management",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(integration_quickstart) error: %v", err)
	}
}

func integrationQuickstartFixture() model.IntegrationQuickstartManifestSpec {
	return model.IntegrationQuickstartManifestSpec{
		DisplayName: "Secrets Management",
		Description: "AWS + GCP secret backends",
		Providers: []model.ProviderQuickstart{
			{
				ID:          "aws-secrets-manager",
				DisplayName: "AWS Secrets Manager",
				Requires: []model.QuickstartRequirement{
					{Kind: "integration_family", Name: "aws", Reason: "needs aws integration installed"},
					{Kind: "cluster_capability", Capability: "irsa", Reason: "pod auth via IRSA"},
				},
				Inputs: []model.QuickstartInput{
					{
						ID:       "region",
						Label:    "AWS Region",
						Type:     "string",
						Required: true,
						Validate: &model.QuickstartValidate{Regex: `^[a-z]{2}-[a-z]+-\d$`},
					},
					{
						ID:    "tier",
						Label: "Tier",
						Type:  "select",
						Choices: []model.QuickstartChoice{
							{Value: "standard", Label: "Standard"},
							{Value: "advanced", Label: "Advanced"},
						},
					},
				},
				Steps: []model.QuickstartStep{
					{
						ID:          "register-instance",
						Description: "Register the secrets-management instance",
						Uses: map[string]any{
							"kind":      "integration",
							"family":    "secrets-management",
							"operation": "register",
						},
						With: map[string]any{
							"region": "{{ inputs.region }}",
						},
					},
				},
				SmokeTest: &model.QuickstartSmokeTest{
					Description: "list secrets to confirm reachability",
					Uses: map[string]any{
						"kind":      "integration",
						"family":    "secrets-management",
						"operation": "list_secrets",
					},
				},
				PostInstallHints: []string{"now run `yggdrasil secrets upsert ...`"},
			},
		},
	}
}
