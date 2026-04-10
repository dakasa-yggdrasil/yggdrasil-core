package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateRemediationContractSpec(t *testing.T) {
	spec := remediationContractFixture()

	if err := ValidateRemediationContractSpec(spec); err != nil {
		t.Fatalf("ValidateRemediationContractSpec error: %v", err)
	}
}

func TestValidateRemediationContractSpecRejectsMissingActions(t *testing.T) {
	spec := remediationContractFixture()
	spec.Actions = nil

	if err := ValidateRemediationContractSpec(spec); err == nil {
		t.Fatal("expected missing actions to fail validation")
	}
}

func TestRemediationContractDocumentValidation(t *testing.T) {
	raw, err := json.Marshal(remediationContractFixture())
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	doc := model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "remediation_contract",
		Metadata: model.ManifestMetadataInput{
			Name:      "yggdrasil-console-rightsize",
			Namespace: "global",
		},
		Spec: raw,
	}

	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("ValidateDocument(remediation_contract) error: %v", err)
	}
}

func remediationContractFixture() model.RemediationContractManifestSpec {
	return model.RemediationContractManifestSpec{
		ComponentKind:      "surface",
		ComponentNamespace: "global",
		ComponentName:      "yggdrasil-console",
		Actions: []model.RemediationContractActionSpec{
			{
				Name:        "rightsize_component",
				Mode:        model.RemediationContractActionModeWorkflowDispatch,
				AutoExecute: true,
				WorkflowDispatch: &model.RemediationWorkflowDispatchSpec{
					Workflow: "deploy.yml",
					Ref:      "main",
					Inputs: map[string]any{
						"environment": "production",
					},
				},
			},
		},
	}
}
