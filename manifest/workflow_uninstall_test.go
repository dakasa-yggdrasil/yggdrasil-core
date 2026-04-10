package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestValidateWorkflowSpec_AcceptsUninstallProductOperation asserts that
// the new "installation.uninstall" operation is accepted by the workflow
// validator as a product step operation.
func TestValidateWorkflowSpec_AcceptsUninstallProductOperation(t *testing.T) {
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "teardown",
				Use: model.WorkflowStepUseSpec{
					Kind:      "product",
					Operation: "installation.uninstall",
				},
				With: map[string]any{
					"product_ref": map[string]any{
						"name":      "dakasa-app",
						"namespace": "dakasa",
					},
				},
			},
		},
	}

	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("ValidateWorkflowSpec with installation.uninstall returned error: %v", err)
	}
}

// TestValidateWorkflowSpec_RejectsUnknownProductOperation is a regression
// guardrail: a typo in the operation name must still be rejected even
// now that we added installation.uninstall to the allowlist.
func TestValidateWorkflowSpec_RejectsUnknownProductOperation(t *testing.T) {
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "teardown",
				Use: model.WorkflowStepUseSpec{
					Kind:      "product",
					Operation: "installation.remove", // not a valid operation
				},
				With: map[string]any{
					"product_ref": map[string]any{
						"name":      "dakasa-app",
						"namespace": "dakasa",
					},
				},
			},
		},
	}

	if err := ValidateWorkflowSpec(spec); err == nil {
		t.Fatal("expected ValidateWorkflowSpec to reject unknown operation installation.remove")
	}
}
