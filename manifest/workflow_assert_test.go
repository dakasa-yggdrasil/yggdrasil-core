package manifest

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestValidateWorkflowSpecAcceptsClosedAssertInput(t *testing.T) {
	spec := workflowAssertSpec(map[string]any{
		"equal": []any{
			map[string]any{
				"name":     "final_policy_spec",
				"actual":   "{{ steps.observe.metadata.spec }}",
				"expected": map[string]any{"policyTypes": []any{"Ingress", "Egress"}},
			},
		},
		"nonempty": []any{
			map[string]any{
				"name":  "final_policy_uid",
				"value": "{{ steps.observe.metadata.uid }}",
			},
		},
	})

	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("ValidateWorkflowSpec(assert) error: %v", err)
	}
}

func TestValidateWorkflowSpecRejectsMalformedAssertInput(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]any
		wantError string
	}{
		{name: "no checks", input: map[string]any{}, wantError: "at least one"},
		{name: "unknown top level field", input: map[string]any{"headers": []any{}}, wantError: "unsupported fields"},
		{name: "equal is not an array", input: map[string]any{"equal": map[string]any{}}, wantError: "with.equal must be an array"},
		{name: "equal missing expected", input: map[string]any{"equal": []any{map[string]any{"name": "spec", "actual": "x"}}}, wantError: "exactly name, actual, and expected"},
		{name: "equal extra field", input: map[string]any{"equal": []any{map[string]any{"name": "spec", "actual": "x", "expected": "x", "header": "secret"}}}, wantError: "exactly name, actual, and expected"},
		{name: "nonempty missing value", input: map[string]any{"nonempty": []any{map[string]any{"name": "uid"}}}, wantError: "exactly name and value"},
		{name: "empty name", input: map[string]any{"nonempty": []any{map[string]any{"name": "", "value": "x"}}}, wantError: "non-empty string name"},
		{
			name: "duplicate name across check kinds",
			input: map[string]any{
				"equal":    []any{map[string]any{"name": "policy", "actual": "x", "expected": "x"}},
				"nonempty": []any{map[string]any{"name": "policy", "value": "x"}},
			},
			wantError: "duplicated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWorkflowSpec(workflowAssertSpec(tc.input))
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("ValidateWorkflowSpec(assert) error = %v, want substring %q", err, tc.wantError)
			}
		})
	}
}

func workflowAssertSpec(input map[string]any) model.WorkflowManifestSpec {
	return model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "assert-final-state",
				Use: model.WorkflowStepUseSpec{
					Kind:      "yggdrasil",
					Operation: "assert",
				},
				With: input,
			},
		},
	}
}
