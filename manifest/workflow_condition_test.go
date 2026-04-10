package manifest

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestEvaluateWorkflowStepCondition_EmptyMeansRun verifies that an empty
// condition string is treated as "always run" (backwards compatibility — the
// huge majority of existing steps do not set a condition).
func TestEvaluateWorkflowStepCondition_EmptyMeansRun(t *testing.T) {
	run, err := EvaluateWorkflowStepCondition("", newConditionCtx())
	if err != nil {
		t.Fatalf("empty condition returned error: %v", err)
	}
	if !run {
		t.Fatal("empty condition should evaluate to run=true")
	}
}

// TestEvaluateWorkflowStepCondition_TruthyLiterals covers the unary case
// where the expression resolves to a truthy/falsy scalar without operators.
func TestEvaluateWorkflowStepCondition_TruthyLiterals(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		expect bool
	}{
		{"literal true", "true", true},
		{"literal True", "True", true},
		{"literal false", "false", false},
		{"literal False", "False", false},
		{"literal 0", "0", false},
		{"literal 1", "1", true},
		{"literal null", "null", false},
		{"empty string after trim", "   ", true}, // trimmed empty = empty condition = run
		{"nonempty word", "yes", true},
	}

	ctx := newConditionCtx()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run, err := EvaluateWorkflowStepCondition(tc.input, ctx)
			if err != nil {
				t.Fatalf("condition %q returned error: %v", tc.input, err)
			}
			if run != tc.expect {
				t.Fatalf("condition %q = %v, want %v", tc.input, run, tc.expect)
			}
		})
	}
}

// TestEvaluateWorkflowStepCondition_TemplateTruthyFromInputs verifies the
// most common case: condition references an input and is checked for
// truthiness.
func TestEvaluateWorkflowStepCondition_TemplateTruthyFromInputs(t *testing.T) {
	cases := []struct {
		name   string
		input  any
		expect bool
	}{
		{"bool true", true, true},
		{"bool false", false, false},
		{"string yes", "yes", true},
		{"string empty", "", false},
		{"string false", "false", false},
		{"int 1", 1, true},
		{"int 0", 0, false},
		{"float 1.5", 1.5, true},
		{"float 0.0", 0.0, false},
		{"nil", nil, false},
		{"empty slice", []any{}, false},
		{"nonempty slice", []any{"x"}, true},
		{"empty map", map[string]any{}, false},
		{"nonempty map", map[string]any{"k": "v"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WorkflowExecutionContext{
				Inputs: map[string]any{"flag": tc.input},
			}
			run, err := EvaluateWorkflowStepCondition("{{ inputs.flag }}", ctx)
			if err != nil {
				t.Fatalf("returned error: %v", err)
			}
			if run != tc.expect {
				t.Fatalf("flag=%#v run=%v, want %v", tc.input, run, tc.expect)
			}
		})
	}
}

// TestEvaluateWorkflowStepCondition_BinaryEquality covers the `==` operator.
func TestEvaluateWorkflowStepCondition_BinaryEquality(t *testing.T) {
	ctx := WorkflowExecutionContext{
		Inputs: map[string]any{
			"env":   "validation",
			"count": 3,
			"flag":  true,
		},
	}

	cases := []struct {
		name      string
		condition string
		expect    bool
	}{
		{"string match", "{{ inputs.env }} == validation", true},
		{"string no match", "{{ inputs.env }} == production", false},
		{"int match", "{{ inputs.count }} == 3", true},
		{"int no match", "{{ inputs.count }} == 4", false},
		{"bool match", "{{ inputs.flag }} == true", true},
		{"bool no match", "{{ inputs.flag }} == false", false},
		{"both templates", "{{ inputs.env }} == {{ inputs.env }}", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run, err := EvaluateWorkflowStepCondition(tc.condition, ctx)
			if err != nil {
				t.Fatalf("condition %q returned error: %v", tc.condition, err)
			}
			if run != tc.expect {
				t.Fatalf("condition %q = %v, want %v", tc.condition, run, tc.expect)
			}
		})
	}
}

// TestEvaluateWorkflowStepCondition_BinaryInequality covers `!=`.
func TestEvaluateWorkflowStepCondition_BinaryInequality(t *testing.T) {
	ctx := WorkflowExecutionContext{
		Inputs: map[string]any{"env": "validation"},
	}

	cases := []struct {
		name      string
		condition string
		expect    bool
	}{
		{"not equal true", "{{ inputs.env }} != production", true},
		{"not equal false", "{{ inputs.env }} != validation", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run, err := EvaluateWorkflowStepCondition(tc.condition, ctx)
			if err != nil {
				t.Fatalf("condition %q returned error: %v", tc.condition, err)
			}
			if run != tc.expect {
				t.Fatalf("condition %q = %v, want %v", tc.condition, run, tc.expect)
			}
		})
	}
}

// TestEvaluateWorkflowStepCondition_ReferencesStepOutputs exercises the
// ability to branch on metadata from prior step results.
func TestEvaluateWorkflowStepCondition_ReferencesStepOutputs(t *testing.T) {
	ctx := WorkflowExecutionContext{
		Inputs: map[string]any{},
		Steps: map[string]model.WorkflowRunStepResult{
			"previous": {
				ID:     "previous",
				Status: "succeeded",
				Metadata: map[string]any{
					"should_continue": true,
				},
			},
		},
	}

	run, err := EvaluateWorkflowStepCondition("{{ steps.previous.metadata.should_continue }}", ctx)
	if err != nil {
		t.Fatalf("returned error: %v", err)
	}
	if !run {
		t.Fatal("expected condition referencing step metadata to evaluate truthy")
	}
}

// TestEvaluateWorkflowStepCondition_UnresolvableTemplate ensures that an
// unresolvable template returns an error (fail-loud). A broken condition
// should never be silently skipped.
func TestEvaluateWorkflowStepCondition_UnresolvableTemplate(t *testing.T) {
	ctx := WorkflowExecutionContext{
		Inputs: map[string]any{"env": "validation"},
	}

	if _, err := EvaluateWorkflowStepCondition("{{ inputs.missing }} == foo", ctx); err == nil {
		t.Fatal("expected error for unresolvable template on left side")
	}
}

// TestValidateWorkflowSpec_AcceptsCondition ensures that adding a condition
// to an existing valid step does not break validation.
func TestValidateWorkflowSpec_AcceptsCondition(t *testing.T) {
	spec := workflowSpecFixture()
	spec.Steps[1].Condition = "{{ inputs.notify_enabled }}"

	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("ValidateWorkflowSpec with condition error: %v", err)
	}
}

// TestValidateWorkflowSpec_AcceptsBinaryCondition exercises the `==` case
// through the full validator.
func TestValidateWorkflowSpec_AcceptsBinaryCondition(t *testing.T) {
	spec := workflowSpecFixture()
	spec.Steps[1].Condition = "{{ inputs.environment }} == production"

	if err := ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("ValidateWorkflowSpec with binary condition error: %v", err)
	}
}

func newConditionCtx() WorkflowExecutionContext {
	return WorkflowExecutionContext{
		Inputs:   map[string]any{},
		Metadata: map[string]any{},
		Steps:    map[string]model.WorkflowRunStepResult{},
	}
}
