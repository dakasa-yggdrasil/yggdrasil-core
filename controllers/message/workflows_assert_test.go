package message

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestExecuteYggdrasilWorkflowAssertSucceedsWithoutReturningValues(t *testing.T) {
	step := workflowAssertStep(map[string]any{
		"equal": []any{
			map[string]any{
				"name":     "final_policy_spec",
				"actual":   map[string]any{"authorization": "Bearer actual-secret", "rules": []any{"ingress"}},
				"expected": map[string]any{"authorization": "Bearer actual-secret", "rules": []any{"ingress"}},
			},
		},
		"nonempty": []any{
			map[string]any{"name": "policy_uid", "value": "uid-secret-value"},
			map[string]any{"name": "policy_rules", "value": []any{"private-rule"}},
			map[string]any{"name": "policy_labels", "value": map[string]any{"private-label": "private-value"}},
		},
	})
	result := workflowAssertResult(step)

	got := executeYggdrasilWorkflowStep(context.Background(), nil, step, result, step.With)
	if got.Status != "succeeded" || got.Error != "" {
		t.Fatalf("assert result = %#v", got)
	}
	if got.Metadata["assertion_count"] != 4 || got.Metadata["equal_count"] != 1 || got.Metadata["nonempty_count"] != 3 {
		t.Fatalf("assert metadata counts = %#v", got.Metadata)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(result): %v", err)
	}
	for _, forbidden := range []string{"Bearer actual-secret", "uid-secret-value", "private-rule", "private-label", "private-value"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("assert result leaked rendered value %q: %s", forbidden, encoded)
		}
	}
}

func TestExecuteYggdrasilWorkflowAssertMismatchFailsWithoutReturningValues(t *testing.T) {
	step := workflowAssertStep(map[string]any{
		"equal": []any{
			map[string]any{
				"name":     "final_policy_spec",
				"actual":   map[string]any{"authorization": "Bearer actual-secret"},
				"expected": map[string]any{"authorization": "Bearer expected-secret"},
			},
		},
	})

	got := executeYggdrasilWorkflowStep(context.Background(), nil, step, workflowAssertResult(step), step.With)
	if got.Status != "failed" || got.Error != `assert equal check "final_policy_spec" failed` {
		t.Fatalf("assert mismatch result = %#v", got)
	}
	if got.Metadata != nil {
		t.Fatalf("failed assert metadata = %#v, want nil", got.Metadata)
	}
	if strings.Contains(got.Error, "actual-secret") || strings.Contains(got.Error, "expected-secret") || strings.Contains(got.Error, "authorization") {
		t.Fatalf("assert mismatch leaked rendered values: %q", got.Error)
	}
}

func TestExecuteYggdrasilWorkflowAssertRejectsEmptyAndScalarValues(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "nil", value: nil},
		{name: "empty string", value: ""},
		{name: "empty slice", value: []any{}},
		{name: "empty map", value: map[string]any{}},
		{name: "number", value: float64(1)},
		{name: "boolean", value: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			step := workflowAssertStep(map[string]any{
				"nonempty": []any{map[string]any{"name": "required_value", "value": tc.value}},
			})
			got := executeYggdrasilWorkflowStep(context.Background(), nil, step, workflowAssertResult(step), step.With)
			if got.Status != "failed" || got.Error != `assert nonempty check "required_value" failed` {
				t.Fatalf("assert nonempty result = %#v", got)
			}
		})
	}
}

func TestExecuteYggdrasilWorkflowAssertRevalidatesClosedShape(t *testing.T) {
	step := workflowAssertStep(map[string]any{
		"equal": []any{
			map[string]any{
				"name":     "final_policy_spec",
				"actual":   "actual-secret",
				"expected": "actual-secret",
				"headers":  map[string]any{"Authorization": "Bearer secret"},
			},
		},
	})

	got := executeYggdrasilWorkflowStep(context.Background(), nil, step, workflowAssertResult(step), step.With)
	if got.Status != "failed" || got.Error == "" {
		t.Fatalf("malformed assert result = %#v", got)
	}
	if strings.Contains(got.Error, "actual-secret") || strings.Contains(got.Error, "Authorization") || strings.Contains(got.Error, "Bearer secret") {
		t.Fatalf("malformed assert leaked input: %q", got.Error)
	}
}

func workflowAssertStep(input map[string]any) model.WorkflowStepSpec {
	return model.WorkflowStepSpec{
		ID: "assert-final-state",
		Use: model.WorkflowStepUseSpec{
			Kind:      "yggdrasil",
			Operation: "assert",
		},
		With: input,
	}
}

func workflowAssertResult(step model.WorkflowStepSpec) model.WorkflowRunStepResult {
	return model.WorkflowRunStepResult{
		ID:        step.ID,
		Kind:      step.Use.Kind,
		Operation: step.Use.Operation,
		Status:    "failed",
	}
}
