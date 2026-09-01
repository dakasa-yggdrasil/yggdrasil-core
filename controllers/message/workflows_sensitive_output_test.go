package message

import (
	"reflect"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestRedactSensitiveWorkflowStepResultRedactsDeclaredPathsWithoutMutatingExecutionResult(t *testing.T) {
	original := model.WorkflowRunStepResult{
		Metadata: map[string]any{
			"output": map[string]any{
				"secret_shared_key": "one-time-secret",
				"resource_id":       "webhook-123",
				"nested": map[string]any{
					"tokens": []any{"public", "private"},
				},
			},
			"sensitive_output_paths": []any{"secret_shared_key", "/nested/tokens/1"},
		},
	}

	redacted := redactSensitiveWorkflowStepResult(original)
	redactedOutput := redacted.Metadata["output"].(map[string]any)
	if got := redactedOutput["secret_shared_key"]; got != redactedWorkflowOutputValue {
		t.Fatalf("top-level secret = %v, want %q", got, redactedWorkflowOutputValue)
	}
	if got := redactedOutput["resource_id"]; got != "webhook-123" {
		t.Fatalf("non-sensitive field = %v, want webhook-123", got)
	}
	nested := redactedOutput["nested"].(map[string]any)
	tokens := nested["tokens"].([]any)
	if got := tokens[1]; got != redactedWorkflowOutputValue {
		t.Fatalf("nested secret = %v, want %q", got, redactedWorkflowOutputValue)
	}
	if got := redacted.Metadata["sensitive_output_redaction_scope"]; got != "paths" {
		t.Fatalf("redaction scope = %v, want paths", got)
	}

	// The workflow engine must retain the original value in memory so the next
	// step can persist it into the configured secret store.
	originalOutput := original.Metadata["output"].(map[string]any)
	if got := originalOutput["secret_shared_key"]; got != "one-time-secret" {
		t.Fatalf("execution result was mutated: got %v", got)
	}
	originalTokens := originalOutput["nested"].(map[string]any)["tokens"].([]any)
	if got := originalTokens[1]; got != "private" {
		t.Fatalf("nested execution result was mutated: got %v", got)
	}
}

func TestRedactSensitiveWorkflowStepResultFailsClosedOnInvalidDeclaration(t *testing.T) {
	result := model.WorkflowRunStepResult{
		Metadata: map[string]any{
			"output": map[string]any{
				"secret_shared_key": "one-time-secret",
				"resource_id":       "webhook-123",
			},
			"sensitive_output_paths": []any{"missing.path"},
		},
	}

	redacted := redactSensitiveWorkflowStepResult(result)
	if got := redacted.Metadata["output"]; got != redactedWorkflowOutputValue {
		t.Fatalf("output = %#v, want fail-closed redaction", got)
	}
	if got := redacted.Metadata["sensitive_output_redaction_scope"]; got != "output" {
		t.Fatalf("redaction scope = %v, want output", got)
	}
}

func TestRedactSensitiveWorkflowStepResultFailsClosedOnMalformedJSONPointer(t *testing.T) {
	for _, path := range []string{"/secret~", "/secret~2key", "/"} {
		t.Run(path, func(t *testing.T) {
			result := model.WorkflowRunStepResult{
				Metadata: map[string]any{
					"output": map[string]any{
						"secret~2key": "one-time-secret",
						"resource_id": "webhook-123",
					},
					"sensitive_output_paths": []any{path},
				},
			}

			redacted := redactSensitiveWorkflowStepResult(result)
			if got := redacted.Metadata["output"]; got != redactedWorkflowOutputValue {
				t.Fatalf("output = %#v, want fail-closed redaction", got)
			}
		})
	}
}

func TestRedactSensitiveWorkflowStepResultDecodesJSONPointerEscapes(t *testing.T) {
	result := model.WorkflowRunStepResult{
		Metadata: map[string]any{
			"output": map[string]any{
				"secret/key~name": "one-time-secret",
				"resource_id":     "webhook-123",
			},
			"sensitive_output_paths": []any{"/secret~1key~0name"},
		},
	}

	redacted := redactSensitiveWorkflowStepResult(result)
	output := redacted.Metadata["output"].(map[string]any)
	if got := output["secret/key~name"]; got != redactedWorkflowOutputValue {
		t.Fatalf("escaped JSON Pointer target = %#v, want redaction", got)
	}
	if got := output["resource_id"]; got != "webhook-123" {
		t.Fatalf("non-sensitive field = %#v, want webhook-123", got)
	}
}

func TestRedactSensitiveWorkflowStepResultFailsClosedOnEmptyPathList(t *testing.T) {
	result := model.WorkflowRunStepResult{
		Metadata: map[string]any{
			"output":                 map[string]any{"secret": "one-time-secret"},
			"sensitive_output_paths": []any{},
		},
	}

	redacted := redactSensitiveWorkflowStepResult(result)
	if got := redacted.Metadata["output"]; got != redactedWorkflowOutputValue {
		t.Fatalf("output = %#v, want fail-closed redaction", got)
	}
}

func TestRedactSensitiveWorkflowStepResultLeavesUnmarkedOutputUntouched(t *testing.T) {
	result := model.WorkflowRunStepResult{
		Metadata: map[string]any{
			"output": map[string]any{"resource_id": "webhook-123"},
		},
	}

	if got := redactSensitiveWorkflowStepResult(result); !reflect.DeepEqual(got, result) {
		t.Fatalf("unmarked result changed: got %#v want %#v", got, result)
	}
}
