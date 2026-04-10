package message

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// TestRunWorkflow_ConditionSkipDoesNotAbort verifies that condition-skipped
// steps do not abort the workflow. Both steps have a condition that
// evaluates to false, so neither actually runs — which is exactly why it
// is safe to pass nil for the AMQP connection and the database handle:
// executeWorkflowStep bails out on the condition check before touching
// them.
//
// Before this change, runWorkflow aborted on any status != "succeeded",
// which would have treated a condition-skipped step as a failure. This
// test is the guardrail against that regression.
func TestRunWorkflow_ConditionSkipDoesNotAbort(t *testing.T) {
	workflowManifest := model.Manifest{
		ID:   uuid.New(),
		Kind: "workflow",
		Metadata: model.ManifestMetadata{
			Name:      "condition-skip-smoke",
			Namespace: "test",
		},
	}

	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID:        "first",
				Condition: "false",
				Use: model.WorkflowStepUseSpec{
					Kind:       "integration",
					Capability: "noop",
					InstanceRef: &model.ManifestSelector{
						Name:      "never-resolved",
						Namespace: "test",
					},
				},
			},
			{
				ID:        "second",
				Condition: "{{ inputs.run_second }}",
				DependsOn: []string{"first"},
				Use: model.WorkflowStepUseSpec{
					Kind:       "integration",
					Capability: "noop",
					InstanceRef: &model.ManifestSelector{
						Name:      "never-resolved",
						Namespace: "test",
					},
				},
			},
		},
	}

	req := model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{
			Name:      "condition-skip-smoke",
			Namespace: "test",
		},
		Inputs: map[string]any{
			"run_second": false,
		},
	}

	resp, err := runWorkflow(context.Background(), nil, nil, workflowManifest, spec, req)
	if err != nil {
		t.Fatalf("runWorkflow error: %v", err)
	}

	if resp.Status != "succeeded" {
		t.Fatalf("workflow status = %q, want succeeded (condition-skipped steps must not abort the run)", resp.Status)
	}

	if len(resp.Steps) != 2 {
		t.Fatalf("step count = %d, want 2", len(resp.Steps))
	}

	for _, step := range resp.Steps {
		if step.Status != "skipped" {
			t.Errorf("step %q status = %q, want skipped", step.ID, step.Status)
		}
		if reason, _ := step.Metadata["skip_reason"].(string); reason != "condition" {
			t.Errorf("step %q skip_reason = %q, want condition", step.ID, reason)
		}
	}
}

// TestRunWorkflow_ConditionWithBadTemplateFailsStep verifies the fail-loud
// behavior: an unresolvable template inside a condition must fail the
// step (and therefore the workflow) rather than silently skip.
func TestRunWorkflow_ConditionWithBadTemplateFailsStep(t *testing.T) {
	workflowManifest := model.Manifest{
		ID:   uuid.New(),
		Kind: "workflow",
		Metadata: model.ManifestMetadata{
			Name:      "condition-broken-template",
			Namespace: "test",
		},
	}

	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID:        "first",
				Condition: "{{ inputs.missing }} == foo",
				Use: model.WorkflowStepUseSpec{
					Kind:       "integration",
					Capability: "noop",
					InstanceRef: &model.ManifestSelector{
						Name:      "never-resolved",
						Namespace: "test",
					},
				},
			},
		},
	}

	req := model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{
			Name:      "condition-broken-template",
			Namespace: "test",
		},
		Inputs: map[string]any{},
	}

	resp, err := runWorkflow(context.Background(), nil, nil, workflowManifest, spec, req)
	if err != nil {
		t.Fatalf("runWorkflow returned go error: %v (expected a step-level failure)", err)
	}

	if resp.Status != "failed" {
		t.Fatalf("workflow status = %q, want failed", resp.Status)
	}

	if len(resp.Steps) == 0 {
		t.Fatal("expected at least one step result")
	}

	first := resp.Steps[0]
	if first.Status != "failed" {
		t.Errorf("first step status = %q, want failed", first.Status)
	}
	if first.Error == "" {
		t.Error("first step error should describe the condition failure")
	}
}
