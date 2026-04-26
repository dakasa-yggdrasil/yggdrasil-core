package message

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// TestRunWorkflow_ForEachFanOutSkipped verifies the fan-out path produces
// one result per item with stable IDs. The step's condition is false on
// every iteration so each iteration records "skipped" — which lets the
// test stay hermetic (no AMQP / DB needed). The structural guarantee we
// care about is that the engine emits N results, not 1, when for_each is
// declared with a populated items slice.
func TestRunWorkflow_ForEachFanOutSkipped(t *testing.T) {
	workflowManifest := model.Manifest{
		ID:   uuid.New(),
		Kind: "workflow",
		Metadata: model.ManifestMetadata{Name: "for-each-smoke", Namespace: "test"},
	}

	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID:        "publish",
				Condition: "false",
				ForEach: &model.WorkflowForEachSpec{
					Items: "{{ inputs.subdomains }}",
					As:    "sub",
				},
				Use: model.WorkflowStepUseSpec{
					Kind:       "integration",
					Capability: "noop",
					InstanceRef: &model.ManifestSelector{
						Name:      "never-resolved",
						Namespace: "test",
					},
				},
				With: map[string]any{"name": "{{ each.sub }}"},
			},
		},
	}

	req := model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Name: "for-each-smoke", Namespace: "test"},
		Inputs: map[string]any{
			"subdomains": []any{"app", "enterprise", "tartaro"},
		},
	}

	resp, err := runWorkflow(context.Background(), nil, nil, workflowManifest, spec, req)
	if err != nil {
		t.Fatalf("runWorkflow error: %v", err)
	}

	if resp.Status != "succeeded" {
		t.Fatalf("status = %q, want succeeded", resp.Status)
	}
	if len(resp.Steps) != 3 {
		t.Fatalf("step count = %d, want 3 (one per item)", len(resp.Steps))
	}
	wantIDs := []string{"publish[0]", "publish[1]", "publish[2]"}
	for i, expected := range wantIDs {
		if resp.Steps[i].ID != expected {
			t.Errorf("step[%d].ID = %q, want %q", i, resp.Steps[i].ID, expected)
		}
	}
}

// TestRunWorkflow_ForEachItemsRenderError fails the step fail-loud when
// the items template can't be resolved, instead of silently emitting 0
// iterations.
func TestRunWorkflow_ForEachItemsRenderError(t *testing.T) {
	workflowManifest := model.Manifest{
		ID:   uuid.New(),
		Kind: "workflow",
		Metadata: model.ManifestMetadata{Name: "for-each-bad-items", Namespace: "test"},
	}
	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{Mode: "manual"},
		Steps: []model.WorkflowStepSpec{
			{
				ID: "iterate",
				ForEach: &model.WorkflowForEachSpec{
					Items: "{{ inputs.does_not_exist }}",
					As:    "x",
				},
				Use: model.WorkflowStepUseSpec{
					Kind:       "integration",
					Capability: "noop",
					InstanceRef: &model.ManifestSelector{Name: "never-resolved", Namespace: "test"},
				},
			},
		},
	}
	req := model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Name: "for-each-bad-items", Namespace: "test"},
		Inputs:   map[string]any{},
	}
	resp, err := runWorkflow(context.Background(), nil, nil, workflowManifest, spec, req)
	if err != nil {
		t.Fatalf("runWorkflow error: %v", err)
	}
	if resp.Status != "failed" {
		t.Fatalf("status = %q, want failed", resp.Status)
	}
	if len(resp.Steps) == 0 || resp.Steps[0].Status != "failed" {
		t.Fatalf("expected first step failed, got %#v", resp.Steps)
	}
}
