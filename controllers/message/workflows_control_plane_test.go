package message

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestControlPlaneSelectorFromInput_RequiresRef(t *testing.T) {
	if _, err := controlPlaneSelectorFromInput(map[string]any{}); err == nil {
		t.Fatal("expected missing control_plane_ref to fail")
	}
}

func TestControlPlaneSelectorFromInput_RejectsNonObjectRef(t *testing.T) {
	if _, err := controlPlaneSelectorFromInput(map[string]any{"control_plane_ref": "primary"}); err == nil {
		t.Fatal("expected non-object control_plane_ref to fail")
	}
}

func TestControlPlaneSelectorFromInput_RequiresNameOrID(t *testing.T) {
	if _, err := controlPlaneSelectorFromInput(map[string]any{
		"control_plane_ref": map[string]any{"namespace": "global"},
	}); err == nil {
		t.Fatal("expected ref without name/manifest_id to fail")
	}
}

func TestControlPlaneSelectorFromInput_DefaultsNamespaceToGlobal(t *testing.T) {
	selector, err := controlPlaneSelectorFromInput(map[string]any{
		"control_plane_ref": map[string]any{"name": "primary"},
	})
	if err != nil {
		t.Fatalf("controlPlaneSelectorFromInput error: %v", err)
	}
	if selector.Namespace != "global" {
		t.Errorf("namespace = %q, want global", selector.Namespace)
	}
	if selector.Name != "primary" {
		t.Errorf("name = %q, want primary", selector.Name)
	}
	if selector.Version != nil {
		t.Errorf("version = %v, want nil", selector.Version)
	}
}

func TestControlPlaneSelectorFromInput_AcceptsVersionAsFloat(t *testing.T) {
	// Workflow templating produces JSON-style numbers (float64). The
	// selector must accept that without forcing the user to express
	// integer types in the workflow YAML.
	selector, err := controlPlaneSelectorFromInput(map[string]any{
		"control_plane_ref": map[string]any{
			"name":    "primary",
			"version": float64(3),
		},
	})
	if err != nil {
		t.Fatalf("controlPlaneSelectorFromInput error: %v", err)
	}
	if selector.Version == nil || *selector.Version != 3 {
		t.Errorf("version = %v, want 3", selector.Version)
	}
}

func TestControlPlaneSelectorFromInput_AcceptsJSONNumber(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"control_plane_ref":{"name":"primary","version":4}}`))
	dec.UseNumber()
	var input map[string]any
	if err := dec.Decode(&input); err != nil {
		t.Fatalf("decode: %v", err)
	}
	selector, err := controlPlaneSelectorFromInput(input)
	if err != nil {
		t.Fatalf("controlPlaneSelectorFromInput error: %v", err)
	}
	if selector.Version == nil || *selector.Version != 4 {
		t.Errorf("version = %v, want 4", selector.Version)
	}
}

// TestExecuteYggdrasilWorkflowStep_ControlPlaneRenderRejectsBadInput
// runs the dispatcher with a control_plane.render step but no
// control_plane_ref. We expect a clean failure before any DB hit, so
// passing nil for *sql.DB is safe.
func TestExecuteYggdrasilWorkflowStep_ControlPlaneRenderRejectsBadInput(t *testing.T) {
	step := model.WorkflowStepSpec{
		ID: "render",
		Use: model.WorkflowStepUseSpec{
			Kind:      "yggdrasil",
			Operation: "control_plane.render",
		},
		With: map[string]any{},
	}
	result := model.WorkflowRunStepResult{ID: "render", Kind: "yggdrasil", Operation: "control_plane.render", Status: "failed"}

	got := executeYggdrasilWorkflowStep(context.Background(), nil, step, result, step.With)
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !strings.Contains(got.Error, "control_plane_ref") {
		t.Errorf("error = %q, want one mentioning control_plane_ref", got.Error)
	}
}
