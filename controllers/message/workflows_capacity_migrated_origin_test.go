package message

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestCapacityMigratedOriginProtectedHumanBoundary(t *testing.T) {
	b := model.CapacityMigratedNativeOriginBinding{OperatorID: "named-human", Confirmation: "RETIRE OBSOLETE ORIGIN WITHOUT SDK WITNESS"}
	base := map[string]any{"binding": b, "confirmation": b.Confirmation}
	human := context.WithValue(context.Background(), executorPowerOperatorKey{}, b.OperatorID)
	if _, err := migratedOriginHumanInput(human, capacity.RetireMigratedNativeOrigin, base); err != nil {
		t.Fatal("named human input refused", err)
	}
	for _, name := range []string{"machine", "different_operator", "different_confirmation", "caller_target_receipt", "case_alias", "other_operation"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var in map[string]any
			if json.Unmarshal(raw, &in) != nil {
				t.Fatal("fixture")
			}
			ctx, op := human, capacity.RetireMigratedNativeOrigin
			switch name {
			case "machine":
				ctx = context.Background()
			case "different_operator":
				ctx = context.WithValue(ctx, executorPowerOperatorKey{}, "another-human")
			case "different_confirmation":
				in["confirmation"] = "SDK EXIT SUCCEEDED"
			case "caller_target_receipt":
				in["target"] = map[string]any{"sdk_joined": true}
			case "case_alias":
				in["Binding"] = in["binding"]
				delete(in, "binding")
			case "other_operation":
				op = "capacity.execute_bound"
			}
			if _, err := migratedOriginHumanInput(ctx, op, in); err == nil {
				t.Fatal("untrusted boundary became administrative authority")
			}
		})
	}
}

func TestCapacityMigratedOriginLiteralWorkflowBoundary(t *testing.T) {
	b := model.CapacityMigratedNativeOriginBinding{OperatorID: "named-human", Confirmation: "RETIRE OBSOLETE ORIGIN"}
	w := model.WorkflowManifestSpec{DispatchMode: "sync", Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "fixed", Name: "named-human"}}, Steps: []model.WorkflowStepSpec{{ID: "retire-once", TimeoutSeconds: 90, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.RetireMigratedNativeOrigin}, With: map[string]any{"binding": b, "confirmation": "{{ inputs.confirmation }}"}}}}
	if !migratedOriginLiteralWorkflow(w, b) {
		t.Fatal("fixed human workflow refused")
	}
	for _, name := range []string{"async", "timer", "retry", "binding_template", "other_binding", "condition", "caller_selected_adapter", "literal_confirmation", "extra_step"} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(w)
			var x model.WorkflowManifestSpec
			if json.Unmarshal(raw, &x) != nil {
				t.Fatal("fixture")
			}
			switch name {
			case "async":
				x.DispatchMode = "async"
			case "timer":
				x.Trigger.Mode = "event"
			case "retry":
				x.Steps[0].Retry.MaxAttempts = 2
			case "binding_template":
				x.Steps[0].With["binding"] = "{{ inputs.binding }}"
			case "other_binding":
				changed := b
				changed.OperatorID = "other"
				x.Steps[0].With["binding"] = changed
			case "condition":
				x.Steps[0].Condition = "{{ true }}"
			case "caller_selected_adapter":
				x.Steps[0].Use.InstanceRef = &model.ManifestSelector{Name: "caller-choice"}
			case "literal_confirmation":
				x.Steps[0].With["confirmation"] = b.Confirmation
			case "extra_step":
				x.Steps = append(x.Steps, x.Steps[0])
			}
			if migratedOriginLiteralWorkflow(x, b) {
				t.Fatal("workflow acquired broader administrative authority")
			}
		})
	}
}
