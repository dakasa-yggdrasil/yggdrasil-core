package manifest

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
)

func TestOriginalGuestReconcileJSONPresenceIsExplicit(t *testing.T) {
	for _, tc := range []struct {
		raw string
		ok  bool
	}{
		{`{}`, true}, {`{"guest_notify_reconcile_binding":{"mode":"original_guest_notify_reconcile_v1","signals":[]}}`, true},
		{`{"guest_notify_reconcile_binding":null}`, false}, {`{"guest_notify_reconcile_binding":false}`, false},
		{`{"Guest_Notify_Reconcile_Binding":{}}`, false}, {`{"guest_notify_reconcile_binding":{},"guest_notify_reconcile_binding":{}}`, false},
	} {
		if (validateGuestReconcileJSON([]byte(tc.raw)) == nil) != tc.ok {
			t.Fatal("ambiguous binding accepted", tc.raw)
		}
	}
}

func TestOriginalGuestReconcileWorkflowOperationsAreClosed(t *testing.T) {
	for _, operation := range []string{"capacity.plan_original_guest", "capacity.complete_original_guest"} {
		t.Run(operation, func(t *testing.T) {
			spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "unit-only", Name: "capacity"}}, Steps: []model.WorkflowStepSpec{{ID: "original-guest", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: operation}, With: map[string]any{"policy": map[string]any{"namespace": "unit-only", "name": "capacity"}}, TimeoutSeconds: 90, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}}}}
			if err := ValidateWorkflowSpec(spec); err != nil {
				t.Fatal("literal owning opcode refused", err)
			}
			spec.Authorization = nil
			if ValidateWorkflowSpec(spec) == nil {
				t.Fatal("actorless capacity workflow accepted")
			}
			spec.Authorization = &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "unit-only", Name: "capacity"}}
			spec.Steps[0].Use.Operation = operation + "_alias"
			if ValidateWorkflowSpec(spec) == nil {
				t.Fatal("unknown opcode accepted")
			}
		})
	}
}
