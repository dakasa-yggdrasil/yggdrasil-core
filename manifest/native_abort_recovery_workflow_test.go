package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeAbortUnredeemedRecoveryWorkflowRegistration(t *testing.T) {
	for _, name := range []string{"exact_sync_literal", "unknown_operation", "integration_target_refused"} {
		t.Run(name, func(t *testing.T) {
			// Registration admits only the advertised builtin shape. Its literal
			// binding receives independent semantic/authority checks at dispatch.
			spec := model.WorkflowManifestSpec{DispatchMode: "sync", Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "fixture", Name: "named-human"}}, Steps: []model.WorkflowStepSpec{{ID: "recover-once", TimeoutSeconds: 90, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.recover_unredeemed_native_birth"}, With: map[string]any{"binding": model.CapacityNativeAbortRecoveryBinding{Schema: "native_pre_registration_abort_unredeemed_recovery_v1"}, "confirmation": "FIXED ORIGINAL ONLY"}}}}
			switch name {
			case "unknown_operation":
				spec.Steps[0].Use.Operation += "_unchecked"
			case "integration_target_refused":
				spec.Steps[0].Use.InstanceRef = &model.ManifestSelector{Namespace: "fixture", Name: "caller-selected"}
			}
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal("literal workflow fixture unavailable")
			}
			parsed, err := ParseWorkflowSpec(json.RawMessage(raw))
			if err == nil {
				err = ValidateWorkflowSpec(parsed)
			}
			if (err == nil) != (name == "exact_sync_literal") {
				t.Fatal("advertised recovery builtin registration boundary changed")
			}
		})
	}
}
