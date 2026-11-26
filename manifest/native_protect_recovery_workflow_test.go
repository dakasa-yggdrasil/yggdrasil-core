package manifest

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
)

func TestNativeProtectRecoveryWorkflowRegistration(t *testing.T) {
	for _, name := range []string{"advertised_builtin", "arbitrary_builtin"} {
		t.Run(name, func(t *testing.T) {
			op := "capacity.recover_unredeemed_native_protect"
			if name == "arbitrary_builtin" {
				op += "_arbitrary"
			}
			w := model.WorkflowManifestSpec{DispatchMode: "sync", Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "fixed", Name: "named-human"}}, Steps: []model.WorkflowStepSpec{{ID: "recover-once", TimeoutSeconds: 90, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: op}, With: map[string]any{"binding": model.CapacityUnredeemedProtectRecoveryBinding{}, "confirmation": "{{ inputs.confirmation }}"}}}}
			raw, err := json.Marshal(w)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseWorkflowSpec(raw)
			if err == nil {
				err = ValidateWorkflowSpec(parsed)
			}
			if (err == nil) != (name == "advertised_builtin") {
				t.Fatal("recovery bypassed closed builtin registry")
			}
		})
	}
}
