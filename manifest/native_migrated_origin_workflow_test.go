package manifest

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
)

func TestNativeMigratedOriginWorkflowRegistration(t *testing.T) {
	for _, name := range []string{"advertised_builtin", "arbitrary_builtin"} {
		t.Run(name, func(t *testing.T) {
			op := "capacity.retire_migrated_native_origin"
			if name == "arbitrary_builtin" {
				op += "_arbitrary"
			}
			w := model.WorkflowManifestSpec{DispatchMode: "sync", Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "fixed", Name: "named-human"}}, Steps: []model.WorkflowStepSpec{{ID: "retire-once", TimeoutSeconds: 90, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: op}, With: map[string]any{"binding": model.CapacityMigratedNativeOriginBinding{}, "confirmation": "{{ inputs.confirmation }}"}}}}
			raw, err := json.Marshal(w)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseWorkflowSpec(raw)
			if err == nil {
				err = ValidateWorkflowSpec(parsed)
			}
			if (err == nil) != (name == "advertised_builtin") {
				t.Fatal("retirement bypassed closed builtin registry")
			}
		})
	}
}
