package manifest

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"testing"
)

func TestNativeAbortQuarantineWorkflowRegistration(t *testing.T) {
	for _, name := range []string{"advertised_builtin", "arbitrary_builtin"} {
		t.Run(name, func(t *testing.T) {
			op := "capacity.quarantine_uncertain_native_birth"
			if name == "arbitrary_builtin" {
				op += "_arbitrary"
			}
			spec := model.WorkflowManifestSpec{DispatchMode: "sync", Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "fixture", Name: "named-human"}}, Steps: []model.WorkflowStepSpec{{ID: "quarantine-once", TimeoutSeconds: 90, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: op}, With: map[string]any{"binding": model.CapacityNativeAbortQuarantineBinding{Schema: "native_uncertain_abort_quarantine_v1"}, "confirmation": "QUARANTINE UNKNOWN ONLY"}}}}
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal("fixed literal unavailable")
			}
			parsed, err := ParseWorkflowSpec(raw)
			if err == nil {
				err = ValidateWorkflowSpec(parsed)
			}
			if (err == nil) != (name == "advertised_builtin") {
				t.Fatal("quarantine registration bypassed builtin registry")
			}
		})
	}
}
