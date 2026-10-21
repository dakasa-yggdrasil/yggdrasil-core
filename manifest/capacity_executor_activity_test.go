package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestExecutorActivityPolicyBindingStrictDecode(t *testing.T) {
	for _, raw := range []string{
		`{"executor_activity_binding":null}`,
		`{"Executor_Activity_Binding":{}}`,
		`{"executor_activity_binding":{},"executor_activity_binding":{}}`,
		`{"executor_activity_binding":{"mode":"executor_activity_v1","Mode":"executor_activity_v1"}}`,
		`{"executor_activity_binding":{"instance_id":"caller-selected"}}`,
	} {
		if _, err := ParseCapacityPolicySpec(json.RawMessage(raw)); err == nil {
			t.Fatalf("ambiguous binding accepted: %s", raw)
		}
	}
	got, err := ParseCapacityPolicySpec(json.RawMessage(`{"executor_activity_binding":{"mode":"executor_activity_v1","lease_ttl_seconds":90,"idle_after_seconds":600,"max_observation_age_seconds":30,"max_tasks":10000}}`))
	if err != nil || got.ExecutorActivityBinding == nil || got.ExecutorActivityBinding.IdleAfterSeconds != 600 {
		t.Fatal(got, err)
	}
	legacy, err := ParseCapacityPolicySpec(json.RawMessage(`{"execution_enabled":false}`))
	if err != nil || legacy.ExecutorActivityBinding != nil {
		t.Fatal("legacy absence changed", err)
	}
}

func TestExecutorActivityWorkflowUsesExistingAuthorizationGate(t *testing.T) {
	for _, op := range []string{"capacity.initialize_executor_activity", "capacity.record_executor_activity", "capacity.observe_executor_activity", "capacity.reserve_executor_stop", "capacity.prepare_executor_stop"} {
		spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Steps: []model.WorkflowStepSpec{{ID: "activity", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: op}}}}
		if ValidateWorkflowSpec(spec) == nil {
			t.Fatalf("actorless %s accepted", op)
		}
		spec.Authorization = &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "ops", Name: "lab-activity-rbac"}}
		if err := ValidateWorkflowSpec(spec); err != nil {
			t.Fatalf("protected %s refused: %v", op, err)
		}
	}
}
