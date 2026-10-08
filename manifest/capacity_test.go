package manifest

import (
	"encoding/json"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestCapacityPolicyStrictDecode(t *testing.T) {
	for _, raw := range []string{`{"unknown":true}`, `{} {}`, `{"execution_enabled":"true"}`} {
		if _, err := ParseCapacityPolicySpec(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted ambiguous policy %s", raw)
		}
	}
	if _, err := ParseCapacityPolicySpec(json.RawMessage(`{"execution_enabled":false}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityWorkflowRequiresAuthorization(t *testing.T) {
	for _, operation := range []string{"capacity.assess", "capacity.observe", "capacity.claim", "capacity.renew", "capacity.advance", "capacity.recover", "capacity.renew_recovery", "capacity.reconcile"} {
		spec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Steps: []model.WorkflowStepSpec{{ID: "capacity", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: operation}}}}
		if err := ValidateWorkflowSpec(spec); err == nil {
			t.Fatal("actorless capacity workflow accepted")
		}
		spec.Authorization = &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "ops", Name: "capacity-rbac"}}
		if err := ValidateWorkflowSpec(spec); err != nil {
			t.Fatal(err)
		}
	}
}
