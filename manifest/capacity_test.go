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
	for _, operation := range []string{"capacity.assess", "capacity.observe", "capacity.claim", "capacity.renew", "capacity.advance", "capacity.recover", "capacity.renew_recovery", "capacity.reconcile", "capacity.grant_mutation", "capacity.record_slot", "capacity.confirm_mutation"} {
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

func TestCapacityDemandSourceStrictDecode(t *testing.T) {
	for _, field := range []string{"healthy", "qualified", "url", "token", "sql", "principal", "capacity", "proof"} {
		raw := `{"controller_binding":{"demand_source":{"` + field + `":true}}}`
		if _, err := ParseCapacityPolicySpec(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted request-only source field %s", field)
		}
	}
	legacy := model.CapacityControllerBinding{Mode: "capacity_dispatch_prestart_v1", MachinePrincipalID: "fixed", DispatchLeaseSeconds: 30}
	raw, err := json.Marshal(legacy)
	if err != nil || string(raw) != `{"mode":"capacity_dispatch_prestart_v1","machine_principal_id":"fixed","dispatch_lease_seconds":30}` {
		t.Fatal("absent demand changed original controller wire")
	}
}
