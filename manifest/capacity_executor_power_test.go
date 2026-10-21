package manifest

import (
	"encoding/json"
	"testing"
)

func TestExecutorPowerBindingClosedCanonicalDecode(t *testing.T) {
	for _, raw := range []string{
		`{"executor_power_binding":null}`,
		`{"Executor_Power_Binding":{}}`,
		`{"executor_power_binding":{},"executor_power_binding":{}}`,
		`{"executor_power_binding":{"enabled":true,"Enabled":false}}`,
		`{"executor_power_binding":{"resource":{"instance_id":"i-0123456789abcdef0","Instance_ID":"foreign"}}}`,
		`{"executor_power_binding":{"unexpected":true}}`,
	} {
		if _, err := ParseCapacityPolicySpec(json.RawMessage(raw)); err == nil {
			t.Fatal("ambiguous authority binding accepted", raw)
		}
	}
	p, err := ParseCapacityPolicySpec(json.RawMessage(`{}`))
	if err != nil || p.ExecutorPowerBinding != nil {
		t.Fatal("legacy default-off broken", err)
	}
	p, err = ParseCapacityPolicySpec(json.RawMessage(`{"executor_power_binding":{"mode":"ec2_power_v1","enabled":false}}`))
	if err != nil || p.ExecutorPowerBinding == nil || p.ExecutorPowerBinding.Enabled {
		t.Fatal("explicit disabled decode", err)
	}
}
func TestExecutorPowerOperationsStayProtectedWorkflowSteps(t *testing.T) {
	for _, op := range []string{"capacity.adopt_executor_power", "capacity.grant_executor_power", "capacity.confirm_executor_power"} {
		raw := json.RawMessage(`{"trigger":{"mode":"manual"},"authorization":{"rbac":{"namespace":"ops","name":"lab"}},"steps":[{"id":"power","use":{"kind":"yggdrasil","operation":"` + op + `"}}]}`)
		if _, err := ParseWorkflowSpec(raw); err != nil {
			t.Fatal(op, err)
		}
	}
}
