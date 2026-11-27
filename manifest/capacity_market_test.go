package manifest

import (
	"encoding/json"
	"testing"
)

func TestCapacityMarketPolicyBindingsAreStrictOptIn(t *testing.T) {
	for _, field := range []string{"market_binding", "native_worker_pool_binding"} {
		for _, raw := range []string{
			`{"` + field + `":null}`,
			`{"` + field + `":{ },"` + field + `":{ }}`,
			`{"` + field + `":{ },"` + field + `":null}`,
			`{"` + field + `":[]}`,
			`{"` + field + `":{"mode":"x","Mode":"y"}}`,
			`{"` + field + `":{"mode":"x","unexpected":true}}`,
		} {
			if _, err := ParseCapacityPolicySpec(json.RawMessage(raw)); err == nil {
				t.Errorf("accepted ambiguous source binding: %s", raw)
			}
		}
	}
	for _, raw := range []string{`{"Market_binding":{}}`, `{"NATIVE_WORKER_POOL_BINDING":{}}`} {
		if _, err := ParseCapacityPolicySpec(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted aliased operator field: %s", raw)
		}
	}
	legacy, err := ParseCapacityPolicySpec(json.RawMessage(`{"execution_enabled":false}`))
	if err != nil || legacy.MarketBinding != nil || legacy.NativeWorkerPoolBinding != nil {
		t.Fatalf("legacy default changed: %+v %v", legacy, err)
	}
}
