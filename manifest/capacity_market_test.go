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
			if err := ValidateCapacityMarketPolicyJSON([]byte(raw)); err == nil {
				t.Errorf("stored policy accepted ambiguous source binding: %s", raw)
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

func TestCapacityMarketValidatorDoesNotReinterpretHistoricalPolicyFields(t *testing.T) {
	// The repository's preexisting parser owns legacy policy members. In
	// particular a new market validator cannot retrofit a full authoring gate.
	for _, raw := range []string{
		`{"execution_enabled":false,"historical_extension":{"state":"retained"}}`,
		`{"executor_activity_binding":null}`,
		`{"execution_enabled":false,"execution_enabled":true}`,
	} {
		if err := ValidateCapacityMarketPolicyJSON([]byte(raw)); err != nil {
			t.Fatalf("new market validator changed an unrelated historical contract: %v", err)
		}
	}
}
