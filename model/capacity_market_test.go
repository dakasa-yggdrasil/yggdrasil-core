package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapacityMarketJSONClosedContract(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"duplicate", `{"schema":"a","schema":"b"}`},
		{"case_alias", `{"Schema":"a"}`},
		{"case_duplicate", `{"schema":"a","SCHEMA":"b"}`},
		{"unknown", `{"schema":"a","price_override":1}`},
		{"nested_unknown", `{"profiles":[{"adapter":{"unknown":1}}]}`},
		{"nested_case", `{"profiles":[{"adapter":{"Manifest_ID":"x"}}]}`},
		{"nested_duplicate", `{"profiles":[{"provider":"a","provider":"b"}]}`},
		{"null_root", `null`},
		{"null_array", `{"profiles":null}`},
		{"null_leaf", `{"profiles":[{"workload_qualified":null}]}`},
		{"trailing", `{"schema":"a"} {}`},
		{"fractional_integer", `{"horizon_seconds":1.5}`},
		{"integer_overflow", `{"horizon_seconds":9223372036854775808}`},
		{"nested_limit", `{"profiles":` + strings.Repeat("[", 25) + `0` + strings.Repeat("]", 25) + `}`},
		{"byte_limit", `{"schema":"` + strings.Repeat("a", 2<<20) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a CapacityMarketAssessment
			if err := json.Unmarshal([]byte(tc.body), &a); err == nil {
				t.Fatal("unsafe market JSON accepted")
			}
		})
	}
	var a CapacityMarketAssessment
	if err := json.Unmarshal([]byte(`{"schema":"capacity_market_v1","currency":"USD","horizon_seconds":3600,"profiles":[]}`), &a); err != nil || a.Currency != "USD" || a.Profiles == nil {
		t.Fatalf("canonical contract refused: %+v %v", a, err)
	}
}

func TestCapacityMarketBindingRejectsNestedContractDrift(t *testing.T) {
	for _, body := range []string{
		`{"profiles":[{"quota_dimensions":[{"scope":"regional","Per_Unit":1}]}]}`,
		`{"profiles":[{"adapter":{"type_checksum":"x","type_checksum":"y"}}]}`,
		`{"profiles":[{"quota_dimensions":[{"limit":100}]}]}`,
		`{"profiles":[null]}`,
	} {
		var b CapacityMarketBinding
		if json.Unmarshal([]byte(body), &b) == nil {
			t.Fatalf("invalid closed binding accepted: %s", body)
		}
	}
}

func TestAbsentMarketPreservesLegacyJSON(t *testing.T) {
	for _, value := range []any{CapacityPolicySpec{}, CapacityAssessment{}, CapacityClockState{}} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, added := range []string{`"market_binding"`, `"native_worker_pool_binding"`, `"market"`, `"native_worker_pool"`, `"economic_candidate"`, `"economic_since"`} {
			if strings.Contains(string(raw), added) {
				t.Fatalf("legacy absence serialized %s", added)
			}
		}
	}
}
