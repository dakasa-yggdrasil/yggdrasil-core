package repository

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The native decoder accepts a raw JSON object through json.RawMessage. Passing
// []byte would marshal this complete SQL scan as a base64 JSON string instead.
// Keep this regression in ordinary unit CI, before the natural-expiry PG cases.
func TestPreActionPlanEffectScanJSONWire(t *testing.T) {
	positive := preActionPlanEffectScan{
		Schema: "preaction_failed_plan_effect_scan_v1",
		Base: CapacityDispatchFinalizationLostEffectScan{
			CapacityDispatchAbandonedEffectScan: CapacityDispatchAbandonedEffectScan{
				ClockSkewMarginSeconds: CapacityDispatchAbandonedClockSkewMarginSec,
			},
			Schema:     CapacityDispatchFinalizationLostScanSchema,
			BaseSchema: CapacityDispatchAbandonedScanSchema,
		},
		CurrentIntentMatchesAnchor: true,
		CurrentMembersMatchAnchor:  true,
	}
	raw, err := json.Marshal(positive)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err = json.Unmarshal(raw, &outer); err != nil || len(outer) != 11 {
		t.Fatal("complete SQL scan requires the closed eleven-key object", err)
	}
	var base map[string]json.RawMessage
	if err = json.Unmarshal(outer["base"], &base); err != nil || len(base) != 47 {
		t.Fatal("complete inherited scan requires all forty-seven keys", err)
	}
	if !preActionPlanEffectScanTolerable(raw) {
		t.Fatal("complete raw SQL object was not decoded as JSON")
	}
	stringJSON, err := json.Marshal(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	base64JSON, err := json.Marshal(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	for name, wire := range map[string][]byte{
		"string": stringJSON,
		"base64": base64JSON,
		"null":   []byte("null"),
	} {
		t.Run(name, func(t *testing.T) {
			if preActionPlanEffectScanTolerable(wire) {
				t.Fatal("non-object scan admitted")
			}
		})
	}
	mutate := func(t *testing.T, edit func(map[string]json.RawMessage)) []byte {
		t.Helper()
		var value map[string]json.RawMessage
		if e := json.Unmarshal(raw, &value); e != nil {
			t.Fatal(e)
		}
		edit(value)
		wire, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		return wire
	}
	editBase := func(t *testing.T, value map[string]json.RawMessage, edit func(map[string]json.RawMessage)) {
		t.Helper()
		var fields map[string]json.RawMessage
		if e := json.Unmarshal(value["base"], &fields); e != nil {
			t.Fatal(e)
		}
		edit(fields)
		wire, e := json.Marshal(fields)
		if e != nil {
			t.Fatal(e)
		}
		value["base"] = wire
	}
	faults := map[string]func(*testing.T, map[string]json.RawMessage){
		"missing_outer_field":   func(t *testing.T, v map[string]json.RawMessage) { delete(v, "other_busy_runs") },
		"unknown_outer_field":   func(t *testing.T, v map[string]json.RawMessage) { v["unknown"] = json.RawMessage("0") },
		"null_outer_field":      func(t *testing.T, v map[string]json.RawMessage) { v["other_busy_runs"] = json.RawMessage("null") },
		"boolean_outer_counter": func(t *testing.T, v map[string]json.RawMessage) { v["other_busy_runs"] = json.RawMessage("false") },
		"nonzero_outer_counter": func(t *testing.T, v map[string]json.RawMessage) { v["other_busy_runs"] = json.RawMessage("1") },
		"missing_base_field": func(t *testing.T, v map[string]json.RawMessage) {
			editBase(t, v, func(b map[string]json.RawMessage) { delete(b, "canary_returns_since_start") })
		},
		"unknown_base_field": func(t *testing.T, v map[string]json.RawMessage) {
			editBase(t, v, func(b map[string]json.RawMessage) { b["unknown"] = json.RawMessage("0") })
		},
		"null_base_counter": func(t *testing.T, v map[string]json.RawMessage) {
			editBase(t, v, func(b map[string]json.RawMessage) { b["canary_returns_since_start"] = json.RawMessage("null") })
		},
		"boolean_base_counter": func(t *testing.T, v map[string]json.RawMessage) {
			editBase(t, v, func(b map[string]json.RawMessage) { b["canary_returns_since_start"] = json.RawMessage("false") })
		},
		"nonzero_base_counter": func(t *testing.T, v map[string]json.RawMessage) {
			editBase(t, v, func(b map[string]json.RawMessage) { b["canary_returns_since_start"] = json.RawMessage("1") })
		},
		"false_current_anchor": func(t *testing.T, v map[string]json.RawMessage) {
			v["current_intent_matches_anchor"] = json.RawMessage("false")
		},
		"false_current_members": func(t *testing.T, v map[string]json.RawMessage) {
			v["current_members_match_anchor"] = json.RawMessage("false")
		},
	}
	for name, edit := range faults {
		t.Run(name, func(t *testing.T) {
			wire := mutate(t, func(v map[string]json.RawMessage) { edit(t, v) })
			if preActionPlanEffectScanTolerable(wire) {
				t.Fatal("incomplete or effectful scan admitted")
			}
		})
	}
}
