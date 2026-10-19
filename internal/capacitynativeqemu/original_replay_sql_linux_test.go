//go:build linux && nativequalification

package capacitynativeqemu

import (
	"strings"
	"testing"
)

// These tests exercise only the refusal predicate, never pretend to be an
// actual SQL/provider session or a successful old PostgreSQL case.
func TestOriginalReplaySQLRejectsMutationAndPrematureNativeEffect(t *testing.T) {
	before := originalReplaySQLSnapshot{State: "redeemed", GrantID: "same", AttemptID: "winner", Preregistrations: 1, GrantWireSHA256: strings.Repeat("a", 64), PreregistrationWireSHA256: strings.Repeat("b", 64)}
	if !originalReplaySQLUnchanged(before, before) {
		t.Fatal("unchanged snapshot comparator refused")
	}
	for _, tc := range []struct {
		name   string
		change func(*originalReplaySQLSnapshot)
	}{
		{"second_attempt", func(x *originalReplaySQLSnapshot) { x.AttemptID = "other" }},
		{"second_grant", func(x *originalReplaySQLSnapshot) { x.GrantID = "other" }},
		{"grant_record_mutation", func(x *originalReplaySQLSnapshot) { x.GrantWireSHA256 = strings.Repeat("c", 64) }},
		{"preregistration_mutation", func(x *originalReplaySQLSnapshot) { x.PreregistrationWireSHA256 = strings.Repeat("d", 64) }},
		{"duplicate_preregistration", func(x *originalReplaySQLSnapshot) { x.Preregistrations = 2 }},
		{"premature_member", func(x *originalReplaySQLSnapshot) { x.Members = 1 }},
		{"premature_ensured_event", func(x *originalReplaySQLSnapshot) { x.EnsuredEvents = 1 }},
		{"foreign_executor", func(x *originalReplaySQLSnapshot) { x.ExecutorID = "other" }},
		{"foreign_policy", func(x *originalReplaySQLSnapshot) { x.PolicyID = "other" }},
		{"confirmed_before_send", func(x *originalReplaySQLSnapshot) { x.State = "confirmed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := before
			tc.change(&after)
			if originalReplaySQLUnchanged(before, after) {
				t.Fatal("changed or prematurely applied original accepted")
			}
		})
	}
}
