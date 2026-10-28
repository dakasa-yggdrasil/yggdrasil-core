//go:build linux && nativequalification

package message

import "testing"

func TestRetirementStep39DiagnosticClosed(t *testing.T) {
	for _, tc := range []struct {
		name, want                              string
		http, floor, decode, load, auth, record bool
	}{
		{"http", "original-retirement-39-http", true, true, true, true, true, true},
		{"floor", "original-retirement-39-floor", false, true, true, true, true, true},
		{"decode", "original-retirement-39-decode", false, false, true, true, true, true},
		{"load", "original-retirement-39-load", false, false, false, true, true, true},
		{"auth", "original-retirement-39-auth", false, false, false, false, true, true},
		{"record", "original-retirement-39-record", false, false, false, false, false, true},
		{"none", "original-guest-step-39", false, false, false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := guestRetirementStep39Predicate(tc.http, tc.floor, tc.decode, tc.load, tc.auth, tc.record); got != tc.want {
				t.Fatalf("got %q", got)
			}
		})
	}
}
