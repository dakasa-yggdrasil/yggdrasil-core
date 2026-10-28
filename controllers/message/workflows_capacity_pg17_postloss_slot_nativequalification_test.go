//go:build linux && nativequalification

package message

import "testing"

func TestPG17PostlossCaseBindsActualSlotProtection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		slot      int
		protected int
		want      bool
	}{
		{"canonical_postloss_protected_failed_create_reissue", 1, 2, true},
		{"canonical_postloss_protected_failed_create_reissue", 2, 2, false},
		{"canonical_postloss_protected_failed_create_reissue", 1, 0, false},
		{"canonical_postloss_unprotected_failed_create_reissue", 2, 1, true},
		{"canonical_postloss_unprotected_failed_create_reissue", 1, 1, false},
		{"canonical_postloss_unprotected_failed_create_reissue", 2, 2, false},
		{"foreign", 1, 2, false},
	} {
		if got := pg17PostlossSlotProtection(tc.name, tc.slot, tc.protected); got != tc.want {
			t.Fatalf("case=%s slot=%d protected=%d: got %v, want %v", tc.name, tc.slot, tc.protected, got, tc.want)
		}
	}
}
