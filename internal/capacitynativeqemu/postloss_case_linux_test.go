//go:build linux && nativequalification

package capacitynativeqemu

import "testing"

func TestPostlossSourceGuestCaseFollowsActualSlot(t *testing.T) {
	for _, tc := range []struct {
		name              string
		baseline, failure int
	}{
		{"canonical_postloss_unprotected_failed_create_reissue", 1, 2},
		{"canonical_postloss_protected_failed_create_reissue", 2, 1},
	} {
		if SourceBaselineSlot(tc.name) != tc.baseline || SourceFailureSlot(tc.name) != tc.failure || sourceGuestCase(tc.name, tc.baseline) != "positive_original_lifecycle" || sourceGuestCase(tc.name, tc.failure) != tc.name {
			t.Fatalf("source guest case/slot mismatch for %s", tc.name)
		}
	}
}
