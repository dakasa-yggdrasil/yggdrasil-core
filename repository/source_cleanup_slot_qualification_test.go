//go:build linux && nativequalification

package repository

import "testing"

func TestSourceCleanupDirectoryBindsCaseAndSlot(t *testing.T) {
	for _, tc := range []struct {
		name, directory string
		slot            int
		want            bool
	}{
		{"canonical_postloss_protected_failed_create_reissue", "/fixture/slot-1", 1, true},
		{"canonical_postloss_protected_failed_create_reissue", "/fixture/slot-2", 1, false},
		{"canonical_postloss_protected_failed_create_reissue", "/fixture/slot-2", 2, false},
		{"canonical_postloss_unprotected_failed_create_reissue", "/fixture/slot-2", 2, true},
		{"compensation_protected_lost_create_reply", "/fixture/slot-2", 2, true},
		{"unknown", "/fixture/slot-2", 2, false},
	} {
		b := SourceFailureCleanupBody{NativeCase: tc.name, Slot: tc.slot, SourceSlotDirectory: tc.directory}
		if got := sourceCleanupSlotDirectoryMatches(b); got != tc.want {
			t.Fatalf("case=%s slot=%d path=%s: got %v, want %v", tc.name, tc.slot, tc.directory, got, tc.want)
		}
	}
}
