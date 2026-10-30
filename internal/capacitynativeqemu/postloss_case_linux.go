//go:build linux && nativequalification

package capacitynativeqemu

import "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"

// Separate fixed qualification cases. Existing lost-empty negatives retain their ABI.
func PostlossSourceCase(c string) bool {
	return capacity.GuestPostlossQualificationSlot(c) != 0
}

// CanonicalCompensationPendingCase holds only fixed failed-create
// qualification cases pending: their accepted parent stays settled.
func CanonicalCompensationPendingCase(c string) bool {
	return c == "canonical_compensation_unprotected_failed_create" || c == "canonical_compensation_protected_failed_create" || c == "canonical_failed_floor_recovery" || c == "compensation_unprotected_failed_create" || c == "compensation_protected_failed_create" || c == "source_live_failed_floor_recovery"
}

// SourceFailureSlot is a fixed case-to-slot binding, never an arbitrary caller
// input. Existing non-postloss cases retain their original slot 2.
func SourceFailureSlot(c string) int {
	if slot := capacity.GuestPostlossQualificationSlot(c); slot != 0 {
		return slot
	}
	if SourceCompensationCase(c) {
		return 2
	}
	return 0
}

// SourceBaselineSlot is the independently confirmed surviving original.
func SourceBaselineSlot(c string) int {
	if SourceFailureSlot(c) == 1 {
		return 2
	}
	return 1
}

func sourceGuestCase(nativeCase string, slot int) string {
	if slot == SourceBaselineSlot(nativeCase) {
		return "positive_original_lifecycle"
	}
	return nativeCase
}
