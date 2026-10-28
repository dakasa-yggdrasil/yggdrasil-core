//go:build linux && nativequalification

package capacitynativeqemu

import "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"

// Separate fixed qualification cases. Existing lost-empty negatives retain their ABI.
func PostlossSourceCase(c string) bool {
	return capacity.GuestPostlossQualificationSlot(c) != 0
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
