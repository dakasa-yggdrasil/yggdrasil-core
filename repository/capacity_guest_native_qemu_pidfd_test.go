package repository

import "testing"

// A pin still has to match the exact creator identity, original Wait/EOF,
// poll and close times. This checks only the actual Linux poll bit mask.
func TestGuestNativeQEMUPIDFDExitMask(t *testing.T) {
	for _, tc := range []struct {
		name     string
		value    int16
		accepted bool
	}{
		{"exited_unreaped", 1, true},
		{"exited_reaped", 1 | 16, true},
		{"not_ready", 0, false},
		{"hangup_alone", 16, false},
		{"error_with_readable", 1 | 8, false},
		{"invalid_with_readable", 1 | 32, false},
		{"unknown_with_readable", 1 | 64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if GuestNativeQEMUPIDFDExited(tc.value) != tc.accepted {
				t.Fatalf("unexpected event classification: %d", tc.value)
			}
		})
	}
}
