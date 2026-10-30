//go:build linux && nativequalification

package message

import (
	"errors"
	"testing"
)

func TestCanonicalFloorPermissionFailsClosedBeforeIssue(t *testing.T) {
	readErr := errors.New("permission read failed")
	issueErr := errors.New("issue failed")
	for _, tc := range []struct {
		name           string
		permissionOnly bool
		handled        bool
		readErr        error
		issueErr       error
		wantIssue      bool
		wantErr        error
	}{
		{"ordinary_create", false, false, nil, nil, false, nil},
		{"permission_only", true, true, nil, nil, true, nil},
		{"permission_disappeared", true, false, nil, nil, false, errOriginalGuestStep},
		{"permission_appeared_after_prepare", false, true, nil, nil, false, errOriginalGuestStep},
		{"read_failed_unhandled", false, false, readErr, nil, false, readErr},
		{"read_failed_permission_only", true, false, readErr, nil, false, readErr},
		{"read_failed_handled", true, true, readErr, nil, false, readErr},
		{"issue_failed", true, true, nil, issueErr, true, issueErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			output, handled, err := completeCanonicalFloorPermission(tc.permissionOnly, tc.handled, tc.readErr, func() (any, error) {
				calls++
				return "issued", tc.issueErr
			})
			if (calls == 1) != tc.wantIssue || calls > 1 || handled != tc.handled || !errors.Is(err, tc.wantErr) {
				t.Fatalf("calls=%d handled=%t err=%v", calls, handled, err)
			}
			if !tc.wantIssue && output != nil {
				t.Fatalf("unexpected output before issue: %v", output)
			}
		})
	}
}
