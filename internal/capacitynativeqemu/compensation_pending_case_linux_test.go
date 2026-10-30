//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Only the fixed failed-create cases join postloss pending.
func TestCanonicalCompensationPendingCaseIsClosed(t *testing.T) {
	for c, want := range map[string]bool{"canonical_compensation_unprotected_failed_create": true, "canonical_compensation_protected_failed_create": true, "canonical_failed_floor_recovery": true, "compensation_unprotected_failed_create": true, "compensation_protected_failed_create": true, "source_live_failed_floor_recovery": true, "compensation_unprotected_lost_create_reply": false, "canonical_postloss_unprotected_failed_create_reissue": false, "positive_original_lifecycle": false, "": false} {
		if CanonicalCompensationPendingCase(c) != want {
			t.Fatalf("case %q pending=%v", c, !want)
		}
		if want && SourceFailureSlot(c) != 2 {
			t.Fatalf("case %q failure slot moved", c)
		}
	}
	for _, tc := range []struct {
		name string
		slot int
	}{{"canonical_compensation_unprotected_failed_create", 1}, {"canonical_compensation_protected_failed_create", 1}, {"canonical_failed_floor_recovery", 1}, {"compensation_unprotected_failed_create", 1}, {"compensation_protected_failed_create", 1}, {"source_live_failed_floor_recovery", 1}, {"positive_original_lifecycle", 2}} {
		r := &Realm{Request: SourceRequest{NativeCase: tc.name}}
		if err := r.EnrolledPending(context.Background(), model.CapacityMutationGrant{Slot: tc.slot}, model.CapacityGuestOriginalProvisioningPreregistration{Slot: tc.slot}, model.CapacityGuestOriginalProvisioningReceipt{}); !errors.Is(err, ErrOriginalUnknown) {
			t.Fatalf("case %s slot %d published a pending enrollment", tc.name, tc.slot)
		}
	}
}
