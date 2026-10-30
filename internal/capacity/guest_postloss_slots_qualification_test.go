//go:build linux && nativequalification

package capacity

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestPostlossQualificationSlot(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{"canonical_postloss_unprotected_failed_create_reissue", 2},
		{"canonical_postloss_protected_failed_create_reissue", 1},
		{"positive_original_lifecycle", 0},
		{"compensation_protected_lost_create_reply", 0},
		{"", 0},
	} {
		if got := GuestPostlossQualificationSlot(tc.name); got != tc.want {
			t.Fatalf("case %q: got slot %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestGuestPostlossObservationBindsCaseAndSlot(t *testing.T) {
	binding := model.CapacityGuestRetirementBinding{
		EvidenceClass: "native_qemu_qualification", CoreAuthoritySourceCommit: CurrentGuestCoreSource(),
		ProfileManifest: model.CapacityGuestProtectedProfileManifest{Profile: "qualification-original-echo-writer-v1"},
	}
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name string
		slot int
	}{
		{"canonical_postloss_unprotected_failed_create_reissue", 2},
		{"canonical_postloss_protected_failed_create_reissue", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := model.CapacityGuestOriginalCreateWitness{Tuple: model.CapacityGuestNativeTuple{Provider: "native-qemu", Slot: tc.slot}, SourceObservation: &model.CapacityGuestPostlossObservation{
				Schema: "canonical_postloss_observed_create_v1", Scope: "SOURCE_ONLY_OBSERVED_SAME_CREATE_NOT_ACCEPTED_TRANSPORT", Case: tc.name,
				OriginalOutcome: "uncertain", OwningReplySHA256: BusinessCreationSHA256(nil), OwningReplyReadSHA256: digest,
				IndependentNativeReadSHA256: digest, OriginalCreatorSHA256: digest,
			}}
			if !guestPostlossObservationAllowed(binding, w) {
				t.Fatal("exact source case and failed slot rejected")
			}
			w.Tuple.Slot = 3 - tc.slot
			if guestPostlossObservationAllowed(binding, w) {
				t.Fatal("cross-case slot admitted")
			}
			w.Tuple.Slot = tc.slot
			w.SourceObservation.ProductionQualified = true
			if guestPostlossObservationAllowed(binding, w) {
				t.Fatal("source-only evidence claimed production qualification")
			}
		})
	}
}
