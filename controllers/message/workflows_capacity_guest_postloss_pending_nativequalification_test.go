//go:build linux && nativequalification

package message

import (
	"context"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"testing"
)

func TestSourcePostlossPendingSelectionFailsClosed(t *testing.T) {
	old := originalGuestNativeRealm
	t.Cleanup(func() { originalGuestNativeRealm = old })
	input := guestOriginalStepInput{Slot: 1}
	grant := model.CapacityMutationGrant{Slot: 1}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Slot: 1}
	call := func(ctx context.Context) (bool, error) {
		return guestOriginalSourcePendingPostloss(ctx, repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{}, input, grant, pre, model.CapacityMutationProof{})
	}
	originalGuestNativeRealm = nil
	if _, err := call(context.Background()); err == nil {
		t.Fatal("missing realm accepted")
	}
	for _, tc := range []struct {
		name    string
		slot    int
		pending bool
	}{
		{"positive_original_lifecycle", 1, false}, {"canonical_postloss_unprotected_failed_create_reissue", 1, false}, {"canonical_postloss_protected_failed_create_reissue", 2, false}, {"unknown", 1, false},
		{"canonical_postloss_protected_failed_create_reissue", 1, true}, {"canonical_postloss_unprotected_failed_create_reissue", 2, true},
		{"canonical_compensation_unprotected_failed_create", 1, false}, {"canonical_compensation_protected_failed_create", 1, false}, {"canonical_failed_floor_recovery", 1, false}, {"canonical_failed_floor_recovery", 2, true}, {"compensation_unprotected_failed_create", 2, false}, {"compensation_protected_failed_create", 2, false}, {"compensation_unprotected_lost_create_reply", 2, false},
		{"canonical_compensation_unprotected_failed_create", 2, true}, {"canonical_compensation_protected_failed_create", 2, true},
	} {
		originalGuestNativeRealm = &q.Realm{Request: q.SourceRequest{NativeCase: tc.name}}
		input.Slot = tc.slot
		grant.Slot = 3 - tc.slot
		pending, err := call(context.Background())
		if pending != tc.pending || (tc.pending && err == nil) || (!tc.pending && err != nil) {
			t.Fatalf("case %s slot %d did not fail closed", tc.name, tc.slot)
		}
	}
}
