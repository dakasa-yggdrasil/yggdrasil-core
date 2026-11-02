//go:build linux && nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"testing"
)

// This tests only the assertion selector. Qualification still requires the
// stored signed witness and native-read/proof join and the actual QEMU run.
func TestPG17ConfirmSettlementPreservesUnknown(t *testing.T) {
	proof := model.CapacityMutationProof{ResourceID: "resource"}
	uncertain := model.CapacityMutationSettleRequest{Outcome: "uncertain", TransportCompleted: true}
	accepted := model.CapacityMutationSettleRequest{Outcome: "accepted", ResourceID: "resource"}
	if pg17ConfirmSettlementClass("positive_original_lifecycle", 2, &accepted, proof) != 1 {
		t.Fatal("accepted resource rejected")
	}
	accepted.ResourceID = "foreign"
	if pg17ConfirmSettlementClass("positive_original_lifecycle", 2, &accepted, proof) != 0 {
		t.Fatal("foreign accepted resource accepted")
	}
	cases := []struct {
		name string
		slot int
	}{{"canonical_postloss_unprotected_failed_create_reissue", 2}, {"canonical_postloss_protected_failed_create_reissue", 1}}
	for _, c := range cases {
		if pg17ConfirmSettlementClass(c.name, c.slot, &uncertain, proof) != 2 {
			t.Fatal("valid unknown settlement refused", c)
		}
		if pg17ConfirmSettlementClass(c.name, 3-c.slot, &uncertain, proof) != 0 {
			t.Fatal("foreign slot accepted", c)
		}
	}
	if pg17ConfirmSettlementClass("positive_original_lifecycle", 2, &uncertain, proof) != 0 {
		t.Fatal("unknown case accepted")
	}
	for _, f := range []func(*model.CapacityMutationSettleRequest){
		func(s *model.CapacityMutationSettleRequest) { s.ResourceID = "foreign" },
		func(s *model.CapacityMutationSettleRequest) { s.ResourceCreatedAt = "foreign" },
		func(s *model.CapacityMutationSettleRequest) { s.ActionID = "foreign" },
		func(s *model.CapacityMutationSettleRequest) { s.NextActionIDs = []string{"foreign"} },
		func(s *model.CapacityMutationSettleRequest) {
			s.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{ID: "foreign"}}
		},
		func(s *model.CapacityMutationSettleRequest) { s.AuxiliaryInventoryComplete = true },
		func(s *model.CapacityMutationSettleRequest) { s.TransportCompleted = false },
		func(s *model.CapacityMutationSettleRequest) { s.Outcome = "rejected_before_send" },
	} {
		bad := uncertain
		f(&bad)
		if pg17ConfirmSettlementClass(cases[0].name, 2, &bad, proof) != 0 {
			t.Fatal("altered unknown settlement accepted")
		}
	}
}

func TestPG17ConfirmWithoutRealmReturnsHeld(t *testing.T) {
	old := originalGuestNativeRealm
	originalGuestNativeRealm = nil
	t.Cleanup(func() { originalGuestNativeRealm = old })
	_, err := guestPG17MutationAfterConfirm(context.Background(), repository.CapacityStore{}, model.Manifest{}, model.CapacityPolicySpec{}, model.CapacityMutationBinding{}, guestOriginalStepInput{}, model.CapacityMutationGrant{}, model.CapacityMutationProof{}, model.CapacityMutationProof{})
	if err == nil {
		t.Fatal("missing realm accepted")
	}
}
