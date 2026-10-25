//go:build !nativequalification

package message

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestProductionOriginalGuestAssertionsLeaveRealAdmissionToWorkflow(t *testing.T) {
	ctx := context.Background()
	store := repository.CapacityStore{}
	policy := model.Manifest{}
	spec := model.CapacityPolicySpec{}
	binding := model.CapacityMutationBinding{}
	input := guestOriginalStepInput{}
	grant := model.CapacityMutationGrant{}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{}
	proof := model.CapacityMutationProof{}
	for name, call := range map[string]func() error{
		"after_create": func() error { return guestPG17AfterCreate(ctx, store, policy, spec, binding, input, grant, pre, proof) },
		"before_confirm": func() error {
			return guestPG17BeforeConfirm(ctx, store, policy, model.ManifestReference{}, input, grant)
		},
		"after_confirm":  func() error { return guestPG17AfterConfirm(ctx, store, policy, spec, binding, input, grant, proof) },
		"after_terminal": func() error { return guestPG17AfterTerminal(ctx, store, policy, spec, binding, input, grant, pre, nil) },
		"after_historical": func() error {
			return guestPG17AfterHistorical(ctx, store, policy, spec, binding, input, grant, pre, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err != nil {
				t.Fatalf("qualification assertion blocked ordinary production: %v", err)
			}
			// A successful assertion is deliberately not an owning create return.
			// Missing private invocation state must refuse before touching this nil DB.
			if _, err := guestOriginalSourceCreateWitness(ctx, store, "unowned", proof, nil); err == nil {
				t.Fatal("assertion manufactured a signed original witness")
			}
			if err := guestOriginalSourceWitnessed(ctx, grant, pre, model.CapacityGuestOriginalCreateWitness{}); err == nil {
				t.Fatal("assertion manufactured original create state")
			}
			if err := guestOriginalSourceInstallation(ctx, grant, pre, model.CapacityGuestOriginalProvisioningReceipt{}, model.CapacityGuestOriginalInstallationConfirmation{}, time.Now()); err == nil {
				t.Fatal("assertion manufactured an installation")
			}
			if err := guestOriginalSourceEnrolled(ctx, grant, pre, model.CapacityGuestOriginalProvisioningReceipt{}); err == nil {
				t.Fatal("assertion manufactured enrollment")
			}
		})
	}
}
