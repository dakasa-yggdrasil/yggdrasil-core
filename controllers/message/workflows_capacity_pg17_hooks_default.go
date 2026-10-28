//go:build !nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// PG17 assertions observe the Linux qualification harness only. Production
// keeps its actual provider, receipt, witness, installation and confirmation
// checks in the original workflow; this assertion hook adds no authority.
func guestPG17AfterCreate(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, proof model.CapacityMutationProof) error {
	return nil
}

func guestPG17AfterConfirm(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, proof, guestProof model.CapacityMutationProof) error {
	return nil
}

func guestPG17AfterTerminal(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) error {
	return nil
}

func guestPG17AfterHistorical(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) error {
	return nil
}

func guestPG17BeforeConfirm(ctx context.Context, store repository.CapacityStore, policy model.Manifest, workflow model.ManifestReference, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, proof model.CapacityMutationProof) (model.CapacityMutationProof, error) {
	return proof, nil
}
