//go:build !linux && nativequalification

package message

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// The native qualification harness is unsupported on this platform.
func guestPG17AfterCreate(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, proof model.CapacityMutationProof) error {
	return errOriginalGuestStep
}

// The native qualification harness is unsupported on this platform.
func guestPG17AfterConfirm(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, proof model.CapacityMutationProof) error {
	return errOriginalGuestStep
}

// The native qualification harness is unsupported on this platform.
func guestPG17AfterTerminal(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) error {
	return errOriginalGuestStep
}

// The native qualification harness is unsupported on this platform.
func guestPG17AfterHistorical(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, output any) error {
	return errOriginalGuestStep
}

func guestPG17BeforeConfirm(ctx context.Context, store repository.CapacityStore, policy model.Manifest, workflow model.ManifestReference, input guestOriginalStepInput, grant model.CapacityMutationGrant) error {
	return errOriginalGuestStep
}
