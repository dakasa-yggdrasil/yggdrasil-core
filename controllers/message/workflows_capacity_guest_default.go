//go:build !nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestOriginalSourceLimit(ctx context.Context) (context.Context, context.CancelFunc, error) {
	return ctx, func() {}, errOriginalGuestStep
}
func guestOriginalSourceEnrolled(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalProvisioningReceipt) error {
	return errOriginalGuestStep
}
func guestOriginalSourceWitnessed(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalCreateWitness) error {
	return errOriginalGuestStep
}
func sourceGuestQualificationStep(context.Context, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, guestOriginalStepInput, ed25519.PrivateKey, string) (any, error) {
	return nil, errOriginalGuestStep
}
func guestOriginalSourceBeforeRetirement(context.Context, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, guestOriginalStepInput, ed25519.PrivateKey) (func() error, error) {
	return nil, errOriginalGuestStep
}
