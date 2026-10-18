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

// Production retains the original single issue and all repository admission gates.
func guestOriginalSourceIssue(ctx context.Context, store repository.CapacityStore, policy model.Manifest, step model.WorkflowStepSpec, input guestOriginalStepInput, issue model.CapacityMutationIssue) (model.CapacityMutationGrant, error) {
	return store.IssueMutation(ctx, policy, input.Generation, input.FencingToken, input.LeaseOwner, issue)
}

func guestOriginalSourceAssertApply(context.Context, repository.CapacityStore, model.Manifest, guestOriginalStepInput, model.CapacityMutationProof, model.CapacityMutationGrant) error {
	return nil
}

func guestOriginalSourceAssertNativeRefusals(context.Context, repository.CapacityStore, model.Manifest, guestOriginalStepInput, model.CapacityMutationProof, model.CapacityMutationGrant) error {
	return nil
}

// Absent from production behavior: no workflow input can activate this hook.
func guestOriginalSourceContractFence(context.Context, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, model.CapacityMutationBinding, guestOriginalStepInput, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration) (any, bool, error) {
	return nil, false, nil
}

func guestOriginalSourceLivePartial(context.Context, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, model.CapacityMutationBinding, guestOriginalStepInput, ed25519.PrivateKey) (any, bool, error) { return nil, false, nil }

func guestOriginalSourceHistoricalConfirm(context.Context,repository.CapacityStore,model.Manifest,model.CapacityPolicySpec,model.CapacityMutationBinding,guestOriginalStepInput,ed25519.PrivateKey,model.CapacityMutationGrant,model.CapacityGuestOriginalProvisioningPreregistration,model.CapacityGuestOriginalProvisioningReceipt,model.CapacityMutationProof)(any,bool,error){return nil,false,nil}

func guestOriginalSourceTerminal(context.Context,repository.CapacityStore,model.Manifest,model.CapacityPolicySpec,model.CapacityMutationBinding,guestOriginalStepInput,model.CapacityMutationGrant,model.CapacityGuestOriginalProvisioningPreregistration,ed25519.PrivateKey)(any,bool,error){return nil,false,nil}
