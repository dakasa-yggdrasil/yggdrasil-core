//go:build !nativequalification

package message

import (
	"context"
	"crypto/ed25519"
	"reflect"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestOriginalSourceLimit(ctx context.Context) (context.Context, context.CancelFunc, error) {
	deadline, ok := ctx.Deadline()
	if !ok || !guestOriginalProviderAvailable(ctx) || ctx.Err() != nil || !time.Now().Before(deadline) {
		return ctx, func() {}, errOriginalGuestStep
	}
	return ctx, func() {}, nil
}
func guestOriginalSourceEnrolled(ctx context.Context, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, r model.CapacityGuestOriginalProvisioningReceipt) error {
	source, err := productionGuestSource(ctx)
	if err != nil || !source.installed || !reflect.DeepEqual(source.grant, g) || !reflect.DeepEqual(source.pre, pre) || !reflect.DeepEqual(source.receipt, r) {
		return errOriginalGuestStep
	}
	return nil
}
func guestOriginalSourceWitnessed(ctx context.Context, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, w model.CapacityGuestOriginalCreateWitness) error {
	source, err := productionGuestSource(ctx)
	if err != nil || !reflect.DeepEqual(source.supplier.createdGrant, g) || !reflect.DeepEqual(source.supplier.createdPre, pre) || w.OriginalCreateGrantID != g.GrantID || w.PreregistrationID != pre.PreregistrationID || w.OriginalCreateRequestSHA256 != g.RequestSHA256 || w.Tuple.ResourceID != source.supplier.createdProof.ResourceID || w.Tuple.CreatedAt != source.supplier.createdProof.ResourceCreatedAt {
		return errOriginalGuestStep
	}
	source.grant, source.pre, source.witness = g, pre, w
	return nil
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

func guestOriginalSourceLivePartial(context.Context, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, model.CapacityMutationBinding, guestOriginalStepInput, ed25519.PrivateKey, model.WorkflowStepSpec, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration) (any, bool, error) {
	return nil, false, nil
}

func guestOriginalSourceHistoricalConfirm(context.Context, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, model.CapacityMutationBinding, guestOriginalStepInput, ed25519.PrivateKey, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityMutationProof) (any, bool, error) {
	return nil, false, nil
}

func guestOriginalSourceTerminal(context.Context, repository.CapacityStore, model.Manifest, model.CapacityPolicySpec, model.CapacityMutationBinding, guestOriginalStepInput, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, ed25519.PrivateKey) (any, bool, error) {
	return nil, false, nil
}

func guestOriginalSourceCreateWitness(ctx context.Context, store repository.CapacityStore, id string, proof model.CapacityMutationProof, key ed25519.PrivateKey) (model.CapacityGuestOriginalCreateWitness, error) {
	source, err := productionGuestSource(ctx)
	if err != nil || source.supplier.createdPre.PreregistrationID != id || !reflect.DeepEqual(source.supplier.createdProof, proof) || source.supplier.createdGrant.GrantID != proof.GrantID || !source.owner.OriginalReturned(ctx, source.supplier.createdGrant, source.supplier.createdPre) {
		return model.CapacityGuestOriginalCreateWitness{}, errOriginalGuestStep
	}
	// The private source state exists only after this invocation's actual
	// original accepted adapter return and native read. A settled row or GET
	// cannot create it after an uncertain original RPC caller return.
	return store.RecordGuestCreateWitness(ctx, id, proof, key)
}

func guestOriginalSourceInstallation(ctx context.Context, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, r model.CapacityGuestOriginalProvisioningReceipt, confirmation model.CapacityGuestOriginalInstallationConfirmation, readReturnedAt time.Time) error {
	source, err := productionGuestSource(ctx)
	if err != nil || !reflect.DeepEqual(source.grant, g) || !reflect.DeepEqual(source.pre, pre) || r.PreregistrationID != pre.PreregistrationID || r.OriginalProvisioningSHA256 != r.Enrollment.Statement.OriginalNativeResultSHA256 || capacity.GuestOriginalInstallation(pre, r, confirmation, source.supplier.p.GuestRetirementBinding.ProvisionerPublicKey, readReturnedAt) != nil {
		return errOriginalGuestStep
	}
	source.receipt, source.installed = r, true
	return nil
}
func guestOriginalSourceInstallationState(ctx context.Context, slot int, state string) error {
	_, err := productionGuestSource(ctx)
	return err
}
