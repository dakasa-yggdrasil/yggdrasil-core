//go:build linux && nativequalification

package message

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func guestOriginalSourceConfirmationProof(ctx context.Context, store repository.CapacityStore, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt, original model.CapacityMutationProof) (model.CapacityMutationProof, error) {
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return model.CapacityMutationProof{}, errOriginalGuestStep
	}
	// The fixed historical corpus intentionally ages the original proof and
	// obtains its own real read only after the original lease has expired.
	if capacitynativeqemu.SourceHistoricalConfirmCase(originalGuestNativeRealm.Request.NativeCase) {
		return original, nil
	}
	return originalGuestNativeRealm.RefreshEnrollmentProof(ctx, grant, pre, receipt, original, func(read context.Context, confirmed model.CapacityMutationProof, wire []byte) error {
		return store.RecordCanonicalPostlossConfirmation(read, pre.PreregistrationID, confirmed, wire)
	})
}

// Only the fixed postloss and failed-create compensation slots remain
// pending: source cleanup never treats a confirmed member as a failed creation.
// The baseline and all ordinary source/production paths retain confirmation.
func guestOriginalSourcePendingPostloss(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, input guestOriginalStepInput, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, proof model.CapacityMutationProof) (bool, error) {
	if originalGuestNativeRealm == nil {
		return false, errOriginalGuestStep
	}
	nativeCase := originalGuestNativeRealm.Request.NativeCase
	postloss := capacitynativeqemu.PostlossSourceCase(nativeCase)
	if !(postloss || capacitynativeqemu.CanonicalCompensationPendingCase(nativeCase)) || input.Slot != capacitynativeqemu.SourceFailureSlot(nativeCase) {
		return false, nil
	}
	if input.Slot != grant.Slot || grant.Slot != pre.Slot || pre.OriginalCreateGrantID != grant.GrantID || pre.Generation != input.Generation || pre.Fence != input.FencingToken || pre.LeaseOwner != input.LeaseOwner || pre.ExecutorID != store.ExecutorID || ctx.Err() != nil {
		return true, errOriginalGuestStep
	}
	if !postloss {
		return true, store.VerifyCanonicalCompensationPending(ctx, policy, p, nativeCase, grant, proof)
	}
	return true, store.VerifyCanonicalPostlossPending(ctx, policy, p, nativeCase, grant, proof)
}

func guestOriginalSourcePendingEnrollment(ctx context.Context, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt) error {
	if originalGuestNativeRealm == nil {
		return errOriginalGuestStep
	}
	return originalGuestNativeRealm.EnrolledPending(ctx, grant, pre, receipt)
}
