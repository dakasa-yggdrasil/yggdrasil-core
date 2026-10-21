//go:build linux && nativequalification

package message

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func guestOriginalSourceConfirmationProof(ctx context.Context, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt, original model.CapacityMutationProof) (model.CapacityMutationProof, error) {
	if originalGuestNativeRealm == nil || ctx.Err() != nil {
		return model.CapacityMutationProof{}, errOriginalGuestStep
	}
	// The fixed historical corpus intentionally ages the original proof and
	// obtains its own real read only after the original lease has expired.
	if capacitynativeqemu.SourceHistoricalConfirmCase(originalGuestNativeRealm.Request.NativeCase) {
		return original, nil
	}
	return originalGuestNativeRealm.RefreshEnrollmentProof(ctx, grant, pre, receipt, original)
}
