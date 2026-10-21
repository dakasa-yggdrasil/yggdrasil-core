//go:build !nativequalification

package message

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Production cannot install the qualification source or synthesize its read.
func guestOriginalSourceConfirmationProof(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityMutationProof) (model.CapacityMutationProof, error) {
	return model.CapacityMutationProof{}, errOriginalGuestStep
}
