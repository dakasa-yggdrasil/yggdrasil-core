//go:build !nativequalification

package message

import (
	"context"
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// A confirmation always performs another native read of the same original
// durable settlement. Installation never turns an old proof into a fresh one.
func guestOriginalSourceConfirmationProof(ctx context.Context, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, r model.CapacityGuestOriginalProvisioningReceipt, original model.CapacityMutationProof) (model.CapacityMutationProof, error) {
	source, err := productionGuestSource(ctx)
	if err != nil || !source.installed || !reflect.DeepEqual(source.grant, g) || !reflect.DeepEqual(source.pre, pre) || !reflect.DeepEqual(source.receipt, r) || !reflect.DeepEqual(source.supplier.createdProof, original) {
		return model.CapacityMutationProof{}, errOriginalGuestStep
	}
	return source.owner.Read(ctx, g)
}
