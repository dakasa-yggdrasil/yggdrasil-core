//go:build nativequalification

package capacityqualification

import (
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// OriginalReadMutationBinding resolves a previously validated preregistration's
// member name through the current Guest binding to the mutation binding. The
// names have distinct meanings and must never be used interchangeably.
func OriginalReadMutationBinding(policy model.CapacityPolicySpec, pre model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationBinding, error) {
	guest := policy.GuestRetirementBinding
	if guest == nil || pre.BindingName == "" || pre.Slot < 1 || guest.MutationBindingName == "" {
		return model.CapacityMutationBinding{}, errors.New("original read binding unavailable")
	}
	matches := 0
	for _, member := range guest.Members {
		if member.Name == pre.BindingName || member.Slot == pre.Slot {
			if member.Name != pre.BindingName || member.Slot != pre.Slot {
				return model.CapacityMutationBinding{}, errors.New("original read member mismatch")
			}
			matches++
		}
	}
	if matches != 1 {
		return model.CapacityMutationBinding{}, errors.New("original read member mismatch")
	}
	bindings := 0
	for _, binding := range policy.MutationBindings {
		if binding.Name == guest.MutationBindingName {
			bindings++
		}
	}
	if bindings != 1 {
		return model.CapacityMutationBinding{}, errors.New("original read mutation binding mismatch")
	}
	return capacity.VMObservationBinding(policy, guest.MutationBindingName)
}
