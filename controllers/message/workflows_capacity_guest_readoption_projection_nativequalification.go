//go:build linux && nativequalification

package message

import (
	"encoding/json"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Match the original preregistration to the approved canonical create plan.
// The raw struct encoding is still passed to RecordMutationSlot, which binds
// it through the same plan validation; it is not itself the authority hash.
func sourceNativeReadoptionDesired(p model.CapacityPolicySpec, b model.CapacityMutationBinding, original model.CapacityMutationProof) ([]byte, error) {
	var desired []byte
	for _, slot := range b.Slots {
		if slot.Slot == 2 && slot.DesiredSpec != nil {
			var err error
			desired, err = json.Marshal(slot.DesiredSpec)
			if err != nil {
				return nil, errOriginalGuestStep
			}
		}
	}
	if len(desired) == 0 || original.BindingName != b.Name || original.Slot != 2 {
		return nil, errOriginalGuestStep
	}
	plan, err := capacity.PrepareMutationPlan(p, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: desired})
	if err != nil || plan.Slot != 2 || plan.Capability != b.EnsureCapability || original.RequestSHA256 != plan.RequestSHA256 {
		return nil, errOriginalGuestStep
	}
	return desired, nil
}
