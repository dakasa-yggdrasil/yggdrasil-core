//go:build !nativequalification

package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// Populate only from an independently reviewed actual production catalog and
// profile contract. An empty registry continues to refuse before provider send.
// Qualification results and synthetic unit entries cannot populate this slice.
var guestProductionProfileApprovals = []guestProductionProfileApproval{}

func guestOriginalProductionProfileEnabled(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, provider string) bool {
	return guestProductionProfileMatches(p, binding, provider, CurrentGuestCoreSource(), guestProductionProfileApprovals)
}
