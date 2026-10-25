//go:build !nativequalification

package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// Exact original Notify catalogs and complete protected contracts assembled
// from the reviewed public native returns. Current Core source is separately
// checked; approval alone supplies no lease, useful membership or provider grant.
// Qualification and synthetic profiles remain excluded.

func guestOriginalProductionProfileEnabled(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, provider string) bool {
	return guestProductionProfileMatches(p, binding, provider, CurrentGuestCoreSource(), guestProductionProfileApprovals)
}
