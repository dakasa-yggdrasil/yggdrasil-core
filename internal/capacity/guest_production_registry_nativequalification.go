//go:build nativequalification

package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

func guestOriginalProductionProfileEnabled(model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, string) bool {
	return false
}
