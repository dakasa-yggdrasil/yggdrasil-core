package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// Select only immutable source-owned user-data for the actual slot. An invalid
// map never falls back to the legacy shared template. No key bytes live here.
func GuestProfileBootstrapSHA(profile model.CapacityGuestProtectedProfileManifest, slot int) string {
	if slot < 1 || slot > 64 {
		return ""
	}
	if profile.SlotBootstraps == nil {
		if ValidDigest(profile.BootstrapSHA256) {
			return profile.BootstrapSHA256
		}
		return ""
	}
	if profile.BootstrapSHA256 != "" || len(profile.SlotBootstraps) < 1 || len(profile.SlotBootstraps) > 64 {
		return ""
	}
	previous, selected := 0, ""
	seen := map[string]bool{}
	for _, entry := range profile.SlotBootstraps {
		if entry.Slot <= previous || entry.Slot > 64 || !ValidDigest(entry.BootstrapSHA256) || seen[entry.BootstrapSHA256] {
			return ""
		}
		if entry.Slot == slot {
			selected = entry.BootstrapSHA256
		}
		previous = entry.Slot
		seen[entry.BootstrapSHA256] = true
	}
	return selected
}

func guestProfileBootstrapsCover(profile model.CapacityGuestProtectedProfileManifest, members []model.CapacityGuestRetirementMemberBinding, class string) bool {
	if profile.SlotBootstraps == nil {
		return ValidDigest(profile.BootstrapSHA256)
	}
	if class != "owned_provisioner_original" || len(profile.SlotBootstraps) != len(members) {
		return false
	}
	for index, member := range members {
		if profile.SlotBootstraps[index].Slot != member.Slot || !ValidDigest(GuestProfileBootstrapSHA(profile, member.Slot)) {
			return false
		}
	}
	return true
}
