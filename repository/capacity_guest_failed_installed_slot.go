package repository

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// A disposal selects the one newly installed tail member, never an arbitrary
// survivor. Historical first-member records have no separate slot field.
// The admission joins this value to the immutable preregistration and tuple.
func failedInstalledDisposalSlot(r FailedInstalledGuestDisposal) int {
	return max(1, r.OriginalIntent.Decision.Units)
}

// Claim replaces the original baseline with the observed pre-retirement fleet.
// The plan receives this server-owned claim; it never accepts a caller's slot.
func FailedInstalledDisposalClaimSlot(current model.CapacityIntent) int {
	return max(1, current.BaselineSnapshot.Units)
}

func failedInstalledDisposalTargetUnits(slot int) int {
	// The original first-member protocol retains its historical drain target;
	// an expansion disposal retains every member preceding its failed tail.
	return max(1, slot-1)
}

func failedInstalledDisposalMembersMatch(r FailedInstalledGuestDisposal, members []GuestNotifyFloorMember) bool {
	target := failedInstalledDisposalSlot(r)
	if len(members) != target {
		return false
	}
	seen := make(map[int]bool, target)
	for _, member := range members {
		if member.Slot < 1 || member.Slot > target || seen[member.Slot] || member.PreregistrationID == "" || (member.Slot == target) != (member.PreregistrationID == r.PreregistrationID) {
			return false
		}
		seen[member.Slot] = true
	}
	return true
}
