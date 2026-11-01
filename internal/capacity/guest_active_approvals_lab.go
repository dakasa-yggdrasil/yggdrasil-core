//go:build labqualification && !nativequalification

package capacity

// LAB approvals must be explicitly source-reviewed and describe only isolated
// resources. An empty list deliberately admits no provider profile.
var guestLabProfileApprovals = []guestProductionProfileApproval{}

const guestOriginalExecutionClass = "lab_registry_unqualified_hold"
const guestHistoricalProductionApprovalsEnabled = false

func activeGuestProfileApprovals() []guestProductionProfileApproval {
	return guestLabProfileApprovals
}
