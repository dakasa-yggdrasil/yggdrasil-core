//go:build !labqualification

package capacity

const guestHistoricalProductionApprovalsEnabled = true

func activeGuestProfileApprovals() []guestProductionProfileApproval {
	return guestProductionProfileApprovals
}
