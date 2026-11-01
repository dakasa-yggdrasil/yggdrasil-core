//go:build labqualification && !nativequalification

package capacity

// LAB approvals must be explicitly source-reviewed and describe only isolated
// resources. These are the two exact, source-reviewed isolated LAB contracts.
var guestLabProfileApprovals = []guestProductionProfileApproval{
	{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "50f025772698aa652e5a28c6238c58f46024575ec2e1f77684b65a867cae2666"},
	{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "7ea62af7f6fd6e6f7ad90a6e8bd1943ede01bc8e0b8f3b6315372744f9a51e57"},
}

const guestOriginalExecutionClass = "lab_registry_unqualified_hold"
const guestHistoricalProductionApprovalsEnabled = false

func activeGuestProfileApprovals() []guestProductionProfileApproval {
	return guestLabProfileApprovals
}
