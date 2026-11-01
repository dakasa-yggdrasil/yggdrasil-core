//go:build labqualification && !nativequalification

package capacity

// LAB approvals must be explicitly source-reviewed and describe only isolated
// resources. These are the two exact, source-reviewed isolated LAB contracts.
var guestLabProfileApprovals = []guestProductionProfileApproval{
	{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "5152138aa51bd49aa58da783874216a9780c2904e2c4cc6af71fabff72eef79f"},
	{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "bbc0a48df4b89de1102c63ed1b85f714015d7e2e7dcf0bd307dd7e49dbb1a757"},
}

const guestOriginalExecutionClass = "lab_registry_unqualified_hold"
const guestHistoricalProductionApprovalsEnabled = false

func activeGuestProfileApprovals() []guestProductionProfileApproval {
	return guestLabProfileApprovals
}
