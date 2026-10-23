//go:build !nativequalification

package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// Exact original Notify catalogs and complete protected contracts assembled
// from the reviewed public native returns. Current Core source is separately
// checked; approval alone supplies no lease, useful membership or provider grant.
// Qualification and synthetic profiles remain excluded.
var guestProductionProfileApprovals = []guestProductionProfileApproval{
	{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "94b17d651954742383839e8184c342b4d11fff326576b55d4a4b73474ed84086"},
	{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "fd9d4c511230e041955aa4da4a6626d5aee4e236664eabfdcb024660dc095a2e"},
}

func guestOriginalProductionProfileEnabled(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, provider string) bool {
	return guestProductionProfileMatches(p, binding, provider, CurrentGuestCoreSource(), guestProductionProfileApprovals)
}
