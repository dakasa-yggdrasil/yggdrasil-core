//go:build !nativequalification

package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// Exact original Notify catalogs and complete protected contracts assembled
// from the reviewed public native returns. Current Core source is separately
// checked; approval alone supplies no lease, useful membership or provider grant.
// Qualification and synthetic profiles remain excluded.
var guestProductionProfileApprovals = []guestProductionProfileApproval{
	{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "d7edd5c50df10c21f93c3024d0d95a5e6c5b24d5a3ae339d7a833f3c0f47eacb"},
	{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "c01b8969fb8ac4fbacf373275973df3d9b0caa8d5b1391b192e23e2715560921"},
}

func guestOriginalProductionProfileEnabled(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, provider string) bool {
	return guestProductionProfileMatches(p, binding, provider, CurrentGuestCoreSource(), guestProductionProfileApprovals)
}
