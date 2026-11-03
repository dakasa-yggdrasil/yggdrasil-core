package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// GuestD11ProtocolAuthority is the signed Guest-v1 contract revision, not the
// Git revision of the current issuer. CurrentGuestCoreSource always reports the
// real clean build. The published release declares support for this exact map.
const GuestD11ProtocolAuthority = "48888f21acdddaf411094ec525004297c229863f"

// GuestD12ProtocolCompatibilityMapSHA256 identifies the original two-contract
// map. Its immutable snapshot may verify old issues, never a new contract.
const GuestD12ProtocolCompatibilityMapSHA256 = "557b50ee2b03b5d3425ce2ce958538dc602fb4339f853e65139949626058116c"

var guestD12ProtocolProfileApprovals = []guestProductionProfileApproval{
	{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "76c468b890f07284b1205b87bf97833764d7de2a4fe7a62bf03e26cb49c9e281"},
	{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "fd9d4c511230e041955aa4da4a6626d5aee4e236664eabfdcb024660dc095a2e"},
}

const GuestD15ProtocolCompatibilityMapSHA256 = "b5a496bb19f332a82387af7af85b75c9c738f17a139d23665de4548b89c199cd"

var guestD15ProtocolProfileApprovals = append(
	append([]guestProductionProfileApproval(nil), guestD12ProtocolProfileApprovals...),
	guestProductionProfileApproval{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "97beb27b884fcf3928f2da6f14d8840ba0fb6f460012fdb50b8ab02b01334df7"},
	guestProductionProfileApproval{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "3fcb7fc4634fc5102d2172cc1d7f66bd92a61b9d544525a3438e8cdf914803f9"},
)

var guestProductionProfileApprovals = append(
	append([]guestProductionProfileApproval(nil), guestD15ProtocolProfileApprovals...),
	guestProductionProfileApproval{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "d81b2f6bfd4100f8e31a465efc49a1a0698f39a1df1372e2b4af2c12957c1602"},
	guestProductionProfileApproval{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "e9e6745ef3e0ef627bbe2080f196ed55b6037b42839ddf99bd0fbf353b386c9d"},
)

func guestProtocolAuthoritySupported(authority, actualBuild, provider, profile string) bool {
	if !businessSource.MatchString(actualBuild) || !businessSource.MatchString(authority) {
		return false
	}
	if authority == actualBuild {
		return true
	}
	return authority == GuestD11ProtocolAuthority && ((provider == "aws" && profile == "notify-aws-elastic") || (provider == "hetzner" && profile == "notify-hetzner-elastic"))
}

// GuestProtocolCompatibilityMapSHA256 identifies only the compiled production
// contracts. It contains neither a self-referential build hash nor credentials.
func GuestProtocolCompatibilityMapSHA256() string {
	return guestProtocolCompatibilityMapSHA256(guestProductionProfileApprovals)
}

func guestProtocolCompatibilityMapSHA256(approvals []guestProductionProfileApproval) string {
	return GuestRetirementSHA(struct {
		Schema    string                           `json:"schema"`
		Authority string                           `json:"protocol_authority_source_commit"`
		Profiles  []guestProductionProfileApproval `json:"profiles"`
	}{"guest_protocol_authority_compatibility_v1", GuestD11ProtocolAuthority, approvals})
}

// GuestBindingApprovedByCompatibilityMap verifies historical issuer provenance
// against that exact map's complete contracts. It does not issue new authority;
// issuance independently requires the current build and current approvals.
func GuestBindingApprovedByCompatibilityMap(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, actualIssuer, compatibilityMap string) bool {
	return guestBindingApprovedByCompatibilityMap(p, binding, actualIssuer, compatibilityMap, guestProductionProfileApprovals)
}

func guestBindingApprovedByCompatibilityMap(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, actualIssuer, compatibilityMap string, currentApprovals []guestProductionProfileApproval) bool {
	approvals := currentApprovals
	if compatibilityMap == GuestD12ProtocolCompatibilityMapSHA256 {
		if guestProtocolCompatibilityMapSHA256(guestD12ProtocolProfileApprovals) != GuestD12ProtocolCompatibilityMapSHA256 {
			return false
		}
		approvals = guestD12ProtocolProfileApprovals
	} else if compatibilityMap == GuestD15ProtocolCompatibilityMapSHA256 {
		if guestProtocolCompatibilityMapSHA256(guestD15ProtocolProfileApprovals) != GuestD15ProtocolCompatibilityMapSHA256 {
			return false
		}
		approvals = guestD15ProtocolProfileApprovals
	} else if compatibilityMap != guestProtocolCompatibilityMapSHA256(currentApprovals) {
		return false
	}
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == binding.ProfileManifest.Profile {
			if provider != "" {
				return false
			}
			provider = profile.Provider
		}
	}
	return provider != "" && guestProductionProfileMatches(p, binding, provider, actualIssuer, approvals)
}

// GuestBindingAuthorityCurrent keeps every complete profile/catalog/key/ref
// approval. A caller cannot admit another authority by supplying an old hash.
func GuestBindingAuthorityCurrent(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding) bool {
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == binding.ProfileManifest.Profile {
			if provider != "" {
				return false
			}
			provider = profile.Provider
		}
	}
	return provider != "" && GuestOriginalProfileEnabled(p, binding, provider)
}
