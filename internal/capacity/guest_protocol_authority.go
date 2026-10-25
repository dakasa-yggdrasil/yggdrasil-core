package capacity

import "github.com/dakasa-yggdrasil/yggdrasil-core/model"

// GuestD11ProtocolAuthority is the signed Guest-v1 contract revision, not the
// Git revision of the current issuer. CurrentGuestCoreSource always reports the
// real clean build. The published release declares support for this exact map.
const GuestD11ProtocolAuthority = "48888f21acdddaf411094ec525004297c229863f"

var guestProductionProfileApprovals = []guestProductionProfileApproval{
	{Provider: "aws", Profile: "notify-aws-elastic", ProductionCatalogSHA256: "8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", ContractSHA256: "76c468b890f07284b1205b87bf97833764d7de2a4fe7a62bf03e26cb49c9e281"},
	{Provider: "hetzner", Profile: "notify-hetzner-elastic", ProductionCatalogSHA256: "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", ContractSHA256: "fd9d4c511230e041955aa4da4a6626d5aee4e236664eabfdcb024660dc095a2e"},
}

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
	return GuestRetirementSHA(struct {
		Schema    string                           `json:"schema"`
		Authority string                           `json:"protocol_authority_source_commit"`
		Profiles  []guestProductionProfileApproval `json:"profiles"`
	}{"guest_protocol_authority_compatibility_v1", GuestD11ProtocolAuthority, guestProductionProfileApprovals})
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
