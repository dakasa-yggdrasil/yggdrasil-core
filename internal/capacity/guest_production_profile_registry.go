package capacity

import (
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// A source approval binds the complete protected profile, exact native adapter
// and slot contracts, public identities and private reference names. It contains
// no private credential values and is never read from a manifest or environment.
type guestProductionProfileApproval struct {
	Provider                string
	Profile                 string
	ProductionCatalogSHA256 string
	ContractSHA256          string
}

// GuestProductionProfileContractSHA256 is a reproducible source-review digest,
// not approval. The current Core build identity is checked independently because
// a source commit cannot contain its own future Git SHA. Every other binding
// field, including keys, transport references and member principals, is pinned.
func GuestProductionProfileContractSHA256(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, provider string) string {
	if provider == "" || provider == "native-qemu" || binding.EvidenceClass != "owned_provisioner_original" || binding.ProfileManifest.CoverageClass != "complete_production_roster" || ValidateGuestRetirementBinding(p, &binding) != nil || p.GuestRetirementBinding == nil || !reflect.DeepEqual(*p.GuestRetirementBinding, binding) {
		return ""
	}
	bindingMatches := 0
	for _, candidate := range p.MutationBindings {
		if candidate.Name == binding.MutationBindingName {
			bindingMatches++
		}
	}
	if bindingMatches != 1 {
		return ""
	}
	mutation, err := VMObservationBinding(p, binding.MutationBindingName)
	if err != nil {
		return ""
	}
	if provider == "hetzner" && !businessSource.MatchString(mutation.OriginalProviderSourceCommit) {
		return ""
	}
	matches := 0
	for _, profile := range p.Profiles {
		if profile.Name == binding.ProfileManifest.Profile {
			if profile.Provider != provider {
				return ""
			}
			matches++
		}
	}
	if matches != 1 {
		return ""
	}
	binding.CoreAuthoritySourceCommit = ""
	return GuestRetirementSHA(struct {
		Provider        string                               `json:"provider"`
		GuestBinding    model.CapacityGuestRetirementBinding `json:"guest_binding"`
		MutationBinding model.CapacityMutationBinding        `json:"mutation_binding"`
	}{provider, binding, mutation})
}

func guestProductionProfileMatches(p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, provider, currentCoreSource string, approvals []guestProductionProfileApproval) bool {
	if !businessSource.MatchString(currentCoreSource) || binding.CoreAuthoritySourceCommit != currentCoreSource {
		return false
	}
	contract := GuestProductionProfileContractSHA256(p, binding, provider)
	if !ValidDigest(contract) {
		return false
	}
	matches := 0
	for _, approved := range approvals {
		if approved.Provider == provider && approved.Profile == binding.ProfileManifest.Profile && ValidDigest(approved.ProductionCatalogSHA256) && approved.ProductionCatalogSHA256 == binding.ProfileManifest.ProductionCatalogSHA256 && ValidDigest(approved.ContractSHA256) && approved.ContractSHA256 == contract {
			matches++
		}
	}
	// Duplicate approvals are a source configuration error, never two votes.
	return matches == 1
}
