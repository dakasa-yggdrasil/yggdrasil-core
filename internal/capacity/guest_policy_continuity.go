package capacity

import (
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// GuestPolicyContinuitySHA256 is the digest of everything an installed Guest
// member was enrolled against (ADR-0094). Two capacity_policy versions with the
// same digest give an installed member the same Guest production contract:
// the same GuestProductionProfileContractSHA256 (complete Guest retirement
// binding, mutation binding with its slots, desired specs and bootstrap
// digests, and Notify canary binding), the same protocol authority source,
// and the same provider, profile, region, environment, domain, dimension and
// workflow selector. Signals, hysteresis, min_samples, observation adapters,
// thresholds, quotes and floor are deliberately outside it: they decide WHEN
// Core scales, not WHICH Guest it may manage.
//
// It returns "" (never continuous) for anything that is not a complete
// production Guest contract with exactly one matching profile.
func GuestPolicyContinuitySHA256(p model.CapacityPolicySpec) string {
	if p.GuestRetirementBinding == nil {
		return ""
	}
	binding := *p.GuestRetirementBinding
	var profile model.CapacityProfile
	matches := 0
	for _, candidate := range p.Profiles {
		if candidate.Name == binding.ProfileManifest.Profile {
			profile = candidate
			matches++
		}
	}
	if matches != 1 || profile.Provider == "" {
		return ""
	}
	contract := GuestProductionProfileContractSHA256(p, binding, profile.Provider)
	if !ValidDigest(contract) {
		return ""
	}
	return GuestRetirementSHA(struct {
		Schema                    string                 `json:"schema"`
		ContractSHA256            string                 `json:"contract_sha256"`
		CoreAuthoritySourceCommit string                 `json:"core_authority_source_commit"`
		Provider                  string                 `json:"provider"`
		Profile                   string                 `json:"profile"`
		Region                    string                 `json:"region"`
		Environment               string                 `json:"environment"`
		Domain                    string                 `json:"domain"`
		Dimension                 string                 `json:"dimension"`
		Workflow                  model.ManifestSelector `json:"workflow"`
	}{"guest_policy_continuity_v1", contract, binding.CoreAuthoritySourceCommit, profile.Provider, profile.Name, profile.Region, p.Environment, p.Domain, p.Dimension, p.Workflow})
}

// GuestPolicyContinuous reports whether an installed member enrolled under
// the prior policy spec stays manageable under the current one. Both must be
// complete production contracts with the same continuity digest and the
// byte-identical Guest retirement and Notify canary bindings.
func GuestPolicyContinuous(prior, current model.CapacityPolicySpec) bool {
	digest := GuestPolicyContinuitySHA256(current)
	if !ValidDigest(digest) || GuestPolicyContinuitySHA256(prior) != digest || prior.GuestRetirementBinding == nil || current.GuestRetirementBinding == nil {
		return false
	}
	return reflect.DeepEqual(*prior.GuestRetirementBinding, *current.GuestRetirementBinding) && reflect.DeepEqual(prior.GuestNotifyCanaryBinding, current.GuestNotifyCanaryBinding)
}
