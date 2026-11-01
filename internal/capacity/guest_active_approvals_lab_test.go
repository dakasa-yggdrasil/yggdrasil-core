//go:build labqualification && !nativequalification

package capacity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestLabRegistryRejectsProductionProfilesAndHistoricalAuthority(t *testing.T) {
	if len(activeGuestProfileApprovals()) != 2 || guestHistoricalProductionApprovalsEnabled {
		t.Fatal("LAB must expose only its two reviewed approvals and no historical authority")
	}
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/original-notify-" + provider + "-production-contract.json")
			if err != nil {
				t.Fatal(err)
			}
			var policy model.CapacityPolicySpec
			if err := json.Unmarshal(raw, &policy); err != nil || policy.GuestRetirementBinding == nil {
				t.Fatal("production fixture must contain its original binding")
			}
			binding := *policy.GuestRetirementBinding
			if GuestOriginalProfileEnabled(policy, binding, provider) || GuestBindingAuthorityCurrent(policy, binding) {
				t.Fatal("LAB admitted a production profile")
			}
			for _, oldMap := range []string{GuestD12ProtocolCompatibilityMapSHA256, GuestD15ProtocolCompatibilityMapSHA256} {
				if GuestBindingApprovedByCompatibilityMap(policy, binding, strings.Repeat("a", 40), oldMap) {
					t.Fatal("LAB admitted a historical production compatibility map")
				}
			}
			if guestProtocolAuthoritySupported(GuestD11ProtocolAuthority, strings.Repeat("a", 40), provider, binding.ProfileManifest.Profile) {
				t.Fatal("LAB admitted an older production authority")
			}
		})
	}
	current := strings.Repeat("a", 40)
	if !guestProtocolAuthoritySupported(current, current, "aws", "notify-aws-elastic") {
		t.Fatal("the current LAB issuer must remain eligible for exact LAB approvals")
	}
	if GuestProtocolCompatibilityMapSHA256() == GuestD12ProtocolCompatibilityMapSHA256 || GuestProtocolCompatibilityMapSHA256() == GuestD15ProtocolCompatibilityMapSHA256 {
		t.Fatal("LAB map must not equal a production history map")
	}
}

func TestLabRegistryRequiresExactReviewedContractAndCurrentIssuer(t *testing.T) {
	raw, err := os.ReadFile("testdata/original-notify-aws-production-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy model.CapacityPolicySpec
	if err := json.Unmarshal(raw, &policy); err != nil || policy.GuestRetirementBinding == nil {
		t.Fatal("fixture must contain its original binding")
	}
	// This is only a shape operand for the matcher; it is never installed or
	// used as a provider configuration.
	issuer := strings.Repeat("a", 40)
	policy.GuestRetirementBinding.CoreAuthoritySourceCommit = issuer
	policy.GuestRetirementBinding.IntentSigningKeyRef = "secret://isolated-lab/test-intent#value"
	binding := *policy.GuestRetirementBinding
	contract := GuestProductionProfileContractSHA256(policy, binding, "aws")
	if !ValidDigest(contract) {
		t.Fatal("complete test contract required")
	}
	approvals := []guestProductionProfileApproval{{Provider: "aws", Profile: binding.ProfileManifest.Profile, ProductionCatalogSHA256: binding.ProfileManifest.ProductionCatalogSHA256, ContractSHA256: contract}}
	mapSHA := guestProtocolCompatibilityMapSHA256(approvals)
	if !guestBindingApprovedByCompatibilityMap(policy, binding, issuer, mapSHA, approvals) {
		t.Fatal("exact test approval and current issuer were refused")
	}
	if guestBindingApprovedByCompatibilityMap(policy, binding, strings.Repeat("b", 40), mapSHA, approvals) {
		t.Fatal("foreign issuer was accepted")
	}
	policy.GuestRetirementBinding.IntentSigningKeyRef = "secret://isolated-lab/other-intent#value"
	if guestBindingApprovedByCompatibilityMap(policy, *policy.GuestRetirementBinding, issuer, mapSHA, approvals) {
		t.Fatal("changed contract was accepted")
	}
}
