//go:build !nativequalification

package capacity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestProtocolAuthorityCompatibilityKeepsCompleteCanonicalApproval(t *testing.T) {
	t.Run("historical_map_contract_scope", testGuestHistoricalCompatibilityMapContracts)
	t.Run("actual_a900_profile_approvals", testGuestActualA900ProfileApprovals)
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/original-notify-" + provider + "-production-contract.json")
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"reviewed_successor", "unknown_build", "foreign_authority", "changed_key_ref", "changed_member_origin", "changed_catalog", "changed_recipient", "cross_provider"} {
				t.Run(name, func(t *testing.T) {
					var p model.CapacityPolicySpec
					if DecodeNativeCapacity(json.RawMessage(raw), &p) != nil {
						t.Fatal("fixture")
					}
					b := p.GuestRetirementBinding
					b.CoreAuthoritySourceCommit = GuestD11ProtocolAuthority
					actual := strings.Repeat("a", 40)
					selected := provider
					switch name {
					case "unknown_build":
						actual = ""
					case "foreign_authority":
						b.CoreAuthoritySourceCommit = strings.Repeat("b", 40)
					case "changed_key_ref":
						b.IntentSigningKeyRef = "secret://foreign/key#value"
					case "changed_member_origin":
						b.Members[0].Origin = "https://foreign.invalid:9447"
					case "changed_catalog":
						b.ProfileManifest.ProductionCatalogSHA256 = strings.Repeat("c", 64)
					case "changed_recipient":
						p.GuestNotifyCanaryBinding.RecipientSHA256 = strings.Repeat("d", 64)
					case "cross_provider":
						selected = map[string]string{"aws": "hetzner", "hetzner": "aws"}[provider]
					}
					before := b.CoreAuthoritySourceCommit
					if guestProductionProfileMatches(p, *b, selected, actual, guestProductionProfileApprovals) != (name == "reviewed_successor") {
						t.Fatal("compatibility weakened full original approval or refused exact successor")
					}
					if actual == GuestD11ProtocolAuthority || b.CoreAuthoritySourceCommit != before {
						t.Fatal("actual build substituted or authority rewritten")
					}
				})
			}
		})
	}
	if !ValidDigest(GuestProtocolCompatibilityMapSHA256()) {
		t.Fatal("compiled compatibility identity missing")
	}
}

func testGuestHistoricalCompatibilityMapContracts(t *testing.T) {
	if guestProtocolCompatibilityMapSHA256(guestD12ProtocolProfileApprovals) != GuestD12ProtocolCompatibilityMapSHA256 {
		t.Fatal("original two-contract compatibility map changed")
	}
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/original-notify-" + provider + "-production-contract.json")
			if err != nil {
				t.Fatal(err)
			}
			var old, successor model.CapacityPolicySpec
			if DecodeNativeCapacity(json.RawMessage(raw), &old) != nil || DecodeNativeCapacity(json.RawMessage(raw), &successor) != nil {
				t.Fatal("original complete contract fixture")
			}
			old.GuestRetirementBinding.CoreAuthoritySourceCommit = GuestD11ProtocolAuthority
			successor.GuestRetirementBinding.CoreAuthoritySourceCommit = GuestD11ProtocolAuthority
			// Only a pure test operand: never install a synthetic successor in
			// the compiled production approvals or claim a future Guest artifact.
			successor.GuestRetirementBinding.IntentSigningKeyRef = "secret://source-test/successor-intent#value"
			contract := GuestProductionProfileContractSHA256(successor, *successor.GuestRetirementBinding, provider)
			if !ValidDigest(contract) || contract == GuestProductionProfileContractSHA256(old, *old.GuestRetirementBinding, provider) {
				t.Fatal("distinct complete synthetic successor contract required")
			}
			approvals := append([]guestProductionProfileApproval(nil), guestD12ProtocolProfileApprovals...)
			approvals = append(approvals, guestProductionProfileApproval{provider, successor.GuestRetirementBinding.ProfileManifest.Profile, successor.GuestRetirementBinding.ProfileManifest.ProductionCatalogSHA256, contract})
			currentMap := guestProtocolCompatibilityMapSHA256(approvals)
			if currentMap == GuestD12ProtocolCompatibilityMapSHA256 {
				t.Fatal("adding a distinct contract did not change map identity")
			}
			for _, tc := range []struct {
				name, fingerprint, issuer string
				policy                    model.CapacityPolicySpec
				accepted                  bool
			}{
				{"old_contract_original_map", GuestD12ProtocolCompatibilityMapSHA256, strings.Repeat("a", 40), old, true},
				{"old_contract_expanded_map", currentMap, strings.Repeat("a", 40), old, true},
				{"new_contract_expanded_map", currentMap, strings.Repeat("a", 40), successor, true},
				{"old_map_cannot_approve_new_contract_same_profile_and_catalog", GuestD12ProtocolCompatibilityMapSHA256, strings.Repeat("a", 40), successor, false},
				{"unknown_map", strings.Repeat("f", 64), strings.Repeat("a", 40), old, false},
				{"missing_issuer", GuestD12ProtocolCompatibilityMapSHA256, "", old, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if guestBindingApprovedByCompatibilityMap(tc.policy, *tc.policy.GuestRetirementBinding, tc.issuer, tc.fingerprint, approvals) != tc.accepted {
						t.Fatal("historical compatibility map accepted another contract or refused its exact original")
					}
				})
			}
		})
	}
}
