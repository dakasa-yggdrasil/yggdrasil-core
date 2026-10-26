//go:build !nativequalification

package capacity

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These fixtures are the exact canonical policies from the two original owning
// Go full_policy results. Their approvals contain no future source identity.
func TestGuestActualB509ProfileApprovals(t *testing.T) {
	expected := map[string]struct{ catalog, contract, instance string }{
		"aws":     {"8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", "d81b2f6bfd4100f8e31a465efc49a1a0698f39a1df1372e2b4af2c12957c1602", "143beb1c-ed53-4027-b11d-dcc49b35f571"},
		"hetzner": {"6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", "e9e6745ef3e0ef627bbe2080f196ed55b6037b42839ddf99bd0fbf353b386c9d", "7300c345-bfeb-41a8-9601-d6ae69a223b0"},
	}
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/b509-notify-" + provider + "-production-contract.json")
			if err != nil {
				t.Fatal(err)
			}
			var p model.CapacityPolicySpec
			if DecodeNativeCapacity(json.RawMessage(raw), &p) != nil {
				t.Fatal("actual B509 full typed fixture")
			}
			b := p.GuestRetirementBinding
			if b == nil || p.ExecutionEnabled || len(p.MutationBindings) != 1 || p.MutationBindings[0].IntegrationInstanceID != expected[provider].instance || b.GuestSourceCommit != "b50976579e128e9a418ae5209d2b2dfea0fc532b" || b.ProvisionerSourceCommit != b.GuestSourceCommit || b.ProfileManifest.ActorSourceCommit != b.GuestSourceCommit || b.ProfileManifest.OwnerSourceCommit != b.GuestSourceCommit || b.CoreAuthoritySourceCommit != GuestD11ProtocolAuthority || b.ProfileManifest.OwnerImageDigest != "sha256:120a7f2355758cd119386e8ddd1e6c07bc6570aab640cc11bb84793c8e339967" || b.ProfileManifest.ProductionCatalogSHA256 != expected[provider].catalog || GuestProductionProfileContractSHA256(p, *b, provider) != expected[provider].contract {
				t.Fatal("actual B509 contract, source, image or instance binding changed")
			}
			// This is the real prior Core issuer as a pure verification operand;
			// the test does not claim a future Core build or runtime activation.
			issuer := "8c69fa23debd0a665d5276cca41810345f399f14"
			for _, tc := range []struct {
				name, fingerprint string
				accepted          bool
			}{
				{"current_six_contracts", GuestProtocolCompatibilityMapSHA256(), true},
				{"historical_D15_four_cannot_approve_B509", GuestD15ProtocolCompatibilityMapSHA256, false},
				{"historical_D12_two_cannot_approve_B509", GuestD12ProtocolCompatibilityMapSHA256, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if GuestBindingApprovedByCompatibilityMap(p, *b, issuer, tc.fingerprint) != tc.accepted {
						t.Fatal("B509 approval escaped its exact current compatibility map")
					}
				})
			}
		})
	}
}
