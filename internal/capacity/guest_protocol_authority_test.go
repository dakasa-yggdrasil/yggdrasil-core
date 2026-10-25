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
