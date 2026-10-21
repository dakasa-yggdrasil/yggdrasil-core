//go:build !nativequalification

package capacity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Actual public profile contracts, not private material or a native positive.
// Source matching is checked explicitly; no current runtime authority is minted.
func TestOriginalGuestProductionApprovalsBindActualContracts(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/original-notify-" + provider + "-production-contract.json")
			if err != nil {
				t.Fatal(err)
			}
			read := func() model.CapacityPolicySpec {
				t.Helper()
				var p model.CapacityPolicySpec
				if DecodeNativeCapacity(json.RawMessage(raw), &p) != nil {
					t.Fatal("actual public typed contract malformed")
				}
				return p
			}
			// A declared test current-source input exercises the independent
			// self-binding check without claiming this test is deployed Core.
			source := strings.Repeat("c", 40)
			for _, name := range []string{"exact", "unknown_source", "foreign_runtime", "member_origin", "recipient", "adapter_source", "slot_admission", "retirement_age", "cross_provider", "duplicate_approval"} {
				t.Run(name, func(t *testing.T) {
					p := read()
					r := p.GuestRetirementBinding
					r.CoreAuthoritySourceCommit = source
					current, selected := source, provider
					approvals := append([]guestProductionProfileApproval(nil), guestProductionProfileApprovals...)
					switch name {
					case "unknown_source":
						current = ""
					case "foreign_runtime":
						current = strings.Repeat("d", 40)
					case "member_origin":
						r.Members[0].Origin = "https://foreign.invalid:9447"
					case "recipient":
						p.GuestNotifyCanaryBinding.RecipientSHA256 = strings.Repeat("f", 64)
					case "adapter_source":
						p.MutationBindings[0].OriginalProviderSourceCommit = strings.Repeat("e", 40)
					case "slot_admission":
						p.MutationBindings[0].Slots[7].DesiredSpec.AdmissionChecksum = strings.Repeat("f", 64)
					case "retirement_age":
						r.MaxEvidenceAgeSeconds = 29
					case "cross_provider":
						selected = map[string]string{"aws": "hetzner", "hetzner": "aws"}[provider]
					case "duplicate_approval":
						for _, a := range guestProductionProfileApprovals {
							if a.Provider == provider {
								approvals = append(approvals, a)
							}
						}
					}
					if guestProductionProfileMatches(p, *r, selected, current, approvals) != (name == "exact") {
						t.Fatal("actual contract/source changed the closed approval match")
					}
				})
			}
		})
	}
}
