//go:build !nativequalification

package capacity

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestD15CompatibilitySnapshotPreservesOriginalIssues(t *testing.T) {
	if guestProtocolCompatibilityMapSHA256(guestD15ProtocolProfileApprovals) != GuestD15ProtocolCompatibilityMapSHA256 || len(guestD15ProtocolProfileApprovals) != 4 || len(guestProductionProfileApprovals) < 4 {
		t.Fatal("original four-profile b5 changed")
	}
	for n, approval := range guestD15ProtocolProfileApprovals {
		if guestProductionProfileApprovals[n] != approval {
			t.Fatal("current map removed or changed a historical approval")
		}
	}
	for _, provider := range []string{"aws", "hetzner"} {
		raw, e := os.ReadFile("testdata/original-notify-" + provider + "-production-contract.json")
		if e != nil {
			t.Fatal(e)
		}
		var p model.CapacityPolicySpec
		if DecodeNativeCapacity(json.RawMessage(raw), &p) != nil {
			t.Fatal("real old complete contract fixture")
		}
		p.GuestRetirementBinding.CoreAuthoritySourceCommit = GuestD11ProtocolAuthority
		// Only a declared future-map operand: no production approval is added.
		expanded := append([]guestProductionProfileApproval(nil), guestD15ProtocolProfileApprovals...)
		expanded = append(expanded, guestProductionProfileApproval{Provider: "declared", Profile: "not-production"})
		if !guestBindingApprovedByCompatibilityMap(p, *p.GuestRetirementBinding, "8c69fa23debd0a665d5276cca41810345f399f14", GuestD15ProtocolCompatibilityMapSHA256, expanded) {
			t.Fatal("historical77 issue b5 was treated as current-only")
		}
		p.GuestRetirementBinding.IntentSigningKeyRef = "secret://foreign/key#value"
		if guestBindingApprovedByCompatibilityMap(p, *p.GuestRetirementBinding, "8c69fa23debd0a665d5276cca41810345f399f14", GuestD15ProtocolCompatibilityMapSHA256, expanded) {
			t.Fatal("historical map admitted changed contract")
		}
	}
}
