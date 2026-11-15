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

	// The current4720 golden is the exact canonical policy from its actual
	// owning-Go full_policy result. Keep the existing named census unchanged.
	currentRaw, err := os.ReadFile("testdata/current4720-notify-hetzner-production-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(guestProductionProfileApprovals) != 7 || len(guestB509ProtocolProfileApprovals) != 6 || guestProtocolCompatibilityMapSHA256(guestB509ProtocolProfileApprovals) != GuestB509ProtocolCompatibilityMapSHA256 {
		t.Fatal("current append changed the frozen six-contract map")
	}
	for i, historical := range guestB509ProtocolProfileApprovals {
		if guestProductionProfileApprovals[i] != historical {
			t.Fatal("current append changed a historical approval")
		}
	}
	for _, mode := range []string{"exact", "unknown_source", "foreign_runtime", "member_origin", "member_principal", "transport_reference", "recipient", "adapter_source", "slot_admission", "retirement_age", "cross_provider", "duplicate_approval", "Guest_source", "owner_image", "slot_bootstrap", "historical_two", "historical_four", "historical_six"} {
		var p model.CapacityPolicySpec
		if DecodeNativeCapacity(json.RawMessage(currentRaw), &p) != nil {
			t.Fatal("actual current4720 complete typed contract malformed", mode)
		}
		b := p.GuestRetirementBinding
		if b == nil || p.ExecutionEnabled || len(p.MutationBindings) != 1 || p.MutationBindings[0].IntegrationInstanceID != "4809805f-b6e0-4afd-8cd2-9c9926ad7f8a" || b.GuestSourceCommit != "4720b43db5bb513c33485106ecb13314393de43f" || b.ProvisionerSourceCommit != b.GuestSourceCommit || b.ProfileManifest.ActorSourceCommit != b.GuestSourceCommit || b.ProfileManifest.OwnerSourceCommit != b.GuestSourceCommit || b.CoreAuthoritySourceCommit != GuestD11ProtocolAuthority || b.ProfileManifest.OwnerImageDigest != "sha256:e2ef044385f26db74d2657396ffd81133f239d76b9afd6931e9da0f6559313f4" || b.ProfileManifest.ProductionCatalogSHA256 != "6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec" || GuestProductionProfileContractSHA256(p, *b, "hetzner") != "90ae5b64ae602abfbd0672eb2ca33f59ceb5b3e4ff8a62e45379e50de755d3e9" {
			t.Fatal("actual current4720 Source, image, instance or contract changed", mode)
		}
		source := strings.Repeat("c", 40) // Declared pure issuer, not a future Core PUB.
		current, selected := source, "hetzner"
		approvals := append([]guestProductionProfileApproval(nil), guestProductionProfileApprovals...)
		fingerprint := GuestProtocolCompatibilityMapSHA256()
		switch mode {
		case "unknown_source":
			current = ""
		case "foreign_runtime":
			b.CoreAuthoritySourceCommit = source
			current = strings.Repeat("d", 40)
		case "member_origin":
			b.Members[0].Origin = "https://foreign.invalid:9447"
		case "member_principal":
			b.Members[0].ActorClientPrincipal += "-foreign"
		case "transport_reference":
			b.Members[0].ClientKeyRef = "secret://foreign/client#value"
		case "recipient":
			p.GuestNotifyCanaryBinding.RecipientSHA256 = strings.Repeat("f", 64)
		case "adapter_source":
			p.MutationBindings[0].OriginalProviderSourceCommit = strings.Repeat("e", 40)
		case "slot_admission":
			p.MutationBindings[0].Slots[7].DesiredSpec.AdmissionChecksum = strings.Repeat("f", 64)
		case "retirement_age":
			b.MaxEvidenceAgeSeconds = 29
		case "cross_provider":
			selected = "aws"
		case "duplicate_approval":
			approvals = append(approvals, guestProductionProfileApprovals[6])
		case "Guest_source":
			b.GuestSourceCommit = strings.Repeat("e", 40)
		case "owner_image":
			b.ProfileManifest.OwnerImageDigest = "sha256:" + strings.Repeat("e", 64)
		case "slot_bootstrap":
			b.ProfileManifest.SlotBootstraps[7].BootstrapSHA256 = strings.Repeat("e", 64)
		case "historical_two":
			fingerprint = GuestD12ProtocolCompatibilityMapSHA256
		case "historical_four":
			fingerprint = GuestD15ProtocolCompatibilityMapSHA256
		case "historical_six":
			fingerprint = GuestB509ProtocolCompatibilityMapSHA256
		}
		b.ProfileManifestSHA256 = GuestRetirementSHA(b.ProfileManifest)
		if guestProductionProfileMatches(p, *b, selected, current, approvals) != (mode == "exact" || mode == "historical_two" || mode == "historical_four" || mode == "historical_six") {
			t.Fatal("current4720 complete contract escaped source approval", mode)
		}
		if mode == "historical_two" || mode == "historical_four" || mode == "historical_six" {
			if guestBindingApprovedByCompatibilityMap(p, *b, source, fingerprint, approvals) {
				t.Fatal("historical snapshot approved the new current4720 contract", mode)
			}
		} else if mode == "exact" && !guestBindingApprovedByCompatibilityMap(p, *b, source, fingerprint, approvals) {
			t.Fatal("current seven-profile map refused its actual complete contract")
		}
	}
}
