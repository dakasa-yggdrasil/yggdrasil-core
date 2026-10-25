//go:build !nativequalification

package capacity

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"os"
	"strings"
	"testing"
)

// The fixtures and literal expected hashes come only from the two original
// owning-Go full_policy results. No synthetic contract enters the registry.
func testGuestActualA900ProfileApprovals(t *testing.T) {
	expected := map[string]struct{ catalog, contract string }{
		"aws":     {"8066c34878d2a476f926207e65c27cf3f5bc87743c8380549e360040b7499b48", "97beb27b884fcf3928f2da6f14d8840ba0fb6f460012fdb50b8ab02b01334df7"},
		"hetzner": {"6d0a539f4841566c97063158fa3a4e62a465f7eb74d10a6405679681957706ec", "3fcb7fc4634fc5102d2172cc1d7f66bd92a61b9d544525a3438e8cdf914803f9"},
	}
	if len(guestProductionProfileApprovals) != 4 || guestProtocolCompatibilityMapSHA256(guestD12ProtocolProfileApprovals) != GuestD12ProtocolCompatibilityMapSHA256 || GuestProtocolCompatibilityMapSHA256() == GuestD12ProtocolCompatibilityMapSHA256 {
		t.Fatal("old two-map snapshot changed or current four-map absent")
	}
	for _, provider := range []string{"aws", "hetzner"} {
		data, err := os.ReadFile("testdata/a900-notify-" + provider + "-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"actual_current_map", "old557_rejects_new", "changed_member", "changed_bootstrap", "changed_Guest_source", "changed_runtime_source", "changed_OCI", "missing_actual_issuer"} {
			t.Run(provider+"/"+kind, func(t *testing.T) {
				var p model.CapacityPolicySpec
				if DecodeNativeCapacity(json.RawMessage(data), &p) != nil {
					t.Fatal("actual full typed fixture")
				}
				b := p.GuestRetirementBinding
				if b == nil || b.GuestSourceCommit != "a900f5379db35ee48f74798c4a68cd8091f8c116" || b.ProvisionerSourceCommit != b.GuestSourceCommit || b.ProfileManifest.ActorSourceCommit != b.GuestSourceCommit || b.ProfileManifest.OwnerSourceCommit != b.GuestSourceCommit || b.CoreAuthoritySourceCommit != GuestD11ProtocolAuthority || b.ProfileManifest.OwnerImageDigest != "sha256:1fbb774a3c4d0dfd5439b79a4082e1d25f8b8cf3ccfedb3bac651e98190ff373" || b.ProfileManifest.ProductionCatalogSHA256 != expected[provider].catalog || GuestProductionProfileContractSHA256(p, *b, provider) != expected[provider].contract {
					t.Fatal("published actual a900 contract hashes or original OCI changed")
				}
				fingerprint := GuestProtocolCompatibilityMapSHA256()
				issuer := strings.Repeat("a", 40) // Declared pure operand, never a future actual Core PUB.
				switch kind {
				case "old557_rejects_new":
					fingerprint = GuestD12ProtocolCompatibilityMapSHA256
				case "changed_member":
					b.Members[0].ActorClientPrincipal += "-foreign"
				case "changed_bootstrap":
					b.ProfileManifest.BootstrapSHA256 = strings.Repeat("f", 64)
				case "changed_Guest_source":
					b.GuestSourceCommit = "548734eef627404f10b5117e0ec7f27582ae9048"
				case "changed_runtime_source":
					b.ProfileManifest.OwnerSourceCommit = "548734eef627404f10b5117e0ec7f27582ae9048"
				case "changed_OCI":
					b.ProfileManifest.OwnerImageDigest = "sha256:" + strings.Repeat("f", 64)
				case "missing_actual_issuer":
					issuer = ""
				}
				accepted := GuestBindingApprovedByCompatibilityMap(p, *b, issuer, fingerprint)
				if accepted != (kind == "actual_current_map") {
					t.Fatal("wrong complete contract or old map approved a new Guest", kind)
				}
			})
		}
	}
}
