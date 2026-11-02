package capacity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Shape-only synthetic contract (never installed in the compiled registry).
func guestPolicyContinuityFixture(t *testing.T) model.CapacityPolicySpec {
	t.Helper()
	p, _, _, _ := guestProductionRegistryFixture(t)
	p.Environment, p.Domain, p.Dimension = "production", "notify", "aws-vm-members"
	p.Workflow = model.ManifestSelector{Namespace: "dakasa-production", Name: "original-guest-reconcile"}
	p.MinSamples = 61
	p.Signals = []model.CapacitySignalRule{{Name: "handlers", SourceIdentity: "prometheus/notify", Unit: "handlers", UpAbove: 3, DownBelow: 0.25}}
	p.Profiles[0].Region = "us-east-1"
	p.Profiles[0].QuoteValidUntil = time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)
	return guestPolicyContinuityClone(t, p)
}

func guestPolicyContinuityClone(t *testing.T, p model.CapacityPolicySpec) model.CapacityPolicySpec {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out model.CapacityPolicySpec
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGuestPolicyContinuityKeepsMembersAcrossSchedulingOnlyChanges(t *testing.T) {
	prior := guestPolicyContinuityFixture(t)
	if !ValidDigest(GuestPolicyContinuitySHA256(prior)) {
		t.Fatal("complete synthetic production contract has no continuity digest")
	}
	for name, change := range map[string]func(*model.CapacityPolicySpec){
		"min_samples_61_to_60": func(p *model.CapacityPolicySpec) { p.MinSamples = 60 },
		"signal_thresholds":    func(p *model.CapacityPolicySpec) { p.Signals[0].UpAbove, p.Signals[0].DownBelow = -1, -2 },
		"hysteresis_and_cadence": func(p *model.CapacityPolicySpec) {
			p.UpHoldSeconds, p.DownHoldSeconds, p.CooldownSeconds = 60, 300, 300
		},
		"refreshed_quote": func(p *model.CapacityPolicySpec) {
			p.Profiles[0].QuoteValidUntil = p.Profiles[0].QuoteValidUntil.AddDate(0, 1, 0)
		},
		"sample_gap": func(p *model.CapacityPolicySpec) { p.MaxSampleGapSeconds = 10 },
		// The binding pins max_evidence_age_seconds 30; the policy bound may
		// move anywhere at or above it without changing the contract (below
		// it, see the refusal case "policy_evidence_age_below_binding").
		"policy_evidence_age_raised": func(p *model.CapacityPolicySpec) { p.MaxEvidenceAgeSeconds = 120 },
	} {
		t.Run(name, func(t *testing.T) {
			current := guestPolicyContinuityClone(t, prior)
			change(&current)
			if GuestPolicyContinuitySHA256(current) != GuestPolicyContinuitySHA256(prior) || !GuestPolicyContinuous(prior, current) {
				t.Fatal("a scheduling-only policy change stranded the installed Guest member")
			}
		})
	}
}

func TestGuestPolicyContinuityRefusesAChangedGuestContract(t *testing.T) {
	prior := guestPolicyContinuityFixture(t)
	for name, change := range map[string]func(*model.CapacityPolicySpec){
		"member_origin": func(p *model.CapacityPolicySpec) {
			p.GuestRetirementBinding.Members[0].Origin = "https://other.invalid"
		},
		"member_principal": func(p *model.CapacityPolicySpec) {
			p.GuestRetirementBinding.Members[0].ActorClientPrincipal = "other-actor"
		},
		"provisioner_key": func(p *model.CapacityPolicySpec) {
			p.GuestRetirementBinding.ProvisionerPublicKey = strings.Repeat("A", 43) + "="
		},
		"protocol_authority": func(p *model.CapacityPolicySpec) {
			p.GuestRetirementBinding.CoreAuthoritySourceCommit = strings.Repeat("f", 40)
		},
		"slot_bootstrap": func(p *model.CapacityPolicySpec) {
			p.MutationBindings[0].Slots[0].DesiredSpec.BootstrapSHA256 = strings.Repeat("9", 64)
		},
		"mutation_slot_native": func(p *model.CapacityPolicySpec) { p.MutationBindings[0].Slots[0].DesiredSpec.NativeName = "other-vm" },
		"provider":             func(p *model.CapacityPolicySpec) { p.Profiles[0].Provider = "other-fixture" },
		"region":               func(p *model.CapacityPolicySpec) { p.Profiles[0].Region = "sa-east-1" },
		"dimension":            func(p *model.CapacityPolicySpec) { p.Dimension = "hetzner-vm-members" },
		"environment":          func(p *model.CapacityPolicySpec) { p.Environment = "staging" },
		"workflow":             func(p *model.CapacityPolicySpec) { p.Workflow.Name = "other-reconcile" },
		"invalid_canary_binding": func(p *model.CapacityPolicySpec) {
			p.GuestNotifyCanaryBinding = &model.CapacityGuestNotifyCanaryBinding{}
		},
		// A policy evidence-age bound under the binding's 30 seconds makes the
		// Guest binding itself invalid, so it breaks continuity (ADR-0094).
		"policy_evidence_age_below_binding": func(p *model.CapacityPolicySpec) { p.MaxEvidenceAgeSeconds = 29 },
		"no_guest_binding":                  func(p *model.CapacityPolicySpec) { p.GuestRetirementBinding = nil },
		"profile_not_unique":                func(p *model.CapacityPolicySpec) { p.Profiles = append(p.Profiles, p.Profiles[0]) },
		"evidence_class_legacy": func(p *model.CapacityPolicySpec) {
			p.GuestRetirementBinding.EvidenceClass = "native_qemu_qualification"
		},
	} {
		t.Run(name, func(t *testing.T) {
			current := guestPolicyContinuityClone(t, prior)
			change(&current)
			if GuestPolicyContinuous(prior, current) || GuestPolicyContinuous(current, prior) {
				t.Fatal("a changed Guest production contract was treated as continuous")
			}
		})
	}
}

// The synthetic fixture has no Notify canary binding, so the canary-binding
// equality path is proved on the actual public production contracts: each
// change below still validates (both digests stay valid), yet the member must
// not cross it.
func TestGuestPolicyContinuityRefusesAChangedValidCanaryBinding(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		raw, err := os.ReadFile("testdata/original-notify-" + provider + "-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		read := func(t *testing.T) model.CapacityPolicySpec {
			t.Helper()
			var p model.CapacityPolicySpec
			if DecodeNativeCapacity(json.RawMessage(raw), &p) != nil || p.GuestNotifyCanaryBinding == nil {
				t.Fatal("actual public typed contract with a canary binding required")
			}
			return p
		}
		t.Run(provider+"/scheduling_only_stays_continuous", func(t *testing.T) {
			prior, current := read(t), read(t)
			current.MinSamples = 60
			// 120 -> 30: still >= the binding's 30 and the canary's interval.
			current.MaxEvidenceAgeSeconds = 30
			if !ValidDigest(GuestPolicyContinuitySHA256(prior)) || !GuestPolicyContinuous(prior, current) {
				t.Fatal("actual production contract stranded its member on a min_samples change")
			}
		})
		for name, change := range map[string]func(*model.CapacityGuestNotifyCanaryBinding){
			"maximum_publications_per_hour":        func(b *model.CapacityGuestNotifyCanaryBinding) { b.MaximumPublicationsPerHour-- },
			"minimum_publication_interval_seconds": func(b *model.CapacityGuestNotifyCanaryBinding) { b.MinimumPublicationIntervalSeconds++ },
			"recipient_sha256":                     func(b *model.CapacityGuestNotifyCanaryBinding) { b.RecipientSHA256 = strings.Repeat("7", 64) },
			"name":                                 func(b *model.CapacityGuestNotifyCanaryBinding) { b.Name += "-v2" },
		} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				prior, current := read(t), read(t)
				change(current.GuestNotifyCanaryBinding)
				if ValidateGuestNotifyCanaryBinding(current) != nil || !ValidDigest(GuestPolicyContinuitySHA256(prior)) || !ValidDigest(GuestPolicyContinuitySHA256(current)) {
					t.Fatal("canary change must still validate so the digest comparison is reached")
				}
				if GuestPolicyContinuous(prior, current) || GuestPolicyContinuous(current, prior) {
					t.Fatal("a changed Notify canary binding was treated as continuous")
				}
			})
		}
	}
}
