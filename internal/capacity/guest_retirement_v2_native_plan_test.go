package capacity

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeOffContentFixture(provider string) (model.CapacityPolicySpec, model.CapacityMutationBinding, model.CapacityVMFleetPlan, model.CapacityMutationReceipt) {
	p, b, inventory, _ := vmObservationFixture()
	b.OriginalProviderSourceCommit = strings.Repeat("a", 40)
	if provider == "aws" {
		b.EnsureCapability, b.DestroyCapability = "ensure_ec2_instance", "terminate_ec2_instance"
	}
	for i := range b.Slots {
		b.Slots[i].DesiredSpec.Capability = b.EnsureCapability
		raw, _ := canonicalMutationProjection(*b.Slots[i].DesiredSpec)
		b.Slots[i].DesiredSpecSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	p.Profiles = []model.CapacityProfile{{Name: b.ProfileName, Provider: provider, MaxUnits: b.MaxSlots}}
	p.MutationBindings = []model.CapacityMutationBinding{b}
	slot := b.Slots[1]
	s := inventory.Members[1].Server
	s.ID = "12345"
	s.Status = "off"
	if provider == "aws" {
		s.ID = "i-1234567890abcdef0"
		s.Status = "stopped"
	}
	// Deliberately different clock domains, valid content with no freshness.
	s.CreatedAt = "2050-01-01T00:00:00Z"
	s.ObservedAt = "2000-01-01T00:00:00Z"
	g := model.CapacityMutationGrant{GrantID: "12345678-1234-4234-8234-123456789012", BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, Capability: b.EnsureCapability, RequestSHA256: slot.DesiredSpecSHA256, State: "confirmed"}
	s.Labels["yggdrasil.io/intent"] = g.GrantID
	spec := *slot.DesiredSpec
	spec.Capability = VMObserveServer
	if provider == "aws" {
		spec.Capability = "observe_ec2_instance"
	}
	spec.ExpectedResourceID, spec.ExpectedResourceCreatedAt = s.ID, s.CreatedAt
	digest := slot.DesiredSpecSHA256
	if provider == "hetzner" {
		raw, _ := canonicalMutationProjection(spec)
		digest = fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	plan := model.CapacityVMFleetPlan{DesiredSpec: spec, RequestSHA256: digest, Protected: false, Server: &s, ObservedAt: "1999-01-01T00:00:00Z"}
	r := model.CapacityMutationReceipt{Grant: g, Outcome: "accepted", TransportCompleted: true, ResourceID: s.ID, ResourceCreatedAt: s.CreatedAt}
	return p, b, plan, r
}

func TestGuestRetirementV2NativeOffContentUsesActualProviderWireWithoutClockAuthority(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		t.Run(provider, func(t *testing.T) {
			p, b, plan, r := nativeOffContentFixture(provider)
			if err := GuestRetirementV2NativeOffPlanContent(p, b, plan, r); err != nil {
				t.Fatal("actual provider content refused", err)
			}
			r.Grant.State = "settled"
			if err := GuestRetirementV2NativeOffPlanContent(p, b, plan, r); err != nil {
				t.Fatal("accepted settled original refused", err)
			}
		})
	}
}

func TestGuestRetirementV2NativeOffContentRefusesChangedOriginalOrProjection(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		for _, kind := range []string{"unconfigured_binding", "foreign_provider", "wrong_grant_state", "uncertain_original", "incomplete_transport", "create_compensation", "native_readback_substitute", "destroy_receipt", "missing_tuple", "changed_tuple", "wrong_grant_label", "wrong_owner_shape", "foreign_label", "profile_drift", "wrong_capability", "wrong_expected_tuple", "wrong_digest", "wrong_native_off_state", "unverified_spec", "partial_identity", "warmth", "business", "fencing", "plan_compensation", "missing_server", "bad_time", "missing_source"} {
			t.Run(provider+"/"+kind, func(t *testing.T) {
				p, b, plan, r := nativeOffContentFixture(provider)
				switch kind {
				case "unconfigured_binding":
					p.MutationBindings = nil
				case "foreign_provider":
					p.Profiles[0].Provider = "other"
				case "wrong_grant_state":
					r.Grant.State = "redeemed"
				case "uncertain_original":
					r.Outcome = "uncertain"
				case "incomplete_transport":
					r.TransportCompleted = false
				case "create_compensation":
					r.Grant.CompensationOf = r.Grant.GrantID
				case "native_readback_substitute":
					r.NativeReadback = &model.CapacityMutationProof{}
				case "destroy_receipt":
					r.Grant.Capability = b.DestroyCapability
				case "missing_tuple":
					r.ResourceID = ""
				case "changed_tuple":
					plan.Server.ID = "foreign"
				case "wrong_grant_label":
					plan.Server.Labels["yggdrasil.io/intent"] = "foreign"
				case "wrong_owner_shape":
					plan.Server.Labels["yggdrasil.io/owner"] = ""
				case "foreign_label":
					plan.Server.Labels["caller-ready"] = "true"
				case "profile_drift":
					plan.DesiredSpec.ProfileChecksum = strings.Repeat("f", 64)
				case "wrong_capability":
					plan.DesiredSpec.Capability = b.EnsureCapability
				case "wrong_expected_tuple":
					plan.DesiredSpec.ExpectedResourceID = "foreign"
				case "wrong_digest":
					plan.RequestSHA256 = strings.Repeat("e", 64)
				case "wrong_native_off_state":
					if provider == "aws" {
						plan.Server.Status = "off"
					} else {
						plan.Server.Status = "stopped"
					}
				case "unverified_spec":
					plan.Server.PhysicalSpecVerified = false
				case "partial_identity":
					plan.Server.CompensationIdentityVerified = true
				case "warmth":
					plan.WarmReadinessEvidence = true
				case "business":
					plan.BusinessReadyEvidence = true
				case "fencing":
					plan.ProviderFencingEvidence = true
				case "plan_compensation":
					plan.CompensationIdentityVerified = true
				case "missing_server":
					plan.Server = nil
				case "bad_time":
					plan.ObservedAt = "not-time"
				case "missing_source":
					b.OriginalProviderSourceCommit = ""
					p.MutationBindings = []model.CapacityMutationBinding{b}
				}
				if GuestRetirementV2NativeOffPlanContent(p, b, plan, r) == nil {
					t.Fatal("changed original content accepted", kind)
				}
			})
		}
	}
}
