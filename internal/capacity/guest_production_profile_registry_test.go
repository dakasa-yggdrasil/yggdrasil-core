package capacity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This is a shape-only synthetic contract used solely by the pure matcher. It
// is never installed in the compiled registry and grants no provider authority.
func guestProductionRegistryFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityGuestRetirementBinding, guestProductionProfileApproval, string) {
	t.Helper()
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	profile := model.CapacityGuestProtectedProfileManifest{Schema: GuestProtectedProfileSchema, Profile: "synthetic-production", CoverageClass: "complete_production_roster", ProductionCatalogSHA256: digest, MutationBinding: "synthetic-binding", BootstrapOwnerSourceCommit: source, BootstrapOwnerBinarySHA256: digest, BootstrapReaderBinarySHA256: digest, BootstrapPayloadSHA256: digest, BootstrapSHA256: digest, OriginalProvisioningBudgetSeconds: 420, OriginalProvisioningStepID: "original-create", OwnerSourceCommit: source, OwnerBinarySHA256: digest, OwnerImageDigest: "sha256:" + strings.Repeat("c", 64), ProtectedCgroup: GuestProtectedCgroup, ActorSourceCommit: source, ActorBinarySHA256: digest, RuntimeClientCommandSHA256: digest, PoweroffCommandSHA256: digest, Writers: []model.CapacityGuestProtectedWriterDefinition{{ID: "synthetic-writer", SourceCommit: source, BinarySHA256: digest, CommandSHA256: strings.Repeat("d", 64), ImageDigest: "sha256:" + strings.Repeat("e", 64), SourceImageReceiptSHA256: strings.Repeat("f", 64), HandleContractSHA256: strings.Repeat("1", 64), CgroupRelativePath: "synthetic-writer"}}}
	mutation := model.CapacityMutationBinding{Name: profile.MutationBinding, ProfileName: profile.Profile, MaxSlots: 1, Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpec: &model.CapacityMutationSpecV1{BootstrapSHA256: digest}}}}
	binding := model.CapacityGuestRetirementBinding{Mode: GuestRetirementSchema, MutationBindingName: mutation.Name, EvidenceClass: "owned_provisioner_original", ProvisionerSourceCommit: source, GuestSourceCommit: source, CoreAuthoritySourceCommit: source, ProvisionerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), EnrollmentSigningKeyRef: "secret://synthetic/enrollment#value", IntentSigningKeyRef: "secret://synthetic/intent#value", ProfileManifest: profile, ProfileManifestSHA256: GuestRetirementSHA(profile), MaxEvidenceAgeSeconds: 30, Members: []model.CapacityGuestRetirementMemberBinding{{Name: "synthetic-member", Slot: 1, Origin: "https://synthetic.invalid", ServerCARef: "secret://synthetic/ca#value", ClientCertificateRef: "secret://synthetic/cert#value", ClientKeyRef: "secret://synthetic/key#value", ActorClientPrincipal: "synthetic-actor", ProvisionerClientPrincipal: "synthetic-provisioner"}}}
	policy := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 30, Profiles: []model.CapacityProfile{{Name: profile.Profile, Provider: "fixture"}}, MutationBindings: []model.CapacityMutationBinding{mutation}, GuestRetirementBinding: &binding}
	contract := GuestProductionProfileContractSHA256(policy, binding, "fixture")
	if !ValidDigest(contract) {
		t.Fatal("synthetic complete contract did not validate")
	}
	approval := guestProductionProfileApproval{"fixture", profile.Profile, profile.ProductionCatalogSHA256, contract}
	return policy, binding, approval, source
}

func TestGuestProductionRegistryExactContract(t *testing.T) {
	for _, mode := range []string{"exact", "empty_registry", "duplicate_approval", "empty_runtime_source", "foreign_runtime_source", "foreign_declared_core", "provider", "catalog", "profile", "guest_source", "provisioner_source", "writer_source", "writer_image", "writer_handle", "owner_image", "bootstrap", "principal", "transport_origin", "transport_reference", "issuer_public_key", "slot_contract", "max_slots", "duplicate_binding", "duplicate_profile", "missing_binding", "qualification"} {
		t.Run(mode, func(t *testing.T) {
			p, b, a, source := guestProductionRegistryFixture(t)
			provider := "fixture"
			approvals := []guestProductionProfileApproval{a}
			switch mode {
			case "empty_registry":
				approvals = nil
			case "duplicate_approval":
				approvals = append(approvals, a)
			case "empty_runtime_source":
				source = ""
			case "foreign_runtime_source":
				source = strings.Repeat("f", 40)
			case "foreign_declared_core":
				b.CoreAuthoritySourceCommit = strings.Repeat("e", 40)
			case "provider":
				provider = "foreign"
			case "catalog":
				b.ProfileManifest.ProductionCatalogSHA256 = strings.Repeat("c", 64)
			case "profile":
				b.ProfileManifest.Profile = "foreign"
			case "guest_source":
				b.GuestSourceCommit = strings.Repeat("c", 40)
				b.ProfileManifest.ActorSourceCommit = b.GuestSourceCommit
			case "provisioner_source":
				b.ProvisionerSourceCommit = strings.Repeat("c", 40)
			case "writer_source":
				b.ProfileManifest.Writers[0].SourceCommit = strings.Repeat("c", 40)
			case "writer_image":
				b.ProfileManifest.Writers[0].ImageDigest = "sha256:" + strings.Repeat("c", 64)
			case "writer_handle":
				b.ProfileManifest.Writers[0].HandleContractSHA256 = strings.Repeat("c", 64)
			case "owner_image":
				b.ProfileManifest.OwnerImageDigest = "sha256:" + strings.Repeat("d", 64)
			case "bootstrap":
				b.ProfileManifest.BootstrapPayloadSHA256 = strings.Repeat("c", 64)
			case "principal":
				b.Members[0].ActorClientPrincipal = "foreign"
			case "transport_origin":
				b.Members[0].Origin = "https://foreign.invalid"
			case "transport_reference":
				b.Members[0].ServerCARef = "secret://foreign/ca#value"
			case "issuer_public_key":
				b.EnrollmentIssuerPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			case "slot_contract":
				p.MutationBindings[0].Slots[0].DesiredSpec.NativeName = "foreign"
			case "max_slots":
				p.MutationBindings[0].MaxSlots++
			case "duplicate_binding":
				p.MutationBindings = append(p.MutationBindings, p.MutationBindings[0])
			case "duplicate_profile":
				p.Profiles = append(p.Profiles, p.Profiles[0])
			case "qualification":
				b.EvidenceClass = "native_qemu_qualification"
				provider = "native-qemu"
			}
			b.ProfileManifestSHA256 = GuestRetirementSHA(b.ProfileManifest)
			p.GuestRetirementBinding = &b
			if mode == "missing_binding" {
				p.GuestRetirementBinding = nil
			}
			got := guestProductionProfileMatches(p, b, provider, source, approvals)
			if got != (mode == "exact") {
				t.Fatal("wrong source admission result", got)
			}
		})
	}
}

func TestGuestProductionRegistryPinsIndependentHetznerSource(t *testing.T) {
	p, b, _, _ := guestProductionRegistryFixture(t)
	p.Profiles[0].Provider = "hetzner"
	if GuestProductionProfileContractSHA256(p, b, "hetzner") != "" {
		t.Fatal("Hetzner contract omitted its adapter source")
	}
	p.MutationBindings[0].OriginalProviderSourceCommit = strings.Repeat("2", 40)
	one := GuestProductionProfileContractSHA256(p, b, "hetzner")
	if !ValidDigest(one) {
		t.Fatal("independent adapter source contract refused")
	}
	p.MutationBindings[0].OriginalProviderSourceCommit = strings.Repeat("3", 40)
	if other := GuestProductionProfileContractSHA256(p, b, "hetzner"); !ValidDigest(other) || other == one {
		t.Fatal("adapter source failed to change approval contract")
	}
}

func TestGuestProductionRegistryDigestDoesNotMutateOrApprove(t *testing.T) {
	p, b, _, _ := guestProductionRegistryFixture(t)
	before, _ := json.Marshal(p)
	first := GuestProductionProfileContractSHA256(p, b, "fixture")
	b.CoreAuthoritySourceCommit = strings.Repeat("f", 40)
	p.GuestRetirementBinding = &b
	if first != GuestProductionProfileContractSHA256(p, b, "fixture") {
		t.Fatal("future Core revision entered self-referential digest")
	}
	b.CoreAuthoritySourceCommit = strings.Repeat("a", 40)
	p.GuestRetirementBinding = &b
	after, _ := json.Marshal(p)
	if !bytes.Equal(before, after) {
		t.Fatal("source digest changed caller contract")
	}
	if GuestOriginalProfileEnabled(p, b, "fixture") {
		t.Fatal("computing digest or synthetic test contract granted compiled approval")
	}
}

func TestGuestProductionRegistryPinsCanaryAndDeclarativeTopology(t *testing.T) {
	p, b, _, source := guestProductionRegistryFixture(t)
	p.Profiles[0].Provider = "aws"
	p.MutationBindings[0].OriginalProviderSourceCommit = source
	topology := &model.CapacityGuestNotifyCanaryTopology{Schema: "notify_guest_canary_topology_v1", Namespace: "dakasa-production", Binding: b.MutationBindingName, DefinitionsSHA256: strings.Repeat("a", 64), Queues: []model.CapacityGuestNotifyCanaryQueue{{Provider: "aws", Slot: 1, Name: guestNotifyQueueName(b.MutationBindingName, "aws", 1)}}}
	b.ProfileManifest.NotifyCanaryTopology = topology
	b.ProfileManifestSHA256 = GuestRetirementSHA(b.ProfileManifest)
	p.GuestRetirementBinding = &b
	p.GuestNotifyCanaryBinding = &model.CapacityGuestNotifyCanaryBinding{Mode: "original_guest_notify_canary_v1", Name: "unit-only", WriterID: b.ProfileManifest.Writers[0].ID, NotifySourceCommit: source, QuerySHA256: GuestNotifyBusinessQuerySHA256, RecipientSHA256: strings.Repeat("b", 64), RecipientCount: 2, Database: "unit-not-native", DatabaseOID: "1", SystemID: "2", TableOIDs: []string{"3", "4", "5", "6"}, MinimumPublicationIntervalSeconds: 10, MaximumPublicationsPerHour: 120, TopologySHA256: GuestRetirementSHA(topology)}
	one := GuestProductionProfileContractSHA256(p, b, "aws")
	if !ValidDigest(one) {
		t.Fatal("source canary contract refused")
	}
	p.GuestNotifyCanaryBinding.RecipientSHA256 = strings.Repeat("c", 64)
	two := GuestProductionProfileContractSHA256(p, b, "aws")
	if !ValidDigest(two) || two == one {
		t.Fatal("canary recipient authority escaped source profile digest")
	}
	topology.DefinitionsSHA256 = strings.Repeat("d", 64)
	b.ProfileManifestSHA256 = GuestRetirementSHA(b.ProfileManifest)
	p.GuestNotifyCanaryBinding.TopologySHA256 = GuestRetirementSHA(topology)
	three := GuestProductionProfileContractSHA256(p, b, "aws")
	if !ValidDigest(three) || three == two {
		t.Fatal("declarative topology escaped source profile digest")
	}
	p.GuestNotifyCanaryBinding.TopologySHA256 = strings.Repeat("e", 64)
	if GuestProductionProfileContractSHA256(p, b, "aws") != "" {
		t.Fatal("different profile/config topology received a source contract")
	}
}
