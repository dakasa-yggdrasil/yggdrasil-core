package repository

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
	"testing"
	"time"
)

// Synthetic signatures and shape-only profile; this test grants no native authority.
func TestStoredQualificationEnrollmentStaticOnly(t *testing.T) {
	source, digest := strings.Repeat("a", 40), strings.Repeat("b", 64)
	profile := model.CapacityGuestProtectedProfileManifest{Schema: capacity.GuestProtectedProfileSchema, Profile: "claimed-production-profile", CoverageClass: "complete_production_roster", ProductionCatalogSHA256: digest, MutationBinding: "claimed-production-binding", BootstrapOwnerSourceCommit: source, BootstrapOwnerBinarySHA256: digest, BootstrapReaderBinarySHA256: digest, BootstrapPayloadSHA256: digest, BootstrapSHA256: digest, OriginalProvisioningBudgetSeconds: 420, OriginalProvisioningStepID: "original-production-create", OwnerSourceCommit: source, OwnerBinarySHA256: digest, OwnerImageDigest: "sha256:" + strings.Repeat("c", 64), ProtectedCgroup: capacity.GuestProtectedCgroup, ActorSourceCommit: source, ActorBinarySHA256: digest, RuntimeClientCommandSHA256: digest, PoweroffCommandSHA256: digest, Writers: []model.CapacityGuestProtectedWriterDefinition{{ID: "claimed-production-writer", SourceCommit: source, BinarySHA256: digest, CommandSHA256: strings.Repeat("d", 64), ImageDigest: "sha256:" + strings.Repeat("e", 64), SourceImageReceiptSHA256: strings.Repeat("f", 64), HandleContractSHA256: strings.Repeat("1", 64), CgroupRelativePath: "claimed-production-writer"}}}
	b := model.CapacityMutationBinding{Name: profile.MutationBinding, ProfileName: profile.Profile, MaxSlots: 1, Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpec: &model.CapacityMutationSpecV1{BootstrapSHA256: digest}}}}
	binding := model.CapacityGuestRetirementBinding{Mode: capacity.GuestRetirementSchema, MutationBindingName: b.Name, EvidenceClass: "owned_provisioner_original", ProvisionerSourceCommit: source, GuestSourceCommit: source, CoreAuthoritySourceCommit: source, ProvisionerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), EnrollmentSigningKeyRef: "secret://source/claimed-enrollment#value", IntentSigningKeyRef: "secret://source/claimed-intent#value", ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), MaxEvidenceAgeSeconds: 30, Members: []model.CapacityGuestRetirementMemberBinding{{Name: "claimed-member", Slot: 1, Origin: "https://guest.invalid", ServerCARef: "secret://source/claimed-ca#value", ClientCertificateRef: "secret://source/claimed-cert#value", ClientKeyRef: "secret://source/claimed-key#value", ActorClientPrincipal: "claimed-actor", ProvisionerClientPrincipal: "claimed-provisioner"}}}
	p := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 30, Profiles: []model.CapacityProfile{{Name: profile.Profile, Provider: "fixture"}}, MutationBindings: []model.CapacityMutationBinding{b}, GuestRetirementBinding: &binding}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	binding.EnrollmentIssuerPublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	p.GuestRetirementBinding = &binding
	life := model.CapacityGuestRetirementLifetime{BootID: "11111111-1111-4111-8111-111111111111", ProcessNonceSHA256: digest, PID: 12, StartTicks: 7, SourceCommit: source, BinarySHA256: digest, ServiceInvocationID: strings.Repeat("a", 32)}
	writer := model.CapacityGuestRetirementWriter{ID: profile.Writers[0].ID, Lifetime: life}
	now := time.Unix(100, 0).UTC()
	statement := model.CapacityGuestRetirementEnrollmentStatement{Schema: capacity.GuestRetirementSchema, Purpose: capacity.GuestRetirementPurpose, BindingName: binding.Members[0].Name, SourceClass: binding.EvidenceClass, ProvisionerSourceCommit: source, OriginalNativeResultSHA256: digest, Tuple: model.CapacityGuestNativeTuple{Provider: "fixture", Profile: profile.Profile, Slot: 1, ResourceID: "synthetic", CreatedAt: now.Format(time.RFC3339Nano)}, Actor: life, Runtime: life, Writers: []model.CapacityGuestRetirementWriter{writer}, RuntimeCommandSHA256: digest, PoweroffCommandSHA256: digest, ObservationPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), CoreIntentPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)), CoreAuthoritySourceCommit: source, IssuedAt: now.Add(time.Hour)}
	statement.WriterRosterSHA256 = capacity.GuestRetirementSHA(statement.Writers)
	enrollment := model.CapacityGuestRetirementEnrollment{Statement: statement}
	enrollment.Signature, _ = capacity.GuestLifecycleSignature(key, statement)
	stored := guestOriginalStored{binding: binding, member: binding.Members[0]}
	if err := validateStoredQualificationEnrollment(p, stored, enrollment); err != nil {
		t.Fatal("static valid signature refused", err)
	}
	if capacity.GuestRetirementEnrollment(p, binding, stored.member, enrollment, now) == nil {
		t.Fatal("global validator lost its wall freshness gate")
	}
	t.Run("tamper", func(t *testing.T) {
		bad := enrollment
		bad.Statement.Actor.PID++
		if validateStoredQualificationEnrollment(p, stored, bad) == nil {
			t.Fatal("tamper accepted")
		}
	})
	t.Run("binding", func(t *testing.T) {
		bad := stored
		bad.member.Name = "wrong"
		if validateStoredQualificationEnrollment(p, bad, enrollment) == nil {
			t.Fatal("different member accepted")
		}
	})
	t.Run("old_source", func(t *testing.T) {
		bad := stored
		bad.binding.CoreAuthoritySourceCommit = strings.Repeat("f", 40)
		if validateStoredQualificationEnrollment(p, bad, enrollment) == nil {
			t.Fatal("old source accepted")
		}
	})
}
