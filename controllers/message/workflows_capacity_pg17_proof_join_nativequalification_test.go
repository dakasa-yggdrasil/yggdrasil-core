//go:build nativequalification

package message

import (
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestPG17ProofJoinRequiresExactIdentityAndActions(t *testing.T) {
	b := model.CapacityMutationBinding{Name: "binding", IntegrationInstanceID: "instance", ScopeChecksum: "scope", ProfileName: "profile", EnsureCapability: "ensure_server", Slots: []model.CapacityMutationSlotBinding{{Slot: 2, DesiredSpecSHA256: "digest"}}}
	g := model.CapacityMutationGrant{State: "issued", GrantID: "grant", BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Capability: b.EnsureCapability, Slot: 2, RequestSHA256: "digest", ExpiresAt: time.Now().UTC()}
	guest := model.CapacityMutationProof{GrantID: g.GrantID, BindingName: g.BindingName, Slot: g.Slot, RequestSHA256: g.RequestSHA256, ObservedCreationGrantID: g.GrantID, ResourceID: "resource", ResourceCreatedAt: "created", ObservedAt: time.Now().UTC(), ReceiptRef: "original-native-qemu-enrollment-confirm:hash", OwnerVerified: true, SpecVerified: true, ActionIDs: []string{"action-a", "action-b"}, ActionsTerminal: true, ActionsSuccessful: true}
	confirmed := g
	confirmed.State = "confirmed"
	proof := guest
	proof.ReceiptRef = "core-native:workflow:instance:capacity.confirm_native_mutation"
	proof.ObservedAt = proof.ObservedAt.Add(time.Second)
	first := pg17NativeProofReturn{Grant: confirmed, Proof: proof}
	replay := first
	replay.Proof.ObservedAt = replay.Proof.ObservedAt.Add(time.Second)
	if err := pg17JoinNativeProofs(b, g, guest, first, replay, proof.ReceiptRef); err != nil {
		t.Fatalf("valid join rejected: %v", err)
	}
	cases := map[string]func(*model.CapacityMutationBinding, *model.CapacityMutationGrant, *model.CapacityMutationProof, *pg17NativeProofReturn, *pg17NativeProofReturn){
		"binding profile": func(b *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, _ *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			b.ProfileName = "other"
		},
		"binding instance": func(b *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, _ *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			b.IntegrationInstanceID = "other"
		},
		"grant identity": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Grant.GrantID = "other"
		},
		"native resource": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.ResourceID = "other"
		},
		"replay creation": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, _ *pg17NativeProofReturn, r *pg17NativeProofReturn) {
			r.Proof.ObservedCreationGrantID = "other"
		},
		"action order": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.ActionIDs = []string{"action-b", "action-a"}
		},
		"action multiplicity": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.ActionIDs = []string{"action-a", "action-b", "action-b"}
		},
		"slot digest": func(b *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, _ *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			b.Slots = []model.CapacityMutationSlotBinding{{Slot: 2, DesiredSpecSHA256: "other"}}
		},
		"slot identity": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.Slot = 1
		},
		"native lifecycle": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.AWSInstanceLifecycle = &model.CapacityAWSInstanceLifecycle{Schema: "other"}
		},
		"native spec": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.SpecVerified = false
		},
		"native actions": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.ActionIDs = []string{"other"}
		},
		"replay action status": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, _ *pg17NativeProofReturn, r *pg17NativeProofReturn) {
			r.Proof.ActionsSuccessful = false
		},
		"guest receipt": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, p *model.CapacityMutationProof, _ *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			p.ReceiptRef = ""
		},
		"native receipt": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, f *pg17NativeProofReturn, _ *pg17NativeProofReturn) {
			f.Proof.ReceiptRef = "fake"
		},
		"useful claim": func(_ *model.CapacityMutationBinding, _ *model.CapacityMutationGrant, _ *model.CapacityMutationProof, _ *pg17NativeProofReturn, r *pg17NativeProofReturn) {
			r.UsefulCapacityKnown = true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bb, gg, p, f, r := b, g, guest, first, replay
			mutate(&bb, &gg, &p, &f, &r)
			if pg17JoinNativeProofs(bb, gg, p, f, r, proof.ReceiptRef) == nil {
				t.Fatal("mismatch accepted")
			}
		})
	}
}
