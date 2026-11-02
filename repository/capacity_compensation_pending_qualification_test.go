//go:build linux && nativequalification

package repository

import (
	"context"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Synthetic records exercise the parent join only. They cannot attest a QEMU.
func TestCanonicalCompensationPendingParentFailsClosed(t *testing.T) {
	for c, want := range map[string]bool{"canonical_compensation_unprotected_failed_create": true, "canonical_compensation_protected_failed_create": true, "canonical_failed_floor_recovery": true, "compensation_unprotected_failed_create": true, "compensation_protected_failed_create": true, "source_live_failed_floor_recovery": true, "canonical_postloss_unprotected_failed_create_reissue": false, "": false} {
		if canonicalCompensationPendingCase(c) != want {
			t.Fatalf("case %q selection changed", c)
		}
	}
	policy := model.Manifest{ID: uuid.New(), Checksum: strings.Repeat("a", 64)}
	workflow := uuid.New()
	grant := model.CapacityMutationGrant{GrantID: uuid.NewString(), Slot: 2, State: "redeemed", RequestSHA256: strings.Repeat("b", 64)}
	proof := model.CapacityMutationProof{GrantID: grant.GrantID, Slot: 2, ResourceID: uuid.NewString(), ResourceCreatedAt: "2026-10-29T00:00:00.123456789Z", ActionIDs: []string{"qemu-original-create:" + strings.Repeat("c", 64)}, ObservedCreationGrantID: grant.GrantID}
	base := func() capacityMutationRecord {
		settled := grant
		settled.State = "settled"
		return capacityMutationRecord{Grant: settled, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: workflow, Settlement: &model.CapacityMutationSettleRequest{GrantID: grant.GrantID, Outcome: "accepted", TransportCompleted: true, ResourceID: proof.ResourceID, ResourceCreatedAt: proof.ResourceCreatedAt, ActionID: proof.ActionIDs[0]}}
	}
	if !canonicalCompensationPendingParent(base(), grant, policy, workflow, proof) {
		t.Fatal("exact settled accepted parent refused")
	}
	for name, change := range map[string]func(*capacityMutationRecord, *model.CapacityMutationProof){
		"confirmed":  func(r *capacityMutationRecord, _ *model.CapacityMutationProof) { r.Grant.State = "confirmed" },
		"registered": func(r *capacityMutationRecord, p *model.CapacityMutationProof) { q := *p; r.Proof = &q },
		"compensation": func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.Grant.CompensationOf = uuid.NewString()
		},
		"uncertain": func(r *capacityMutationRecord, _ *model.CapacityMutationProof) { r.Settlement.Outcome = "uncertain" },
		"no_transport": func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.Settlement.TransportCompleted = false
		},
		"no_settlement": func(r *capacityMutationRecord, _ *model.CapacityMutationProof) { r.Settlement = nil },
		"resource":      func(_ *capacityMutationRecord, p *model.CapacityMutationProof) { p.ResourceID = uuid.NewString() },
		"created_at": func(_ *capacityMutationRecord, p *model.CapacityMutationProof) {
			p.ResourceCreatedAt = "2026-10-29T00:00:01Z"
		},
		"action":         func(r *capacityMutationRecord, _ *model.CapacityMutationProof) { r.Settlement.ActionID = "other" },
		"proof_grant":    func(_ *capacityMutationRecord, p *model.CapacityMutationProof) { p.GrantID = uuid.NewString() },
		"proof_slot":     func(_ *capacityMutationRecord, p *model.CapacityMutationProof) { p.Slot = 1 },
		"observed_grant": func(_ *capacityMutationRecord, p *model.CapacityMutationProof) { p.ObservedCreationGrantID = "" },
		"policy": func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.PolicyChecksum = strings.Repeat("d", 64)
		},
		"workflow": func(r *capacityMutationRecord, _ *model.CapacityMutationProof) { r.WorkflowID = uuid.New() },
		"grant_body": func(r *capacityMutationRecord, _ *model.CapacityMutationProof) {
			r.Grant.RequestSHA256 = strings.Repeat("e", 64)
		},
	} {
		record, p := base(), proof
		change(&record, &p)
		if canonicalCompensationPendingParent(record, grant, policy, workflow, p) {
			t.Fatalf("%s parent accepted", name)
		}
	}
}

// Selection fails before touching the store for every wrong slot and the
// separate lost-reply/positive paths.
func TestSourceFailedCreatePendingScope(t *testing.T) {
	store := CapacityStore{}
	for _, tc := range []struct {
		name string
		slot int
	}{
		{"compensation_unprotected_failed_create", 1},
		{"compensation_protected_failed_create", 1},
		{"source_live_failed_floor_recovery", 1},
		{"compensation_unprotected_lost_create_reply", 2},
		{"compensation_protected_lost_create_reply", 2},
		{"positive_original_lifecycle", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := model.CapacityMutationGrant{GrantID: uuid.NewString(), Slot: tc.slot}
			proof := model.CapacityMutationProof{GrantID: grant.GrantID}
			if err := store.VerifyCanonicalCompensationPending(context.Background(), model.Manifest{}, model.CapacityPolicySpec{}, tc.name, grant, proof); err != ErrCapacityConflict {
				t.Fatalf("out-of-scope case or slot accepted: %v", err)
			}
		})
	}
}
