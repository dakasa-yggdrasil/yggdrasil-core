//go:build linux && nativequalification

package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Synthetic byte vectors exercise the join only. They cannot attest a QEMU.
func TestPostlossConfirmationBindsOriginalAndFresh(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	creator, _ := json.Marshal(map[string]any{"resource_id": "11111111-1111-4111-8111-111111111111", "slot": 1, "original_create_returned_at": now.Add(-10 * time.Second)})
	proc := GuestNativeQEMUProcess{PID: 111, PPID: 1, StartTicks: 10, StatSHA256: strings.Repeat("a", 64)}
	orig := postlossConfirmRead{Schema: "core_independent_original_qemu_read_v1", CreatorSHA: strings.Repeat("b", 64), Original: creator, Before: proc, After: proc, Peer: 111, Executable: strings.Repeat("c", 64), CommandLine: strings.Repeat("d", 64), Disk: json.RawMessage(`{"device":1,"inode":2}`), DiskFD: 5, Started: now.Add(-9 * time.Second), Read: now.Add(-8 * time.Second), Closed: now.Add(-7 * time.Second)}
	orig.UUID.UUID = "11111111-1111-4111-8111-111111111111"
	orig.Status.Running = true
	orig.Status.Status = "running"
	fresh := orig
	fresh.Started = now.Add(-4 * time.Second)
	fresh.DiskRead = now.Add(-3 * time.Second)
	fresh.DiskClose = now.Add(-2 * time.Second)
	fresh.Read = now.Add(-time.Second)
	fresh.Closed = now
	witness := model.CapacityGuestOriginalCreateWitness{Tuple: model.CapacityGuestNativeTuple{ResourceID: orig.UUID.UUID, Slot: 1, CreatedAt: now.Add(-10 * time.Second).Format(time.RFC3339Nano)}, OriginalDeadline: now.Add(time.Minute), SourceObservation: &model.CapacityGuestPostlossObservation{OriginalCreatorSHA256: orig.CreatorSHA}}
	receipt := model.CapacityGuestOriginalProvisioningReceipt{RecordedAt: now.Add(-5 * time.Second)}
	grant := model.CapacityMutationGrant{GrantID: "grant", BindingName: "binding", Slot: 1, RequestSHA256: strings.Repeat("e", 64)}
	run := func(o, f postlossConfirmRead, w model.CapacityGuestOriginalCreateWitness, r model.CapacityGuestOriginalProvisioningReceipt, change func(*model.CapacityMutationProof), observed time.Time) bool {
		ow, _ := json.Marshal(o)
		fw, _ := json.Marshal(f)
		proof := model.CapacityMutationProof{GrantID: grant.GrantID, BindingName: grant.BindingName, Slot: grant.Slot, ResourceID: witness.Tuple.ResourceID, ResourceCreatedAt: witness.Tuple.CreatedAt, RequestSHA256: grant.RequestSHA256, ObservedAt: fresh.Closed, ReceiptRef: "original-native-qemu-enrollment-confirm:" + capacity.BusinessCreationSHA256(fw), OwnerVerified: true, SpecVerified: true, ActionIDs: []string{"qemu-original-create:" + capacity.BusinessCreationSHA256(creator)}, ActionsTerminal: true, ActionsSuccessful: true, ObservedCreationGrantID: grant.GrantID}
		if change != nil {
			change(&proof)
		}
		return postlossConfirmationJoin(ow, fw, w, r, grant, proof, observed)
	}
	if !run(orig, fresh, witness, receipt, nil, now) {
		t.Fatal("valid synthetic join refused")
	}
	for _, tc := range []struct {
		name   string
		change func(*postlossConfirmRead, *model.CapacityGuestOriginalCreateWitness, *model.CapacityGuestOriginalProvisioningReceipt, *model.CapacityMutationProof)
	}{
		{"foreign_resource", func(_ *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, p *model.CapacityMutationProof) {
			p.ResourceID = "foreign"
		}},
		{"foreign_epoch", func(_ *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, p *model.CapacityMutationProof) {
			p.ResourceCreatedAt = "2026-01-01T00:00:00Z"
		}},
		{"foreign_action", func(_ *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, p *model.CapacityMutationProof) {
			p.ActionIDs = []string{"foreign"}
		}},
		{"foreign_grant", func(_ *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, p *model.CapacityMutationProof) {
			p.GrantID = "foreign"
		}},
		{"foreign_request", func(_ *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, p *model.CapacityMutationProof) {
			p.RequestSHA256 = strings.Repeat("0", 64)
		}},
		{"false_owner", func(_ *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, p *model.CapacityMutationProof) {
			p.OwnerVerified = false
		}},
		{"foreign_process", func(f *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			f.After.StartTicks++
		}},
		{"foreign_peer", func(f *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			f.Peer++
		}},
		{"foreign_disk", func(f *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			f.Disk = json.RawMessage(`{"device":1,"inode":3}`)
		}},
		{"foreign_creator", func(f *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			f.CreatorSHA = strings.Repeat("f", 64)
		}},
		{"not_running", func(f *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			f.Status.Running = false
		}},
		{"read_before_receipt", func(f *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, r *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			r.RecordedAt = f.Started.Add(time.Second)
		}},
		{"reordered_close", func(f *postlossConfirmRead, _ *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			f.Closed = f.Read.Add(-time.Second)
		}},
		{"foreign_witness_creator", func(_ *postlossConfirmRead, w *model.CapacityGuestOriginalCreateWitness, _ *model.CapacityGuestOriginalProvisioningReceipt, _ *model.CapacityMutationProof) {
			x := *w.SourceObservation
			x.OriginalCreatorSHA256 = strings.Repeat("9", 64)
			w.SourceObservation = &x
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, w, r := fresh, witness, receipt
			var p model.CapacityMutationProof
			tc.change(&f, &w, &r, &p)
			if run(orig, f, w, r, func(v *model.CapacityMutationProof) {
				if p.GrantID != "" {
					v.GrantID = p.GrantID
				}
				if p.ResourceID != "" {
					v.ResourceID = p.ResourceID
				}
				if p.ResourceCreatedAt != "" {
					v.ResourceCreatedAt = p.ResourceCreatedAt
				}
				if p.RequestSHA256 != "" {
					v.RequestSHA256 = p.RequestSHA256
				}
				if p.ActionIDs != nil {
					v.ActionIDs = p.ActionIDs
				}
				if tc.name == "false_owner" {
					v.OwnerVerified = false
				}
			}, now) {
				t.Fatal("foreign or incomplete join accepted")
			}
		})
	}
	if run(orig, fresh, witness, receipt, nil, now.Add(time.Minute)) {
		t.Fatal("stale read accepted")
	}
}
