//go:build nativequalification

package message

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type pg17NativeProofReturn struct {
	Grant               model.CapacityMutationGrant `json:"grant"`
	Proof               model.CapacityMutationProof `json:"mutation_proof"`
	UsefulCapacityKnown bool                        `json:"useful_capacity_known"`
}

// This qualification-only join compares independent observations; it never
// creates authority. The caller must retain both actual handler returns and
// separately retains the original enrollment confirmation lineage.
func pg17JoinNativeProofs(b model.CapacityMutationBinding, g model.CapacityMutationGrant, guest model.CapacityMutationProof, first, replay pg17NativeProofReturn, expectedNativeReceipt string) error {
	bad := errors.New("native qualification proof identity mismatch")
	if g.State != "issued" || g.GrantID == "" || g.RequestSHA256 == "" || g.BindingName == "" || g.BindingName != b.Name || g.IntegrationInstanceID == "" || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum == "" || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName == "" || g.ProfileName != b.ProfileName || g.Capability != b.EnsureCapability || g.Slot < 1 || g.CompensationOf != "" || first.UsefulCapacityKnown || replay.UsefulCapacityKnown {
		return bad
	}
	matchedSlot := false
	for _, slot := range b.Slots {
		if slot.Slot == g.Slot && slot.DesiredSpecSHA256 == g.RequestSHA256 {
			if matchedSlot {
				return bad
			}
			matchedSlot = true
		}
	}
	if !matchedSlot {
		return bad
	}
	expected := g
	expected.State = "confirmed"
	want, err := json.Marshal(expected)
	firstGrant, firstErr := json.Marshal(first.Grant)
	replayGrant, replayErr := json.Marshal(replay.Grant)
	if err != nil || firstErr != nil || replayErr != nil || !bytes.Equal(firstGrant, want) || !bytes.Equal(replayGrant, want) {
		return bad
	}
	if guest.GrantID != g.GrantID || guest.BindingName != g.BindingName || guest.Slot != g.Slot || guest.RequestSHA256 != g.RequestSHA256 || guest.ObservedCreationGrantID != g.GrantID || guest.ResourceID == "" || guest.ResourceCreatedAt == "" || guest.ObservedAt.IsZero() || !strings.HasPrefix(guest.ReceiptRef, "original-native-qemu-enrollment-confirm:") || !guest.OwnerVerified || !guest.SpecVerified || guest.ResourceAbsent || !guest.ActionsTerminal || !guest.ActionsSuccessful || len(guest.ActionIDs) == 0 {
		return bad
	}
	ids := map[string]bool{}
	for _, id := range guest.ActionIDs {
		if id == "" || ids[id] {
			return bad
		}
		ids[id] = true
	}
	for _, native := range []model.CapacityMutationProof{first.Proof, replay.Proof} {
		if native.ObservedAt.IsZero() || expectedNativeReceipt == "" || native.ReceiptRef != expectedNativeReceipt || native.ReceiptRef == guest.ReceiptRef {
			return bad
		}
		// Only the observation time and source receipt may differ. This also
		// rejects missing, extra or reordered actions and all lifecycle fields.
		n, source := native, guest
		n.ObservedAt, source.ObservedAt = time.Time{}, time.Time{}
		n.ReceiptRef, source.ReceiptRef = "", ""
		if !reflect.DeepEqual(n, source) {
			return bad
		}
	}
	if first.Proof.ReceiptRef != replay.Proof.ReceiptRef {
		return bad
	}
	return nil
}
