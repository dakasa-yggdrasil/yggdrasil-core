package capacity

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestSlotBootstrapSelectsOnlyExactPrivateTemplate(t *testing.T) {
	for _, kind := range []string{"slot_one", "slot_two", "missing_slot", "mixed_legacy", "empty_map", "unsorted", "duplicate_slot", "duplicate_hash", "wrong_hash", "out_of_range"} {
		t.Run(kind, func(t *testing.T) {
			one, two := strings.Repeat("a", 64), strings.Repeat("b", 64)
			profile := model.CapacityGuestProtectedProfileManifest{SlotBootstraps: []model.CapacityGuestSlotBootstrap{{Slot: 1, BootstrapSHA256: one}, {Slot: 2, BootstrapSHA256: two}}}
			slot, want := 1, one
			switch kind {
			case "slot_two":
				slot, want = 2, two
			case "missing_slot":
				slot, want = 3, ""
			case "mixed_legacy":
				profile.BootstrapSHA256 = one
				want = ""
			case "empty_map":
				profile.SlotBootstraps = []model.CapacityGuestSlotBootstrap{}
				want = ""
			case "unsorted":
				profile.SlotBootstraps[0], profile.SlotBootstraps[1] = profile.SlotBootstraps[1], profile.SlotBootstraps[0]
				want = ""
			case "duplicate_slot":
				profile.SlotBootstraps[1].Slot = 1
				want = ""
			case "duplicate_hash":
				profile.SlotBootstraps[1].BootstrapSHA256 = one
				want = ""
			case "wrong_hash":
				profile.SlotBootstraps[1].BootstrapSHA256 = "caller-template"
				want = ""
			case "out_of_range":
				profile.SlotBootstraps[1].Slot = 65
				want = ""
			}
			if got := GuestProfileBootstrapSHA(profile, slot); got != want {
				t.Fatal("foreign/invalid template selected or fallback allowed", got)
			}
		})
	}
}

func TestGuestSlotBootstrapPinsFullMemberAndSourceContract(t *testing.T) {
	for _, kind := range []string{"exact", "missing_member", "foreign_slot", "slot_desired_mismatch", "qualification", "changed_source_map"} {
		t.Run(kind, func(t *testing.T) {
			p, b, _, _ := guestProductionRegistryFixture(t)
			b.ProfileManifest.BootstrapSHA256 = ""
			b.ProfileManifest.SlotBootstraps = []model.CapacityGuestSlotBootstrap{{Slot: 1, BootstrapSHA256: strings.Repeat("a", 64)}}
			p.MutationBindings[0].Slots[0].DesiredSpec.BootstrapSHA256 = b.ProfileManifest.SlotBootstraps[0].BootstrapSHA256
			b.ProfileManifestSHA256 = GuestRetirementSHA(b.ProfileManifest)
			p.GuestRetirementBinding = &b
			before := GuestProductionProfileContractSHA256(p, b, "fixture")
			if !ValidDigest(before) {
				t.Fatal("closed exact per-member source map refused")
			}
			switch kind {
			case "missing_member":
				b.Members = append(b.Members, b.Members[0])
				b.Members[1].Slot = 2
				b.Members[1].Name = "other"
			case "foreign_slot":
				b.ProfileManifest.SlotBootstraps[0].Slot = 2
			case "slot_desired_mismatch":
				p.MutationBindings[0].Slots[0].DesiredSpec.BootstrapSHA256 = strings.Repeat("b", 64)
			case "qualification":
				b.EvidenceClass = "native_qemu_qualification"
			case "changed_source_map":
				b.ProfileManifest.SlotBootstraps[0].BootstrapSHA256 = strings.Repeat("c", 64)
				p.MutationBindings[0].Slots[0].DesiredSpec.BootstrapSHA256 = b.ProfileManifest.SlotBootstraps[0].BootstrapSHA256
			}
			b.ProfileManifestSHA256 = GuestRetirementSHA(b.ProfileManifest)
			p.GuestRetirementBinding = &b
			if kind == "changed_source_map" {
				after := GuestProductionProfileContractSHA256(p, b, "fixture")
				if !ValidDigest(after) || after == before {
					t.Fatal("whole slot map escaped source contract")
				}
				return
			}
			if (ValidateGuestRetirementBinding(p, &b) == nil) != (kind == "exact") {
				t.Fatal("slot desired/provider/enrollment profile disagreement admitted")
			}
		})
	}
}

func TestGuestSlotBootstrapKeepsLegacyWireAndPayload(t *testing.T) {
	_, b, _, _ := guestProductionRegistryFixture(t)
	profile := b.ProfileManifest
	raw, _ := json.Marshal(profile)
	if bytes.Contains(raw, []byte("slot_bootstraps")) || GuestProfileBootstrapSHA(profile, 1) != profile.BootstrapSHA256 {
		t.Fatal("legacy wire or fixed selection changed")
	}
	originalPayload := profile.BootstrapPayloadSHA256
	profile.BootstrapSHA256 = ""
	profile.SlotBootstraps = []model.CapacityGuestSlotBootstrap{{Slot: 1, BootstrapSHA256: strings.Repeat("a", 64)}}
	raw, _ = json.Marshal(profile)
	if !bytes.Contains(raw, []byte(`"slot_bootstraps":[{"slot":1,"bootstrap_sha256":`)) || profile.BootstrapPayloadSHA256 != originalPayload {
		t.Fatal("slot user-data changed the fixed executable payload contract")
	}
}
