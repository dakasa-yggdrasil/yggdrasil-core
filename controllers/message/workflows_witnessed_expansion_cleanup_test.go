//go:build !nativequalification

package message

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Attached to the existing supplier root: declared native DTOs, no provider,
// Guest, transport or production evidence and no new root/subtest census.
func testWitnessedExpansionContractCollection(t *testing.T) {
	t.Helper()
	readPolicy := func(name string) model.CapacityPolicySpec {
		raw, err := os.ReadFile("../../internal/capacity/testdata/" + name + "-notify-hetzner-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		var p model.CapacityPolicySpec
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("declared policy")
		}
		return p
	}
	old, head := readPolicy("original"), readPolicy("b509")
	head.GuestContractSuccessor = &model.CapacityGuestContractSuccessor{Schema: capacity.GuestContractSuccessorSchema, RetainedPolicyContracts: []model.CapacityGuestRetainedPolicyContract{{PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("a", 64), ContractSHA256: capacity.GuestProductionProfileContractSHA256(old, *old.GuestRetirementBinding, "hetzner")}}}
	view, err := capacity.GuestContractView(head, old)
	if err != nil {
		t.Fatal(err)
	}
	policy := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Checksum: strings.Repeat("4", 64), Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "declared-cleanup-cohorts"}}
	now := time.Now().UTC()
	label := func(s string) string {
		raw, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	}
	inventory := func(p model.CapacityPolicySpec, slot int) model.CapacityVMFleetInventory {
		b := p.MutationBindings[0]
		s := b.Slots[slot-1]
		inv := model.CapacityVMFleetInventory{IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: s.DesiredSpec.ProfileChecksum, AdmissionChecksum: s.DesiredSpec.AdmissionChecksum, ProfileName: b.ProfileName, ProtectedSlots: b.ProtectedSlots, MaxSlots: b.MaxSlots, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano)}
		inv.Members = []model.CapacityVMFleetInventoryMember{{Slot: slot, Protected: slot <= b.ProtectedSlots, DesiredSpec: *s.DesiredSpec, RequestSHA256: s.DesiredSpecSHA256, Server: model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: fmt.Sprint(800000 + slot), CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, Name: s.DesiredSpec.NativeName, Status: "running", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: map[string]string{"yggdrasil.io/owner": p.Owner, "yggdrasil.io/scope": label(b.ScopeChecksum), "yggdrasil.io/spec": label(s.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": fmt.Sprint(slot)}}}}
		for n := 1; n <= b.MaxSlots; n++ {
			if n != slot {
				inv.MissingSlots = append(inv.MissingSlots, n)
			}
		}
		return inv
	}
	for _, fault := range []string{"complete", "target_absent", "missing_old", "missing_current", "duplicate_slot", "foreign_instance", "wrong_scope", "stale", "incomplete_partition", "expired_context"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		current, prior := inventory(head, 2), inventory(view, 1)
		if fault == "target_absent" {
			current.Members = nil
			current.MissingSlots = []int{1, 2, 3, 4, 5, 6, 7, 8}
		}
		calls := []string{}
		reader := func(b model.CapacityObservationAdapterBinding, op string, input map[string]any, out any) error {
			calls = append(calls, b.IntegrationInstanceID)
			if op != capacity.VMObserveInventory || !reflect.DeepEqual(input, map[string]any{"profile": head.Profiles[0].Name}) {
				t.Fatal("cleanup collector requested non-inventory authority")
			}
			var inv model.CapacityVMFleetInventory
			switch b.IntegrationInstanceID {
			case head.MutationBindings[0].IntegrationInstanceID:
				if fault == "missing_current" {
					return errors.New("declared missing current")
				}
				inv = current
			case view.MutationBindings[0].IntegrationInstanceID:
				if fault == "missing_old" {
					return errors.New("declared missing retained")
				}
				inv = prior
				if fault == "duplicate_slot" {
					inv = inventory(view, 2)
				}
			default:
				t.Fatal("undeclared adapter")
			}
			if fault == "foreign_instance" {
				inv.IntegrationInstanceID = uuid.NewString()
			}
			if fault == "wrong_scope" {
				inv.ScopeChecksum = strings.Repeat("f", 64)
			}
			if fault == "stale" {
				inv.ObservedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			}
			if fault == "incomplete_partition" {
				inv.MissingSlots = nil
			}
			if fault == "expired_context" {
				cancel()
			}
			*(out.(*model.CapacityVMFleetInventory)) = inv
			return nil
		}
		got, e := collectWitnessedExpansionContractInventoriesFromReads(ctx, policy, head, []model.CapacityPolicySpec{head, view}, reader)
		cancel()
		if fault != "complete" && fault != "target_absent" {
			if e == nil {
				t.Fatal("incomplete cohort became physical refresh", fault)
			}
			continue
		}
		if e != nil || len(got) != 2 || len(calls) != 2 || calls[0] != current.IntegrationInstanceID || calls[1] != prior.IntegrationInstanceID || !reflect.DeepEqual(got[0].Inventory, current) || !reflect.DeepEqual(got[1].Inventory, prior) {
			t.Fatal("cleanup did not preserve both exact original inventories/timestamps", fault, e, calls)
		}
	}
}
