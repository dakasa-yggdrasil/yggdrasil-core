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
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Public approved fixtures and declared adapter returns only. No transport,
// Guest receipt, production approval or actual current S2 is supplied here.
func testOriginalGuestContractCollection(t *testing.T) {
	t.Helper()
	readPolicy := func(name string) model.CapacityPolicySpec {
		raw, err := os.ReadFile("../../internal/capacity/testdata/" + name + "-notify-hetzner-production-contract.json")
		if err != nil {
			t.Fatal(err)
		}
		var p model.CapacityPolicySpec
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("public policy")
		}
		return p
	}
	old, head := readPolicy("original"), readPolicy("b509")
	oldSHA := capacity.GuestProductionProfileContractSHA256(old, *old.GuestRetirementBinding, "hetzner")
	head.GuestContractSuccessor = &model.CapacityGuestContractSuccessor{Schema: capacity.GuestContractSuccessorSchema, RetainedPolicyContracts: []model.CapacityGuestRetainedPolicyContract{{PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("a", 64), ContractSHA256: oldSHA}}}
	view, err := capacity.GuestContractView(head, old)
	if err != nil {
		t.Fatal(err)
	}
	contracts := []model.CapacityPolicySpec{head, view}
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
		inv.Members = []model.CapacityVMFleetInventoryMember{{Slot: slot, DesiredSpec: *s.DesiredSpec, RequestSHA256: s.DesiredSpecSHA256, Server: model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: fmt.Sprint(800000 + slot), CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, Name: s.DesiredSpec.NativeName, Status: "off", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: map[string]string{"yggdrasil.io/owner": p.Owner, "yggdrasil.io/scope": label(b.ScopeChecksum), "yggdrasil.io/spec": label(s.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": fmt.Sprint(slot)}}}}
		for n := 1; n <= b.MaxSlots; n++ {
			if n != slot {
				inv.MissingSlots = append(inv.MissingSlots, n)
			}
		}
		return inv
	}
	currentInv, oldInv := inventory(head, 2), inventory(view, 1)
	policy := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "cohort-declared-read"}, Checksum: strings.Repeat("4", 64)}
	for _, fault := range []string{"complete", "missing_old_receipt", "duplicate_logical_slot", "foreign_supplier", "incomplete_reporting"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		calls := []string{}
		reader := func(binding model.CapacityObservationAdapterBinding, operation string, input map[string]any, out any) error {
			calls = append(calls, operation+":"+binding.IntegrationInstanceID)
			if operation == capacity.VMObserveInventory {
				if input["profile"] != head.Profiles[0].Name {
					t.Fatal("foreign profile read")
				}
				var inv model.CapacityVMFleetInventory
				switch binding.IntegrationInstanceID {
				case head.MutationBindings[0].IntegrationInstanceID:
					inv = currentInv
				case view.MutationBindings[0].IntegrationInstanceID:
					if fault == "missing_old_receipt" {
						return errors.New("declared supplier missing")
					}
					inv = oldInv
					if fault == "duplicate_logical_slot" {
						inv = inventory(view, 2)
					}
				default:
					t.Fatal("caller selected an undeclared inventory adapter")
				}
				if fault == "foreign_supplier" {
					inv.IntegrationInstanceID = uuid.NewString()
				}
				*(out.(*model.CapacityVMFleetInventory)) = inv
				return nil
			}
			cov := *head.GuestNotifyReconcileBinding.MemberCoverage
			selected := cov
			rule := model.CapacitySignalRule{Name: capacity.OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/hetzner/reporting-members", Unit: "members"}
			coverage := input["binding"] == cov.BindingName
			if !coverage {
				found := false
				for _, candidate := range head.GuestNotifyReconcileBinding.Signals {
					if candidate.BindingName == input["binding"] {
						selected = candidate
						for _, signal := range head.Signals {
							if signal.Name == candidate.Name {
								rule = signal
								found = true
							}
						}
					}
				}
				if !found {
					t.Fatal("unbound demand reader")
				}
			}
			if operation != capacity.ObserveMetricRange || !reflect.DeepEqual(binding, selected.Adapter) {
				t.Fatal("coverage/demand source escaped current policy")
			}
			n := float64(2)
			r := model.CapacityMetricRangeObservation{Operation: capacity.ObserveMetricRange, Binding: selected.BindingName, BindingSHA256: selected.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete", CapacityEvidence: model.CapacityEvidence{Name: rule.Name, SourceIdentity: rule.SourceIdentity, Unit: rule.Unit, RequireData: true, Matched: true, DataState: "present", Value: &n, RangeMin: &n, RangeMax: &n, Samples: capacity.OriginalGuestCoverageMinimumSamples, CoverageComplete: true, MaxGapSeconds: 1, SourceSampledAt: now, WindowStart: now.Add(-capacity.OriginalGuestCoverageMinimumWindow), WindowEnd: now}}
			if fault == "incomplete_reporting" && coverage {
				r.OK = false
				r.Reason = "no_data"
				r.DataState = "missing"
				r.Matched = false
				r.Value = nil
				r.RangeMin = nil
				r.RangeMax = nil
				r.Samples = 0
				r.CoverageComplete = false
			}
			*(out.(*model.CapacityMetricRangeObservation)) = r
			return nil
		}
		inventories, missing, assessment, _, e := collectOriginalGuestContractAssessmentFromReads(ctx, policy, head, contracts, reader)
		cancel()
		if fault != "complete" {
			if e == nil {
				t.Fatal("incomplete/ambiguous cohort became complete", fault)
			}
			continue
		}
		if e != nil || len(inventories) != 2 || assessment.Snapshot.Units != 2 || !reflect.DeepEqual(missing, []int{3, 4, 5, 6, 7, 8}) || len(calls) != 3+len(head.Signals) {
			t.Fatal("ordered full union collection", e, calls, missing)
		}
		if calls[0] != capacity.VMObserveInventory+":"+head.MutationBindings[0].IntegrationInstanceID || calls[1] != capacity.VMObserveInventory+":"+view.MutationBindings[0].IntegrationInstanceID {
			t.Fatal("retained contract read omitted or reordered", calls)
		}
		members := []repository.GuestNotifyFloorMember{{Slot: 1, PreregistrationID: "old-S1"}, {Slot: 2, PreregistrationID: "new-S2"}}
		mode, slot, _, e := originalGuestNextMissingSlot(head, missing, members, model.CapacityDecision{Action: "expand", Profile: head.Profiles[0].Name, Units: 3})
		if e != nil || mode != "provision" || slot != 3 {
			t.Fatal("head's missing S1 caused duplicate CREATE", mode, slot, e)
		}
		mode, slot, pre, e := originalGuestNextMissingSlot(head, missing, members, model.CapacityDecision{Action: "drain", Profile: head.Profiles[0].Name, Units: 1})
		if e != nil || mode != "retire" || slot != 2 || pre != "new-S2" {
			t.Fatal("retire lost exact retained member identity", mode, slot, pre, e)
		}
	}
}
