package repository

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These are declared DTO operands. No provider, DB, guest or production
// authority is claimed by this unit fixture.
func witnessedPredelete107Unit(t *testing.T) (model.CapacityPolicySpec, WitnessedUnenrolledExpansionCleanup, []WitnessedUnenrolledExpansionCleanupEvent, time.Time) {
	t.Helper()
	wire, err := os.ReadFile("../internal/capacity/testdata/b509-notify-hetzner-production-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if err = json.Unmarshal(wire, &p); err != nil || len(p.MutationBindings) == 0 {
		t.Fatal("declared source policy fixture", err)
	}
	base := time.Date(2026, 11, 15, 14, 43, 0, 0, time.UTC)
	a := WitnessedUnenrolledExpansionCleanup{Schema: WitnessedUnenrolledExpansionCleanupSchema, ID: "10000000-0000-4000-8000-000000000001", GrantID: "10000000-0000-4000-8000-000000000002", ChildGrantID: "10000000-0000-4000-8000-000000000003", BindingName: p.MutationBindings[0].Name, Slot: 2, ResourceID: "176114473", ResourceCreatedAt: "2026-11-14T15:45:13Z", OriginalAuxiliaryKnown: true}
	parent := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: a.GrantID, State: "settled"}, Settlement: &model.CapacityMutationSettleRequest{GrantID: a.GrantID, Outcome: "accepted", TransportCompleted: true, ResourceID: a.ResourceID, ResourceCreatedAt: a.ResourceCreatedAt, AuxiliaryInventoryComplete: true, AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "162672122", RequiresAbsence: true}}}}
	a.OriginalGrantWire = witnessedPredelete107Wire(t, parent)
	lease := base.Add(time.Minute)
	claim := WitnessedUnenrolledExpansionCleanupEvent{Schema: WitnessedUnenrolledExpansionCleanupSchema, CleanupID: a.ID, Sequence: 2, Stage: "claimed", RunID: "10000000-0000-4000-8000-000000000004", Generation: 11, FencingToken: 26, LeaseOwner: "10000000-0000-4000-8000-000000000005", ExecutorID: "10000000-0000-4000-8000-000000000006", LeaseExpiresAt: &lease, ChildGrantID: a.ChildGrantID, RecordedAt: base}
	read := WitnessedExpansionRead{Schema: "witnessed_unenrolled_expansion_native_read_v1", ReadID: "10000000-0000-4000-8000-000000000007", CleanupID: a.ID, Kind: "inventory", ClaimSequence: claim.Sequence, AdmissionSHA256: originalDispositionDigest(witnessedPredelete107Wire(t, a)), ChildGrantID: a.ChildGrantID, IssuedAtCore: base.Add(time.Second), OriginalDeadlineCore: base.Add(6 * time.Second)}
	plan, err := witnessedExpansionDestroyPlan(p, a)
	if err != nil {
		t.Fatal("exact declared destroy projection", err)
	}
	var desired model.CapacityMutationSpecV1
	if err = json.Unmarshal(plan.CanonicalSpec, &desired); err != nil {
		t.Fatal(err)
	}
	server := &model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: a.ResourceID, CreatedAt: a.ResourceCreatedAt}, PrimaryIPv4ID: "162672122", IndependentBillableResources: true, AuxiliaryInventoryComplete: true, PhysicalSpecVerified: true, Labels: map[string]string{"yggdrasil.io/intent": a.GrantID}}
	raw := WitnessedExpansionReadReturn{Schema: "witnessed_unenrolled_expansion_native_return_v1", Read: read, ReadWire: witnessedPredelete107Wire(t, read), Status: "dry_run", Plan: &model.CapacityVMFleetPlan{DesiredSpec: desired, RequestSHA256: plan.RequestSHA256, Server: server}, StartedAtCore: base.Add(time.Second + time.Millisecond), ReturnedAtCore: base.Add(time.Second + 2*time.Millisecond)}
	prepared, returned := claim, claim
	prepared.Stage, prepared.Sequence, prepared.RecordedAt, prepared.Evidence = "inventory_prepared", 3, base.Add(500*time.Millisecond), witnessedPredelete107Wire(t, read)
	returned.Stage, returned.Sequence, returned.RecordedAt, returned.Evidence = "inventory_returned", 4, base.Add(time.Second+3*time.Millisecond), witnessedPredelete107Wire(t, raw)
	requested := WitnessedUnenrolledExpansionCleanupEvent{Schema: WitnessedUnenrolledExpansionCleanupSchema, CleanupID: a.ID, Sequence: 1, Stage: "requested", ChildGrantID: a.ChildGrantID, RecordedAt: base.Add(-time.Second)}
	return p, a, []WitnessedUnenrolledExpansionCleanupEvent{requested, claim, prepared, returned}, base.Add(10 * time.Minute)
}

func witnessedPredelete107Wire(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func witnessedPredelete107Raw(t *testing.T, events []WitnessedUnenrolledExpansionCleanupEvent) WitnessedExpansionReadReturn {
	t.Helper()
	var r WitnessedExpansionReadReturn
	if err := json.Unmarshal(events[len(events)-1].Evidence, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestWitnessedExpansionInventoryAcceptsOnlyOriginalAttachedPrimaryIPs(t *testing.T) {
	for _, two := range []bool{false, true} {
		p, a, events, _ := witnessedPredelete107Unit(t)
		r := witnessedPredelete107Raw(t, events)
		if two {
			var parent capacityMutationRecord
			if err := json.Unmarshal(a.OriginalGrantWire, &parent); err != nil {
				t.Fatal(err)
			}
			parent.Settlement.AuxiliaryResources = append(parent.Settlement.AuxiliaryResources, model.CapacityMutationAuxiliaryResource{Kind: "primary_ip", ID: "162672123", RequiresAbsence: true})
			a.OriginalGrantWire = witnessedPredelete107Wire(t, parent)
			r.Plan.Server.PrimaryIPv6ID = "162672123"
			r.Read.AdmissionSHA256 = originalDispositionDigest(witnessedPredelete107Wire(t, a))
			r.ReadWire = witnessedPredelete107Wire(t, r.Read)
		}
		if _, pending, err := witnessedExpansionReadContent(r, p, a); err != nil || pending {
			t.Fatal("the original CREATE's exact attached paid IPs were rejected", two, err)
		}
	}
	for name, mutate := range map[string]func(*WitnessedExpansionReadReturn, *capacityMutationRecord, *WitnessedUnenrolledExpansionCleanup){
		"different_attached_ip": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.Server.PrimaryIPv4ID = "162672999"
		},
		"missing_attached_ip": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.Server.PrimaryIPv4ID = ""
			r.Plan.Server.IndependentBillableResources = false
		},
		"unknown_second_ip": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.Server.PrimaryIPv6ID = "162672999"
		},
		"duplicate_attached_ip": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.Server.PrimaryIPv6ID = r.Plan.Server.PrimaryIPv4ID
		},
		"billable_flag_inconsistent": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.Server.IndependentBillableResources = false
		},
		"unknown_auxiliary": func(_ *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources[0].Kind = "volume"
		},
		"duplicate_original_ip": func(_ *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources = append(p.Settlement.AuxiliaryResources, p.Settlement.AuxiliaryResources[0])
		},
		"absence_not_required": func(_ *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources[0].RequiresAbsence = false
		},
		"missing_original_inventory": func(_ *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources = nil
		},
		"incomplete_original": func(_ *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryInventoryComplete = false
		},
		"unknown_admission_auxiliary": func(_ *WitnessedExpansionReadReturn, _ *capacityMutationRecord, a *WitnessedUnenrolledExpansionCleanup) {
			a.OriginalAuxiliaryKnown = false
		},
		"foreign_original_grant": func(_ *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Grant.GrantID = "10000000-0000-4000-8000-000000000099"
		},
		"protected_server": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.Server.ProtectedFromDelete = true
		},
		"incomplete_observation": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.Server.AuxiliaryInventoryComplete = false
		},
		"extra_plan_auxiliary": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Plan.AuxiliaryResources = []model.CapacityVMAuxiliaryObservation{{Kind: "volume", ID: "99"}}
		},
		"noncanonical_primary_ip": func(r *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources[0].ID, r.Plan.Server.PrimaryIPv4ID = "01", "01"
		},
		"overflow_primary_ip": func(r *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources[0].ID, r.Plan.Server.PrimaryIPv4ID = "9223372036854775808", "9223372036854775808"
		},
		"zero_primary_ip": func(r *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources[0].ID, r.Plan.Server.PrimaryIPv4ID = "0", "0"
		},
		"signed_primary_ip": func(r *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources[0].ID, r.Plan.Server.PrimaryIPv4ID = "+1", "+1"
		},
		"negative_primary_ip": func(r *WitnessedExpansionReadReturn, p *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			p.Settlement.AuxiliaryResources[0].ID, r.Plan.Server.PrimaryIPv4ID = "-1", "-1"
		},
		"pending_inventory": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Pending = true
		},
		"complete_inventory": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Complete = true
		},
		"inventory_receipt": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Receipt = &model.CapacityMutationReceipt{}
		},
		"inventory_receipt_wire": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.ReceiptWire = []byte("{}")
		},
		"inventory_absence_observation": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.Observation = &model.CapacityVMRetirementObservation{}
		},
		"inventory_observer_source": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.ObserverSourceCommit = "1000000000000000000000000000000000000001"
		},
		"inventory_observer_return": func(r *WitnessedExpansionReadReturn, _ *capacityMutationRecord, _ *WitnessedUnenrolledExpansionCleanup) {
			r.OriginalObserverReturn = []byte("{}")
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, a, events, _ := witnessedPredelete107Unit(t)
			r := witnessedPredelete107Raw(t, events)
			var parent capacityMutationRecord
			if err := json.Unmarshal(a.OriginalGrantWire, &parent); err != nil {
				t.Fatal(err)
			}
			mutate(&r, &parent, &a)
			a.OriginalGrantWire = witnessedPredelete107Wire(t, parent)
			r.Read.AdmissionSHA256 = originalDispositionDigest(witnessedPredelete107Wire(t, a))
			r.ReadWire = witnessedPredelete107Wire(t, r.Read)
			if _, _, err := witnessedExpansionReadContent(r, p, a); err == nil {
				t.Fatal("unknown, incomplete or different paid inventory became DELETE eligibility")
			}
		})
	}
}

func TestWitnessedExpansionPredeleteContinuationRequiresExactOnTimeOriginalRead(t *testing.T) {
	p, a, events, now := witnessedPredelete107Unit(t)
	if !witnessedExpansionPredeleteReturnContinuation(events, events[1], a, p, now) {
		t.Fatal("closed original on-time inventory suffix should permit only a fresh read")
	}
	if witnessedExpansionPredeleteReturnContinuation(events, events[1], a, p, *events[1].LeaseExpiresAt) {
		t.Fatal("unexpired old owner enabled a successor")
	}
	for _, name := range []string{"failed", "original_context_failed", "deadline_return", "foreign_paid_ip", "wrong_read_id", "read_wire_changed", "pending", "receipt", "wrong_kind", "wrong_claim", "preparation_after_issue", "outside_lease"} {
		t.Run(name, func(t *testing.T) {
			p, a, events, now := witnessedPredelete107Unit(t)
			r := witnessedPredelete107Raw(t, events)
			switch name {
			case "failed":
				r.CallFailed = true
			case "original_context_failed":
				r.OriginalContextFailed = true
			case "deadline_return":
				r.ReturnedAtCore = r.Read.OriginalDeadlineCore
				events[3].RecordedAt = r.ReturnedAtCore.Add(time.Millisecond)
			case "foreign_paid_ip":
				r.Plan.Server.PrimaryIPv4ID = "162672999"
			case "wrong_read_id":
				r.Read.ReadID = "10000000-0000-4000-8000-000000000099"
			case "read_wire_changed":
				r.ReadWire = append(r.ReadWire, '\n')
			case "pending":
				r.Pending = true
			case "receipt":
				r.Receipt = &model.CapacityMutationReceipt{}
			case "wrong_kind":
				r.Read.Kind = "absence"
			case "wrong_claim":
				r.Read.ClaimSequence++
			case "preparation_after_issue":
				events[2].RecordedAt = r.Read.IssuedAtCore.Add(time.Millisecond)
			case "outside_lease":
				r.Read.OriginalDeadlineCore = events[1].LeaseExpiresAt.Add(time.Second)
				r.Read.IssuedAtCore = r.Read.OriginalDeadlineCore.Add(-5 * time.Second)
				r.StartedAtCore = r.Read.IssuedAtCore.Add(time.Millisecond)
				r.ReturnedAtCore = r.Read.IssuedAtCore.Add(2 * time.Millisecond)
				events[2].RecordedAt = r.Read.IssuedAtCore.Add(-time.Millisecond)
				events[3].RecordedAt = r.ReturnedAtCore.Add(time.Millisecond)
			}
			if name == "wrong_kind" || name == "wrong_claim" || name == "outside_lease" {
				// Preserve the complete original wrapper so the nominal kind,
				// claim or old-lease guard is what refuses this operand.
				r.ReadWire = witnessedPredelete107Wire(t, r.Read)
				events[2].Evidence = witnessedPredelete107Wire(t, r.Read)
			}
			events[3].Evidence = witnessedPredelete107Wire(t, r)
			if witnessedExpansionPredeleteReturnContinuation(events, events[1], a, p, now) {
				t.Fatal("failed, late or changed original inventory acquired successor eligibility")
			}
		})
	}
	for _, name := range []string{"issued", "possible_send", "missing_return", "missing_prepared", "stray_event", "other_owner", "other_fence", "gap", "qualified_inventory"} {
		t.Run(name, func(t *testing.T) {
			p, a, events, now := witnessedPredelete107Unit(t)
			claim := events[1]
			switch name {
			case "issued", "possible_send":
				events[0].Stage = name
			case "missing_return":
				events = events[:3]
			case "missing_prepared":
				events = append(events[:2], events[3])
			case "stray_event":
				events = append(events, WitnessedUnenrolledExpansionCleanupEvent{Stage: "claimed"})
			case "other_owner":
				events[3].RunID = "10000000-0000-4000-8000-000000000099"
			case "other_fence":
				events[3].FencingToken++
			case "gap":
				events[3].Sequence++
			case "qualified_inventory":
				events[3].Stage = "inventory_qualified"
			}
			if witnessedExpansionPredeleteReturnContinuation(events, claim, a, p, now) {
				t.Fatal("noncanonical or post-issue history acquired pre-DELETE eligibility")
			}
		})
	}
}
