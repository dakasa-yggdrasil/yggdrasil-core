package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Real queries over two existing approved public contracts. Replication mode
// declares only catalog/scope-index rows, not signed Guest or provider evidence.
// All changes are rolled back; no approval global or immutable original changes.
func testGuestContractResolverPostgres(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	read := func(name string) model.CapacityPolicySpec {
		raw, e := os.ReadFile("../internal/capacity/testdata/" + name + "-notify-hetzner-production-contract.json")
		if e != nil {
			t.Fatal(e)
		}
		var p model.CapacityPolicySpec
		if json.Unmarshal(raw, &p) != nil {
			t.Fatal("public HZN contract")
		}
		return p
	}
	old, headBase := read("original"), read("b509")
	if !capacity.GuestBindingAuthorityCurrent(old, *old.GuestRetirementBinding) || !capacity.GuestBindingAuthorityCurrent(headBase, *headBase.GuestRetirementBinding) {
		t.Fatal("owning CI binary needs actual clean -buildvcs=true identity and existing complete approvals")
	}
	if old.MutationBindings[0].IntegrationInstanceID == headBase.MutationBindings[0].IntegrationInstanceID || old.MutationBindings[0].ScopeChecksum == headBase.MutationBindings[0].ScopeChecksum {
		t.Fatal("approved physical targets must be distinct")
	}
	clone := func(p model.CapacityPolicySpec) model.CapacityPolicySpec {
		raw, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		var out model.CapacityPolicySpec
		if json.Unmarshal(raw, &out) != nil {
			t.Fatal("clone")
		}
		return out
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SET LOCAL session_replication_role=replica`); e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"complete", "unknown_ref", "wrong_checksum", "wrong_contract", "cross_namespace", "cross_name", "newer_birth", "inactive_head", "higher_inactive", "broken_intermediate", "gap"} {
		if _, e = tx.ExecContext(ctx, `SAVEPOINT cohort_case`); e != nil {
			t.Fatal(e)
		}
		ns, name := "cohort-"+uuid.NewString(), "notify-hetzner-elastic-capacity"
		if e = lockMutationScope(ctx, tx, ns, headBase); e != nil {
			t.Fatal(e)
		}
		insert := func(namespace, logical string, version int, p model.CapacityPolicySpec, active bool) model.Manifest {
			raw, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			m := model.Manifest{ID: uuid.New(), Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: namespace, Name: logical}, Version: version, Checksum: capacity.BusinessCreationSHA256([]byte(uuid.NewString())), Spec: raw}
			if _, e = tx.ExecContext(ctx, `INSERT INTO manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,$7)`, m.ID, namespace, logical, version, m.Checksum, string(raw), active); e != nil {
				t.Fatal("declared catalog row", e)
			}
			return m
		}
		priorNS, priorName := ns, name
		if fault == "cross_namespace" {
			priorNS += "-foreign"
		}
		if fault == "cross_name" {
			priorName += "-foreign"
		}
		version := 1
		if fault == "newer_birth" {
			version = 4
		}
		prior := insert(priorNS, priorName, version, old, false)
		head := clone(headBase)
		ref := model.CapacityGuestRetainedPolicyContract{PolicyID: prior.ID.String(), PolicyChecksum: prior.Checksum, ContractSHA256: guestContractDigest(old)}
		switch fault {
		case "unknown_ref":
			ref.PolicyID = uuid.NewString()
		case "wrong_checksum":
			ref.PolicyChecksum = strings.Repeat("f", 64)
		case "wrong_contract":
			ref.ContractSHA256 = strings.Repeat("e", 64)
		}
		head.GuestContractSuccessor = &model.CapacityGuestContractSuccessor{Schema: capacity.GuestContractSuccessorSchema, RetainedPolicyContracts: []model.CapacityGuestRetainedPolicyContract{ref}}
		middle := clone(old)
		middle.MinSamples++
		if fault == "broken_intermediate" {
			middle = clone(headBase)
		}
		// The gap is declared before any row is sealed; no history is deleted.
		if fault != "gap" {
			insert(ns, name, 2, middle, false)
		}
		current := insert(ns, name, 3, head, fault != "inactive_head")
		if fault == "higher_inactive" {
			insert(ns, name, 5, head, false)
		}
		var before string
		if e = tx.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(m) ORDER BY version,id)::text FROM manifests m WHERE namespace=$1 AND name=$2`, ns, name).Scan(&before); e != nil {
			t.Fatal(e)
		}
		contracts, err := guestContractSetTx(ctx, tx, current, head)
		if fault != "complete" && fault != "broken_intermediate" && fault != "gap" {
			if fault == "unknown_ref" {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("unknown immutable ref must be absent", err)
				}
			} else if !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("bad immutable ref accepted or wrong failure", fault, err)
			}
		} else {
			if err != nil || len(contracts) != 2 || contracts[0].digest != guestContractDigest(head) || contracts[1].birth.ID != prior.ID || !reflect.DeepEqual(contracts[1].spec.MutationBindings, old.MutationBindings) {
				t.Fatal("exact complete two-contract resolver", err, contracts)
			}
			err = guestContractLineageTx(ctx, tx, current, head, prior.ID.String(), prior.Checksum)
			if fault == "broken_intermediate" || fault == "gap" {
				if !errors.Is(err, ErrCapacityConflict) {
					t.Fatal("broken or numerically gapped lineage re-admitted old member", fault, err)
				}
			} else {
				if err != nil {
					t.Fatal("explicit retained lineage", err)
				}
				// Historical CREATE input must be checked against the NEW default,
				// not admitted just because its old contract remains manageable.
				raw, _ := json.Marshal(old.MutationBindings[0].Slots[1].DesiredSpec)
				issue := model.CapacityMutationIssue{BindingName: head.MutationBindings[0].Name, DesiredSpec: raw}
				selected, e := guestMutationContractTx(ctx, tx, current, head, issue)
				if e != nil || guestContractDigest(selected) != guestContractDigest(head) {
					t.Fatal("CREATE did not resolve current default", e)
				}
				if _, e = capacity.PrepareMutationPlan(selected, issue); e == nil {
					t.Fatal("historical contract authorized a new CREATE")
				}
				raw, _ = json.Marshal(head.MutationBindings[0].Slots[1].DesiredSpec)
				issue.DesiredSpec = raw
				if _, e = capacity.PrepareMutationPlan(selected, issue); e != nil {
					t.Fatal("exact current CREATE projection refused", e)
				}
				if _, e = guestContractForPreTx(ctx, tx, current, head, uuid.NewString()); !errors.Is(e, sql.ErrNoRows) {
					t.Fatal("missing birth receipt became a member contract", e)
				}
				if _, e = guestStoredContractSpecTx(ctx, tx, current, head, guestOriginalStored{}); !errors.Is(e, ErrCapacityConflict) {
					t.Fatal("absent signed binding became a retained member", e)
				}
				// Scope-index rows are explicitly declared without enrollment or
				// witness authority; these queries prove only logical exclusivity.
				putSlot := func(p model.CapacityPolicySpec, id string) {
					b := p.MutationBindings[0]
					s := capacityResourceSlot{BindingName: b.Name, ProfileName: b.ProfileName, DesiredSpecSHA256: b.Slots[0].DesiredSpecSHA256, ResourceID: id, ResourceCreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), ReceiptRef: "declared-scope-index-only", ObservedAt: time.Now().UTC()}
					raw, _ := json.Marshal(s)
					if _, e = tx.ExecContext(ctx, `INSERT INTO capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9::jsonb)`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, ns, p.Environment, p.Domain, p.Dimension, id, string(raw)); e != nil {
						t.Fatal(e)
					}
				}
				// A historical contract view remains available without enrollment,
				// including for cleanup/finish. It is not retirement authority.
				stored := guestOriginalStored{
					pre: model.CapacityGuestOriginalProvisioningPreregistration{
						PreregistrationID: uuid.NewString(), PolicyID: prior.ID.String(),
						PolicyChecksum: prior.Checksum, Slot: 1,
					},
					binding: *old.GuestRetirementBinding,
				}
				view, e := guestStoredContractSpecTx(ctx, tx, current, head, stored)
				if e != nil || !reflect.DeepEqual(view.MutationBindings, old.MutationBindings) || view.GuestContractSuccessor == nil {
					t.Fatal("historical view incorrectly requires a live enrolled member", e)
				}
				refuseRetire := func(candidate guestOriginalStored, why string) {
					if e := guestRequireCurrentContractMemberTx(ctx, tx, current, view, candidate); !errors.Is(e, ErrCapacityConflict) {
						t.Fatal("current-member retirement admission accepted declared index fault", why, e)
					}
				}
				refuseRetire(stored, "absent logical slot")
				if _, e = tx.ExecContext(ctx, `SAVEPOINT retired_member`); e != nil {
					t.Fatal(e)
				}
				putSlot(old, "declared-tombstoned-S1")
				b := old.MutationBindings[0]
				if _, e = tx.ExecContext(ctx, `UPDATE capacity_resource_slots SET slot_record=slot_record||'{"tombstone":true}'::jsonb WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=1`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName); e != nil {
					t.Fatal(e)
				}
				refuseRetire(stored, "tombstoned old member")
				if _, e = guestStoredContractSpecTx(ctx, tx, current, head, stored); e != nil {
					t.Fatal("post-DELETE historical view became live-only", e)
				}
				if _, e = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT retired_member`); e != nil {
					t.Fatal(e)
				}
				putSlot(head, "declared-replacement-S1")
				refuseRetire(stored, "stale preregistration from a different retained cohort")
				foreignSlot := stored
				foreignSlot.pre.Slot = 2
				refuseRetire(foreignSlot, "caller-provided preregistration for another slot")
				if _, e = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT retired_member`); e != nil {
					t.Fatal(e)
				}
				// No M77 witness or enrollment is manufactured here. Positive
				// current-member and final unique-preregistration authority remain
				// outside this declared catalog/index-only fixture.
				putSlot(old, "declared-old-S1")
				m, e := guestLogicalSlotTx(ctx, tx, current, head, 1)
				if e != nil || !m.exists || !reflect.DeepEqual(m.binding, old.MutationBindings[0]) {
					t.Fatal("head's missing slot1 hid retained S1", e)
				}
				putSlot(head, "declared-second-S1")
				if _, e = guestLogicalSlotTx(ctx, tx, current, head, 1); !errors.Is(e, ErrCapacityConflict) {
					t.Fatal("duplicate logical slot accepted", e)
				}
			}
		}
		var after string
		if e = tx.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(m) ORDER BY version,id)::text FROM manifests m WHERE namespace=$1 AND name=$2`, ns, name).Scan(&after); e != nil || before != after {
			t.Fatal("resolver rewrote immutable catalog", e)
		}
		if _, e = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT cohort_case`); e != nil {
			t.Fatal(e)
		}
	}
}
