//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

// This is a tail of the existing single M106 producer/root. Its separate
// database declares the cross-contract topology before migration/admission;
// the provider and Guest replies are fixtures, never production execution.
func witnessedExpansion108Postgres(t *testing.T, original *witnessedCleanup106Fixture, migrations string, put func(string, []byte)) {
	t.Helper()
	f, inventories := witnessedExpansion108CrossContractFixture(t, original, migrations)
	defer f.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	if err := goose.UpToContext(ctx, f.DB, migrations, 107); err != nil {
		t.Fatal("M108 antecedent107", err)
	}
	before := installedReadinessCatalog(t, f.DB)
	if err := goose.UpToContext(ctx, f.DB, migrations, 108); err != nil {
		t.Fatal("M108 actual Up", err)
	}
	after := installedReadinessCatalog(t, f.DB)
	witnessedExpansion108Catalog(t, before, after)
	put("M108-PG-BEFORE107-CATALOG.original.json", before)
	put("M108-PG-AFTER108-CATALOG.original.json", after)
	if err := goose.DownContext(ctx, f.DB, migrations); err != nil {
		t.Fatal("M108 unused Down", err)
	}
	if !bytes.Equal(before, installedReadinessCatalog(t, f.DB)) {
		t.Fatal("M108 unused Down changed whole107 catalog/history")
	}
	if err := goose.UpToContext(ctx, f.DB, migrations, 108); err != nil {
		t.Fatal("M108 new Up after standard Down", err)
	}
	a, err := (CapacityStore{DB: f.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, f.pre.OriginalCreateGrantID, f.job.JobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal("M108 canonical cross-contract admission", err)
	}
	originalBytes := witnessedExpansion107ImmutableOriginals(t, f)
	var previous model.CapacityIntent
	var oldJob CapacityDispatchJob
	var claimedRows []byte
	var owner CapacityStore
	// Two naturally expired, actually FAILED+ACKed, read-free claims prove both
	// the production-shaped loss and a repeated loss after the first new claim.
	for attempt := 0; attempt < 3; attempt++ {
		job := witnessedCleanup106Start(t, f)
		plan := f.private.store.WithOriginalGuestReconcile(f.Workflow, f.private.step(t, "plan-original-guest"), capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
		if attempt > 0 {
			witnessedExpansion108ClaimSQLNegatives(t, f, a, previous, job)
		}
		_, current, same, found, e := plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy)
		if e != nil || !found || same.ID != a.ID || current.Generation != a.OriginalGeneration || current.FencingToken != a.OriginalFencingToken+int64(attempt)+1 {
			t.Fatal("M108 real canonical claim", attempt, found, e, current)
		}
		if attempt > 0 && (current.LeaseOwner == previous.LeaseOwner || current.LeaseExecutorID == previous.LeaseExecutorID || job.RunID == oldJob.RunID) {
			t.Fatal("M108 reused old owner identity", attempt)
		}
		if attempt > 0 && !bytes.Equal(claimedRows, witnessedExpansion107EventRows(t, f.DB, a.ID, attempt+1)) {
			t.Fatal("M108 changed immutable old requested/claimed rows", attempt)
		}
		if !bytes.Equal(originalBytes, witnessedExpansion107ImmutableOriginals(t, f)) {
			t.Fatal("M108 changed immutable failed CREATE/prereg/witness/run/S1", attempt)
		}
		owner, _, found, e = f.private.store.WithOriginalGuestNotifyCanary(f.private.step(t, "retire-original-guest"), capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
		if e != nil || !found {
			t.Fatal("M108 new retire-source bind", attempt, found, e)
		}
		if attempt == 2 {
			previous = current
			oldJob = job
			break
		}
		if _, _, _, _, e = plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy); !errors.Is(e, ErrCapacityLease) {
			t.Fatal("M108 live claim may not be stolen", attempt, e)
		}
		witnessedExpansion108CloseFailedOwner(t, ctx, f, job, current, a)
		claimedRows = witnessedExpansion107EventRows(t, f.DB, a.ID, attempt+2)
		witnessedExpansion108WaitLease(t, ctx, current)
		previous = current
		oldJob = job
	}
	if _, err = owner.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		t.Fatal("M108 no old claim is DELETE authority")
	}
	good := inventories(true)
	if len(good) != 2 || len(good[0].Inventory.Members) != 1 || good[0].Inventory.Members[0].Slot != 2 || len(good[1].Inventory.Members) != 1 || good[1].Inventory.Members[0].Slot != 1 || good[0].Inventory.IntegrationInstanceID == good[1].Inventory.IntegrationInstanceID {
		t.Fatal("M108 current-onlyS2 plus retained-onlyS1 topology")
	}
	witnessedExpansion108ContractNegatives(t, ctx, f, a, owner, good)
	if err = owner.RefreshWitnessedExpansionContractSurvivors(ctx, f.Policy, inventories(true)); err != nil {
		t.Fatal("M108 genuine complete original contract set refresh", err)
	}
	witnessedExpansion108Canaries(t, f, owner, previous, "before_retirement_floor")
	if _, err = owner.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		t.Fatal("M108 survivor canary cannot replace fresh inventory READ")
	}
	read, err := owner.PrepareWitnessedExpansionRead(ctx, f.Policy, "inventory")
	if err != nil || read.ClaimSequence != 4 {
		t.Fatal("M108 fresh own read after third claim", err, read)
	}
	if _, pending, e := owner.RecordWitnessedExpansionRead(ctx, f.Policy, witnessedExpansion108InventoryReturn(t, f, a, read, inventories(true))); e != nil || pending {
		t.Fatal("M108 exact current physical DELETE dry-run", pending, e)
	}
	child, err := owner.IssueWitnessedExpansionDestroy(ctx, f.Policy)
	if err != nil || child.GrantID != a.ChildGrantID || child.CompensationOf != "" {
		t.Fatal("M108 one ordinary child", err, child)
	}
	if _, err = owner.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		t.Fatal("M108 duplicate child")
	}
	if err = owner.MarkWitnessedExpansionPossibleSend(ctx, f.Policy); err != nil {
		t.Fatal(err)
	}
	if err = owner.MarkWitnessedExpansionPossibleSend(ctx, f.Policy); err == nil {
		t.Fatal("M108 possible-send replay")
	}
	receipt := witnessedCleanup106Settle(t, f, owner, child)
	finish, _, found, err := f.private.store.WithOriginalGuestNotifyCanary(f.private.step(t, "finish-original-retirement"), capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, previous.Generation, previous.FencingToken, previous.LeaseOwner)
	if err != nil || !found {
		t.Fatal("M108 finish-source bind", found, err)
	}
	read, err = finish.PrepareWitnessedExpansionRead(ctx, f.Policy, "absence")
	if err != nil {
		t.Fatal(err)
	}
	if _, pending, e := finish.RecordWitnessedExpansionRead(ctx, f.Policy, witnessedCleanup106Absence(t, f, read, receipt, true)); e != nil || !pending {
		t.Fatal("M108 paid IP remains pending", pending, e)
	}
	if _, err = finish.CompleteWitnessedExpansionCleanup(ctx, f.Policy); err == nil {
		t.Fatal("M108 pending paid inventory cannot complete")
	}
	read, err = finish.PrepareWitnessedExpansionRead(ctx, f.Policy, "absence")
	if err != nil {
		t.Fatal(err)
	}
	if proof, pending, e := finish.RecordWitnessedExpansionRead(ctx, f.Policy, witnessedCleanup106Absence(t, f, read, receipt, false)); e != nil || pending || !proof.ResourceAbsent {
		t.Fatal("M108 exact server and paid-set absence", pending, e)
	}
	if err = finish.RefreshWitnessedExpansionContractSurvivors(ctx, f.Policy, inventories(false)); err != nil {
		t.Fatal("M108 target absent only after qualified child absence; retain originalS1", err)
	}
	if _, err = finish.CompleteWitnessedExpansionCleanup(ctx, f.Policy); err == nil {
		t.Fatal("M108 old before-floor cannot authorize terminal")
	}
	witnessedExpansion108Canaries(t, f, finish, previous, "after_retirement_floor")
	terminal, err := finish.CompleteWitnessedExpansionCleanup(ctx, f.Policy)
	if err != nil || terminal.Phase != "hold" || terminal.Decision.Units != 1 || terminal.LeaseOwner != "" || terminal.LeaseExpiresAt != nil {
		t.Fatal("M108 complete floor1 terminal", err, terminal)
	}
	witnessedExpansion108TerminalOriginals(t, f, a, originalBytes)
	catalog := installedReadinessCatalog(t, f.DB)
	if err = goose.DownContext(ctx, f.DB, migrations); err == nil || !strings.Contains(err.Error(), "used claimed-only cleanup recovery") {
		t.Fatal("M108 used Down must refuse", err)
	}
	if !bytes.Equal(catalog, installedReadinessCatalog(t, f.DB)) {
		t.Fatal("M108 refused Down changed whole catalog/history")
	}
	put("M108-CLAIMED-ONLY-CROSS-CONTRACT-TERMINAL.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_expansion108_real_postgres_claimed_cross_contract_fixture_v1", "fixture_only": true, "original_single300_second_producer_reused": true, "natural_lease_expiry_no_clock_rewrite": true, "three_distinct_canonical_claims": true, "two_real_failed_owner_ACKs": true, "old_claim_rows_and_failed_CREATE_originals_immutable": true, "current_onlyS2_retained_onlyS1_native_DTOs": true, "genuine_new_owner_S1_publish_read_before_and_after": true, "new_current_inventory_read_before_single_child": true, "one_ordinary_child_no_compensation": true, "possible_send_is_once": true, "paid_IP_pending_then_complete_absence": true, "target_absent_refresh_preserves_originalS1": true, "typed_original_disposed_ACK_NULL": true, "whole107_to108_catalog_one_function_only": true, "unused_Down_restores107_and_used_Down_refused": true, "native_provider_or_Guest_execution_claimed": false, "clean_cycle_credit": false}))
}

func witnessedExpansion108Catalog(t *testing.T, before, after []byte) {
	t.Helper()
	var b, a map[string]json.RawMessage
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &a) != nil || len(b) != len(a) {
		t.Fatal("M108 whole catalog objects")
	}
	for k, v := range b {
		if k != "functions" && k != "history_wire" && !bytes.Equal(v, a[k]) {
			t.Fatal("M108 changed unrelated catalog", k)
		}
	}
	var old, next []map[string]json.RawMessage
	if json.Unmarshal(b["functions"], &old) != nil || json.Unmarshal(a["functions"], &next) != nil || len(old) != len(next) {
		t.Fatal("M108 must add no function")
	}
	by := map[string]map[string]json.RawMessage{}
	for _, row := range next {
		by[string(row["name"])+string(row["arguments"])] = row
	}
	changed := 0
	for _, row := range old {
		key := string(row["name"]) + string(row["arguments"])
		n, ok := by[key]
		if !ok {
			t.Fatal("M108 removed function", key)
		}
		if !reflect.DeepEqual(row, n) {
			if string(row["name"]) != `"guard_witnessed_unenrolled_expansion_cleanup_event"` {
				t.Fatal("M108 changed unrelated function", key)
			}
			changed++
		}
		delete(by, key)
	}
	if changed != 1 || len(by) != 0 {
		t.Fatal("M108 exact one replaced guard", changed, len(by))
	}
	var oldWire, newWire string
	var oldHistory, newHistory []map[string]any
	if json.Unmarshal(b["history_wire"], &oldWire) != nil || json.Unmarshal(a["history_wire"], &newWire) != nil || json.Unmarshal([]byte(oldWire), &oldHistory) != nil || json.Unmarshal([]byte(newWire), &newHistory) != nil || len(newHistory) != len(oldHistory)+1 || !reflect.DeepEqual(oldHistory, newHistory[:len(oldHistory)]) || oldHistory[len(oldHistory)-1]["version_id"] != float64(107) || newHistory[len(oldHistory)]["version_id"] != float64(108) || newHistory[len(oldHistory)]["is_applied"] != true {
		t.Fatal("M108 actual sole whole Goose history append")
	}
}

func witnessedExpansion108CloseFailedOwner(t *testing.T, ctx context.Context, f *witnessedCleanup106Fixture, job CapacityDispatchJob, current model.CapacityIntent, a WitnessedUnenrolledExpansionCleanup) {
	t.Helper()
	at := time.Now().UTC()
	response := supersededHTTPResult(t, job, current.Generation, current.FencingToken, *job.StartedAt, at)
	response.Metadata = map[string]any{}
	for k, v := range job.Metadata {
		response.Metadata[k] = v
	}
	response.Metadata["failed_step"] = "retire-original-guest"
	for i := range response.Steps {
		response.Steps[i].Metadata = map[string]any{}
		response.Steps[i].Status, response.Steps[i].Attempts = "skipped", 0
	}
	response.Steps[0].Status, response.Steps[0].Attempts = "succeeded", 1
	response.Steps[0].Metadata = map[string]any{"mode": "retire", "slot": a.Slot, "generation": current.Generation, "fencing_token": current.FencingToken, "lease_owner": current.LeaseOwner, "preregistration_id": a.PreregistrationID}
	response.Steps[2].Status, response.Steps[2].Attempts, response.Steps[2].Error = "failed", 1, "declared read-free original cohort refresh failure"
	declared := errors.New("declared cleanup failed before inventory preparation")
	if err := FinishCapacityDispatch(ctx, f.DB, job, response, at, declared); !errors.Is(err, declared) || errors.Is(err, ErrCapacityDispatchUnknown) || errors.Is(err, ErrCapacityDispatchFinalizationPending) {
		t.Fatal("M108 real failed owner ACK", err)
	}
	var closed bool
	if err := f.DB.QueryRowContext(ctx, `SELECT j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.started_at=j.started_at AND w.finished_at=j.returned_at FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, job.JobID).Scan(&closed); err != nil || !closed {
		t.Fatal("M108 exact closed old owner", err, closed)
	}
}

func witnessedExpansion108WaitLease(t *testing.T, ctx context.Context, current model.CapacityIntent) {
	t.Helper()
	if current.LeaseExpiresAt == nil {
		t.Fatal("M108 original cleanup lease missing")
	}
	if d := time.Until(*current.LeaseExpiresAt); d > 0 {
		timer := time.NewTimer(d + time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

// Actual event INSERTs execute the production108 trigger in a rolled-back
// transaction. Adversarial old rows are explicitly declared with replication
// triggers disabled only for setup, then enabled before the attempted INSERT.
func witnessedExpansion108ClaimSQLNegatives(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, current model.CapacityIntent, newJob CapacityDispatchJob) {
	t.Helper()
	_, events, err := (CapacityStore{DB: f.DB}).ReadWitnessedUnenrolledExpansionCleanup(context.Background(), a.GrantID)
	if err != nil || len(events) < 2 || events[len(events)-1].Stage != "claimed" {
		t.Fatal("M108 pure claimed prefix", err)
	}
	old := events[len(events)-1]
	faults := []string{"", "live_lease", "no_ACK", "not_failed", "wrong_current_owner", "same_run", "child_by_ID", "foreign_child_link", "inventory_prepared", "inventory_returned", "issued", "possible_send"}
	for _, fault := range faults {
		tx, e := beginWitnessedExpansionTx(context.Background(), f.DB)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		candidate := old
		candidate.Sequence = int64(len(events) + 1)
		candidate.RunID = newJob.RunID.String()
		candidate.FencingToken = current.FencingToken + 1
		candidate.LeaseOwner = uuid.NewString()
		candidate.ExecutorID = f.private.store.ExecutorID
		candidate.Evidence = nil
		if e = tx.QueryRow(`SELECT clock_timestamp()`).Scan(&candidate.RecordedAt); e != nil {
			t.Fatal(e)
		}
		expires := candidate.RecordedAt.Add(20 * time.Second)
		candidate.LeaseExpiresAt = &expires
		if fault != "" {
			if _, e = tx.Exec(`SET LOCAL session_replication_role=replica`); e != nil {
				t.Fatal("M108 adversarial storage setup", fault, e)
			}
			switch fault {
			case "live_lease":
				_, e = tx.Exec(`UPDATE capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, a.Namespace, candidate.LeaseExpiresAt.Format(time.RFC3339Nano))
			case "no_ACK":
				_, e = tx.Exec(`UPDATE capacity_dispatch_jobs SET finalization_ack_at=NULL WHERE run_id=$1::uuid`, old.RunID)
			case "not_failed":
				_, e = tx.Exec(`UPDATE workflow_runs SET status='succeeded' WHERE id=$1::uuid`, old.RunID)
			case "wrong_current_owner":
				_, e = tx.Exec(`UPDATE capacity_intents SET intent=jsonb_set(intent,'{lease_owner}',to_jsonb($2::text)) WHERE namespace=$1`, a.Namespace, uuid.NewString())
			case "same_run":
				candidate.RunID = old.RunID
			case "child_by_ID", "foreign_child_link":
				id := a.ChildGrantID
				if fault == "foreign_child_link" {
					id = uuid.NewString()
				}
				record := f.parent
				record.Grant.GrantID = id
				record.Grant.State = "expired"
				record.AttemptID = ""
				record.Settlement = nil
				raw := failedServingWire(t, record)
				var doc map[string]json.RawMessage
				if json.Unmarshal(raw, &doc) != nil {
					t.Fatal("M108 declared child object")
				}
				if fault == "foreign_child_link" {
					doc["witnessed_unenrolled_expansion_cleanup_id"] = failedServingWire(t, a.ID)
				}
				_, e = tx.Exec(`INSERT INTO capacity_mutation_grants SELECT (jsonb_populate_record(NULL::capacity_mutation_grants,to_jsonb(g)||jsonb_build_object('id',$2::uuid,'state','expired','grant_record',$3::jsonb))).* FROM capacity_mutation_grants g WHERE id=$1::uuid`, a.GrantID, id, string(failedServingWire(t, doc)))
			default:
				poison := old
				poison.Stage = fault
				poison.Sequence = candidate.Sequence
				poison.RecordedAt = candidate.RecordedAt
				poison.Evidence = nil
				e = (CapacityStore{DB: f.DB}).appendWitnessedExpansionEventTx(context.Background(), tx, poison)
				candidate.Sequence++
			}
			if e != nil {
				t.Fatal("M108 declared negative setup", fault, e)
			}
			if _, e = tx.Exec(`SET LOCAL session_replication_role=origin`); e != nil {
				t.Fatal(e)
			}
		}
		e = (CapacityStore{DB: f.DB}).appendWitnessedExpansionEventTx(context.Background(), tx, candidate)
		if fault == "" && e != nil {
			t.Fatal("M108 independent SQL valid claimed-only successor", e)
		}
		if fault != "" && e == nil {
			t.Fatal("M108 independent SQL unsafe claimed-only successor", fault)
		}
		if e = tx.Rollback(); e != nil {
			t.Fatal(e)
		}
	}
	after, _, err := (CapacityStore{DB: f.DB}).ReadWitnessedUnenrolledExpansionCleanup(context.Background(), a.GrantID)
	if err != nil || after.ID != a.ID {
		t.Fatal("M108 rolled-back independent faults changed admission", err)
	}
}

func witnessedExpansion108ContractNegatives(t *testing.T, ctx context.Context, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, store CapacityStore, good []capacity.GuestContractInventory) {
	t.Helper()
	before := witnessedExpansion107ImmutableOriginals(t, f)
	for _, fault := range []string{"missing_retained", "reordered", "wrong_contract_digest", "duplicate_logical_S1", "changed_S1_birth", "changed_S1_desiredSHA", "stale_retained", "changed_target_birth", "missing_target", "extra_contract"} {
		var inv []capacity.GuestContractInventory
		if json.Unmarshal(failedServingWire(t, good), &inv) != nil {
			t.Fatal("M108 independent contract copy")
		}
		switch fault {
		case "missing_retained":
			inv = inv[:1]
		case "reordered":
			inv[0], inv[1] = inv[1], inv[0]
		case "wrong_contract_digest":
			inv[1].ContractSHA256 = strings.Repeat("f", 64)
		case "duplicate_logical_S1":
			inv[0].Inventory.Members[0].Slot = 1
		case "changed_S1_birth":
			inv[1].Inventory.Members[0].Server.CreatedAt = "2026-01-01T00:00:00Z"
		case "changed_S1_desiredSHA":
			inv[1].Inventory.Members[0].RequestSHA256 = strings.Repeat("f", 64)
		case "stale_retained":
			inv[1].Inventory.ObservedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
		case "changed_target_birth":
			inv[0].Inventory.Members[0].Server.CreatedAt = "2026-01-01T00:00:00Z"
		case "missing_target":
			inv[0].Inventory.Members = nil
			inv[0].Inventory.MissingSlots = []int{1, 2, 3, 4, 5, 6, 7, 8}
		case "extra_contract":
			inv = append(inv, inv[1])
		}
		if err := store.RefreshWitnessedExpansionContractSurvivors(ctx, f.Policy, inv); err == nil {
			t.Fatal("M108 invalid complete survivor union", fault)
		}
		if !bytes.Equal(before, witnessedExpansion107ImmutableOriginals(t, f)) {
			t.Fatal("M108 partial survivor write escaped rollback", fault)
		}
	}
	_ = a
}

func witnessedExpansion108InventoryReturn(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, read WitnessedExpansionRead, inv []capacity.GuestContractInventory) WitnessedExpansionReadReturn {
	t.Helper()
	plan, err := witnessedExpansionDestroyPlan(f.Spec, a)
	if err != nil {
		t.Fatal(err)
	}
	var desired model.CapacityMutationSpecV1
	if json.Unmarshal(plan.CanonicalSpec, &desired) != nil || len(inv) != 2 || len(inv[0].Inventory.Members) != 1 {
		t.Fatal("M108 exact declared current native plan")
	}
	server := inv[0].Inventory.Members[0].Server
	if server.ID != a.ResourceID || server.CreatedAt != a.ResourceCreatedAt {
		t.Fatal("M108 current-only target identity")
	}
	server.AuxiliaryInventoryComplete = true
	server.PrimaryIPv4ID = f.parent.Settlement.AuxiliaryResources[0].ID
	server.PrimaryIPv6ID = ""
	server.IndependentBillableResources = true
	if len(f.parent.Settlement.AuxiliaryResources) > 1 {
		server.PrimaryIPv6ID = f.parent.Settlement.AuxiliaryResources[1].ID
	}
	at := time.Now().UTC()
	return WitnessedExpansionReadReturn{Schema: "witnessed_unenrolled_expansion_native_return_v1", Read: read, ReadWire: failedServingWire(t, read), Status: "dry_run", Plan: &model.CapacityVMFleetPlan{DesiredSpec: desired, RequestSHA256: plan.RequestSHA256, Server: &server, ObservedAt: at.Format(time.RFC3339Nano)}, StartedAtCore: at, ReturnedAtCore: at}
}

// Use the original S1 contract to manufacture only its declared signed DTO;
// current policy/epoch owns the real repository canary publication/read calls.
func witnessedExpansion108Canaries(t *testing.T, f *witnessedCleanup106Fixture, store CapacityStore, current model.CapacityIntent, usage string) {
	t.Helper()
	gap, stop := context.WithTimeout(context.Background(), 7*time.Second)
	delay, err := store.WitnessedExpansionPublicationDelay(gap, f.Policy, f.private.pre.PreregistrationID)
	if err != nil || delay > 6*time.Second {
		stop()
		t.Fatal("M108 original S1 publication gap", delay, err)
	}
	if delay > 0 {
		timer := time.NewTimer(delay + time.Millisecond)
		select {
		case <-timer.C:
		case <-gap.Done():
			timer.Stop()
			stop()
			t.Fatal(gap.Err())
		}
	}
	stop()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	members, err := store.GuestNotifyFloorMembers(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, 2)
	if err != nil || len(members) != 1 || members[0].Slot != 1 || members[0].PreregistrationID != f.private.pre.PreregistrationID {
		t.Fatal("M108 exact retained S1 floor member", members, err)
	}
	enrollment := f.private.receipt.Enrollment
	probe := func(c model.CapacityGuestNotifyCanaryChallenge, pub *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
		c = capacity.RecoveryFixtureCanaryNonce(t, c, enrollment)
		at := time.Now().UTC()
		returned := cleanupNativeHTTP(t, c.GuestNonce, at)
		if e := store.FinalizeGuestNotifyCanaryNonce(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c, returned); e != nil {
			t.Fatal(e)
		}
		if e := store.ReserveGuestNotifyCanarySend(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c); e != nil {
			t.Fatal(e)
		}
		response, facts := capacity.RecoveryFixtureCanaryResponse(t, f.private.p, c, enrollment, pub)
		returned = cleanupNativeHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
		time.Sleep(max(0, time.Until(returned.DriverReturnedAt)) + time.Millisecond)
		if _, e := store.RecordGuestNotifyCanaryReturn(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, c, returned); e != nil {
			t.Fatal("M108 actual original-contract survivor response", e)
		}
		return facts
	}
	key := failedServingKey('c')
	pub, err := store.IssueGuestNotifyCanaryPublication(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, members[0].PreregistrationID, usage, key)
	if err != nil {
		t.Fatal(err)
	}
	facts := probe(pub, nil)
	read, err := store.IssueGuestNotifyCanaryRead(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner, members[0].PreregistrationID, usage, pub.ChallengeID, key)
	if err != nil {
		t.Fatal(err)
	}
	probe(read, facts)
}

func witnessedExpansion108TerminalOriginals(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, before []byte) {
	t.Helper()
	var valid bool
	if err := f.DB.QueryRow(`SELECT public.witnessed_unenrolled_expansion_terminal_valid106($1::uuid)`, a.JobID).Scan(&valid); err != nil || !valid {
		t.Fatal("M108 real typed parent disposition", valid, err)
	}
	var old, now map[string]json.RawMessage
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(witnessedExpansion107ImmutableOriginals(t, f), &now) != nil {
		t.Fatal("M108 whole terminal originals")
	}
	for _, k := range []string{"run", "preregistration", "witness", "S1"} {
		if !bytes.Equal(old[k], now[k]) {
			t.Fatal("M108 original identity changed", k)
		}
	}
	for _, k := range []string{"job", "parent"} {
		var a, b map[string]json.RawMessage
		if json.Unmarshal(old[k], &a) != nil || json.Unmarshal(now[k], &b) != nil {
			t.Fatal(k)
		}
		delete(a, "state")
		delete(b, "state")
		delete(a, "updated_at")
		delete(b, "updated_at")
		if k == "parent" {
			var x, y map[string]json.RawMessage
			if json.Unmarshal(a["grant_record"], &x) != nil || json.Unmarshal(b["grant_record"], &y) != nil {
				t.Fatal("M108 parent record")
			}
			var gx, gy map[string]json.RawMessage
			if json.Unmarshal(x["grant"], &gx) != nil || json.Unmarshal(y["grant"], &gy) != nil {
				t.Fatal("M108 grant record")
			}
			delete(gx, "state")
			delete(gy, "state")
			if !reflect.DeepEqual(gx, gy) {
				t.Fatal("M108 changed immutable original CREATE grant")
			}
			delete(x, "grant")
			delete(y, "grant")
			if !reflect.DeepEqual(x, y) {
				t.Fatal("M108 changed accepted SDK or settlement")
			}
			delete(a, "grant_record")
			delete(b, "grant_record")
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatal("M108 original row changed beyond typed terminal", k)
		}
	}
}
