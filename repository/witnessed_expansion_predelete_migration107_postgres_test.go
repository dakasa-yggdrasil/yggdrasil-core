//go:build recoveryfixture && !nativequalification

package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
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

// This tail uses an isolated, explicitly declared copy of the real M106
// producer's history. It adds no second 300-second producer and never changes
// that producer, its artifacts, or its M106-only rollback tests. The native
// provider/Guest responses remain declared fixture data, never production proof.
func witnessedExpansion107Postgres(t *testing.T, original *witnessedCleanup106Fixture, migrations string, put func(string, []byte)) {
	t.Helper()
	f := witnessedCleanup106Clone(t, original, migrations)
	defer f.DB.Close()
	before := installedReadinessCatalog(t, f.DB)
	if err := goose.UpToContext(context.Background(), f.DB, migrations, 107); err != nil {
		t.Fatal("M107 actual Up", err)
	}
	after := installedReadinessCatalog(t, f.DB)
	put("M107-PG-BEFORE106-CATALOG.original.json", before)
	put("M107-PG-AFTER107-CATALOG.original.json", after)
	witnessedExpansion107Catalog(t, before, after)
	witnessedExpansion107SinglePrimaryIP(t, original, migrations, put)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, err := (CapacityStore{DB: f.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, f.pre.OriginalCreateGrantID, f.job.JobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	immutableOriginals := witnessedExpansion107ImmutableOriginals(t, f)
	oldJob := witnessedCleanup106Start(t, f)
	plan := f.private.store.WithOriginalGuestReconcile(f.Workflow, f.private.step(t, "plan-original-guest"), capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	_, current, _, found, err := plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy)
	if err != nil || !found {
		t.Fatal("M107 original real owner", found, err)
	}
	store, _, found, err := f.private.store.WithOriginalGuestNotifyCanary(f.private.step(t, "retire-original-guest"), capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !found {
		t.Fatal("M107 original bind", found, err)
	}
	read, err := store.PrepareWitnessedExpansionRead(ctx, f.Policy, "inventory")
	if err != nil {
		t.Fatal(err)
	}
	raw := witnessedCleanup106InventoryReturn(t, f, a, read)
	_, events, err := (CapacityStore{DB: f.DB}).ReadWitnessedUnenrolledExpansionCleanup(ctx, a.GrantID)
	if err != nil || len(events) != 3 || events[1].Stage != "claimed" {
		t.Fatal("M107 exact pre-return prefix", err)
	}
	// Storage-level fixture operand: reproduce the old Source's durable return
	// followed by a Go qualification refusal. The real immutable return trigger
	// executes; no inventory_qualified row, child grant, or send is synthesized.
	tx, err := beginWitnessedExpansionTx(ctx, f.DB)
	if err != nil {
		t.Fatal(err)
	}
	var recorded time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&recorded); err == nil {
		err = store.appendWitnessedExpansionStageTx(ctx, tx, a, events[1], "inventory_returned", raw, recorded)
	}
	if err != nil {
		_ = tx.Rollback()
		t.Fatal("M107 declared old returned custody", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	oldRows := witnessedExpansion107EventRows(t, f.DB, a.ID, 4)
	if len(oldRows) == 0 {
		t.Fatal("M107 complete old four rows required")
	}
	witnessedExpansion107InventoryNegatives(t, f, a, raw)
	if _, _, err = store.RecordWitnessedExpansionRead(ctx, f.Policy, raw); err == nil {
		t.Fatal("M107 old raw replay must not qualify")
	}
	if _, _, _, _, err = plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy); !errors.Is(err, ErrCapacityLease) {
		t.Fatal("M107 live owner must not be reclaimed", err)
	}
	failedAt := time.Now().UTC()
	response := supersededHTTPResult(t, oldJob, current.Generation, current.FencingToken, *oldJob.StartedAt, failedAt)
	response.Metadata = map[string]any{}
	for k, v := range oldJob.Metadata {
		response.Metadata[k] = v
	}
	response.Metadata["failed_step"] = "finish-original-retirement"
	for i := range response.Steps {
		response.Steps[i].Metadata = map[string]any{}
		response.Steps[i].Status, response.Steps[i].Attempts = "skipped", 0
	}
	response.Steps[0].Status, response.Steps[0].Attempts = "succeeded", 1
	response.Steps[2].Status, response.Steps[2].Attempts = "succeeded", 1
	response.Steps[5].Status, response.Steps[5].Attempts, response.Steps[5].Error = "failed", 1, "declared old inventory was returned but never qualified"
	declared := errors.New("declared predelete inventory qualification failed")
	if err = FinishCapacityDispatch(ctx, f.DB, oldJob, response, failedAt, declared); !errors.Is(err, declared) || errors.Is(err, ErrCapacityDispatchUnknown) || errors.Is(err, ErrCapacityDispatchFinalizationPending) {
		t.Fatal("M107 real failed old owner ACK", err)
	}
	closed, err := readCapacityDispatchJob(ctx, f.DB, oldJob.JobID, false)
	if err != nil || closed.State != "returned" || closed.FinalizationAckAt == nil || closed.ReturnedAt == nil || closed.ReturnedAt.Before(recorded) {
		t.Fatal("M107 old owner must actually close after custody", err, closed)
	}
	var failedOwner bool
	if err = f.DB.QueryRow(`SELECT j.return_status='failed' AND w.status='failed' AND w.finished_at=j.returned_at FROM capacity_dispatch_jobs j JOIN workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, oldJob.JobID).Scan(&failedOwner); err != nil || !failedOwner {
		t.Fatal("M107 actual failed workflow and job agreement", err)
	}
	if current.LeaseExpiresAt == nil {
		t.Fatal("M107 original lease required")
	}
	if wait := time.Until(*current.LeaseExpiresAt); wait > 0 {
		timer := time.NewTimer(wait + time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
	}
	newJob := witnessedCleanup106Start(t, f)
	plan = f.private.store.WithOriginalGuestReconcile(f.Workflow, f.private.step(t, "plan-original-guest"), capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	_, next, same, found, err := plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy)
	if err != nil || !found || same.ID != a.ID || next.FencingToken != current.FencingToken+1 || next.LeaseOwner == current.LeaseOwner || next.LeaseExecutorID == current.LeaseExecutorID || newJob.RunID == oldJob.RunID {
		t.Fatal("M107 new canonical predelete owner", found, err)
	}
	fresh, _, found, err := f.private.store.WithOriginalGuestNotifyCanary(f.private.step(t, "retire-original-guest"), capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, next.Generation, next.FencingToken, next.LeaseOwner)
	if err != nil || !found {
		t.Fatal("M107 fresh real owner bind", found, err)
	}
	if err = fresh.RefreshWitnessedExpansionSurvivors(ctx, f.Policy, witnessedCleanup106Inventory(t, f, a, true)); err != nil {
		t.Fatal("M107 successor real S1 identity refresh", err)
	}
	witnessedCleanup106Canaries(t, f, fresh, next, "before_retirement_floor")
	if _, err = fresh.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		t.Fatal("M107 old successful inventory must not authorize the child")
	}
	if _, _, err = fresh.RecordWitnessedExpansionRead(ctx, f.Policy, raw); err == nil {
		t.Fatal("M107 same old read cannot be restamped by new owner")
	}
	freshRead, err := fresh.PrepareWitnessedExpansionRead(ctx, f.Policy, "inventory")
	if err != nil || freshRead.ReadID == read.ReadID || freshRead.ClaimSequence != 5 {
		t.Fatal("M107 different real fresh original read", err, freshRead)
	}
	if _, pending, e := fresh.RecordWitnessedExpansionRead(ctx, f.Policy, witnessedCleanup106InventoryReturn(t, f, a, freshRead)); e != nil || pending {
		t.Fatal("M107 new real inventory qualification", e, pending)
	}
	grant, err := fresh.IssueWitnessedExpansionDestroy(ctx, f.Policy)
	if err != nil || grant.GrantID != a.ChildGrantID || grant.CompensationOf != "" {
		t.Fatal("M107 one distinct ordinary child after fresh read/floor", err, grant)
	}
	if _, err = fresh.IssueWitnessedExpansionDestroy(ctx, f.Policy); err == nil {
		t.Fatal("M107 duplicate child issuance")
	}
	if _, err = fresh.PrepareWitnessedExpansionRead(ctx, f.Policy, "inventory"); err == nil {
		t.Fatal("M107 issued child cannot rearm inventory")
	}
	if !bytes.Equal(oldRows, witnessedExpansion107EventRows(t, f.DB, a.ID, 4)) || !bytes.Equal(immutableOriginals, witnessedExpansion107ImmutableOriginals(t, f)) {
		t.Fatal("M107 changed complete old originals or four immutable rows")
	}
	catalogBeforeDown := installedReadinessCatalog(t, f.DB)
	if err = goose.DownContext(ctx, f.DB, migrations); err == nil || !strings.Contains(err.Error(), "recovery107 cannot be removed with admitted history") {
		t.Fatal("M107 used Down must refuse", err)
	}
	if !bytes.Equal(catalogBeforeDown, installedReadinessCatalog(t, f.DB)) {
		t.Fatal("M107 refused Down changed whole catalog or history")
	}
	put("M107-IMMUTABLE-PREDELETE-RETURN-CONTINUATION.PUBLIC.json", failedServingWire(t, map[string]any{
		"schema": "witnessed_expansion107_actual_postgres_predelete_recovery_fixture_v1", "fixture_only": true,
		"old_raw_return_declared_at_storage_seam": true, "native_provider_or_Guest_executed": false,
		"old_four_complete_rows_unchanged": true, "original_CREATE_job_run_preregistration_witness_exact": true, "S1_physical_identity_unchanged": true,
		"real_failed_owner_finalization_ACK_before_natural_lease_expiry": true,
		"new_canonical_dispatch_claim_and_source_binding":                true, "new_read_id": freshRead.ReadID,
		"old_read_id": read.ReadID, "old_read_never_qualified_or_restamped": true,
		"actual_new_S1_floor_and_fresh_inventory_before_one_child": true, "no_provider_send": true,
		"used_down_refused_with_whole_catalog_unchanged": true,
	}))
}

// Inventory refreshes legitimately advance only S1 observation custody. Its
// physical/create/enrollment identity and every original failed expansion row
// remain exact; normalize precisely the same allowed fields as M106's terminal
// proof, without excluding an original parent, job, run, preregistration or SDK.
func witnessedExpansion107ImmutableOriginals(t *testing.T, f *witnessedCleanup106Fixture) []byte {
	t.Helper()
	var rows map[string]json.RawMessage
	if json.Unmarshal(witnessedCleanup106Originals(t, f), &rows) != nil {
		t.Fatal("M107 originals object")
	}
	var s1, slot map[string]json.RawMessage
	if json.Unmarshal(rows["S1"], &s1) != nil || json.Unmarshal(s1["slot_record"], &slot) != nil {
		t.Fatal("M107 complete S1 identity")
	}
	delete(slot, "observed_at")
	delete(slot, "receipt_ref")
	s1["slot_record"] = failedServingWire(t, slot)
	delete(s1, "revision")
	delete(s1, "updated_at")
	rows["S1"] = failedServingWire(t, s1)
	return failedServingWire(t, rows)
}

func witnessedExpansion107EventRows(t *testing.T, db *sql.DB, id string, limit int) []byte {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`SELECT jsonb_agg(to_jsonb(e) ORDER BY sequence)::text FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE cleanup_id=$1 AND sequence<=$2`, id, limit).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func witnessedExpansion107InventoryNegatives(t *testing.T, f *witnessedCleanup106Fixture, a WitnessedUnenrolledExpansionCleanup, raw WitnessedExpansionReadReturn) {
	t.Helper()
	check := func(label string, r WitnessedExpansionReadReturn, want bool) {
		t.Helper()
		var valid bool
		if err := f.DB.QueryRow(`SELECT public.witnessed_expansion_inventory_return_valid107($1::jsonb,$2::jsonb,$3::jsonb)`, string(failedServingWire(t, r)), string(failedServingWire(t, a)), string(f.Policy.Spec)).Scan(&valid); err != nil || valid != want {
			t.Fatal("M107 SQL inventory content", label, want, valid, err)
		}
		_, pending, err := witnessedExpansionReadContent(r, f.Spec, a)
		if (err == nil && !pending) != want {
			t.Fatal("M107 SQL and Go inventory parity", label, want, pending, err)
		}
	}
	check("actual_two_original_IPs", raw, true)
	// These intentionally malformed JSON operands cannot be represented by
	// the typed Go DTO. The independent SQL boundary must reject their types
	// instead of coercing a numeric primary IP into the same textual ID.
	for _, fault := range []string{"numeric_primary_ip", "numeric_original_auxiliary_id", "numeric_read_timestamp"} {
		var returned, admission map[string]json.RawMessage
		if json.Unmarshal(failedServingWire(t, raw), &returned) != nil || json.Unmarshal(failedServingWire(t, a), &admission) != nil {
			t.Fatal("M107 raw numeric operand copy", fault)
		}
		switch fault {
		case "numeric_primary_ip":
			var plan, server map[string]json.RawMessage
			if json.Unmarshal(returned["plan"], &plan) != nil || json.Unmarshal(plan["server"], &server) != nil {
				t.Fatal("M107 raw server operand", fault)
			}
			server["primary_ipv4_id"] = json.RawMessage(raw.Plan.Server.PrimaryIPv4ID)
			plan["server"] = failedServingWire(t, server)
			returned["plan"] = failedServingWire(t, plan)
		case "numeric_original_auxiliary_id":
			var parent, settlement map[string]json.RawMessage
			var auxiliary []map[string]json.RawMessage
			if json.Unmarshal(a.OriginalGrantWire, &parent) != nil || json.Unmarshal(parent["settlement"], &settlement) != nil || json.Unmarshal(settlement["auxiliary_resources"], &auxiliary) != nil || len(auxiliary) != 2 {
				t.Fatal("M107 raw original auxiliary operand", fault)
			}
			auxiliary[0]["id"] = json.RawMessage(raw.Plan.Server.PrimaryIPv4ID)
			settlement["auxiliary_resources"] = failedServingWire(t, auxiliary)
			parent["settlement"] = failedServingWire(t, settlement)
			admission["original_grant_wire"] = failedServingWire(t, failedServingWire(t, parent))
		case "numeric_read_timestamp":
			var read map[string]json.RawMessage
			if json.Unmarshal(returned["read"], &read) != nil {
				t.Fatal("M107 raw read operand", fault)
			}
			read["issued_at_core"] = json.RawMessage("20261115")
			returned["read"] = failedServingWire(t, read)
		}
		var valid bool
		if err := f.DB.QueryRow(`SELECT public.witnessed_expansion_inventory_return_valid107($1::jsonb,$2::jsonb,$3::jsonb)`, string(failedServingWire(t, returned)), string(failedServingWire(t, admission)), string(f.Policy.Spec)).Scan(&valid); err != nil || valid {
			t.Fatal("M107 numeric JSON must be refused by SQL", fault, valid, err)
		}
	}
	for _, fault := range []string{"foreign_server", "foreign_birth", "missing_original_ip", "foreign_ip", "duplicate_ip", "unknown_auxiliary", "unpaid_flag", "locked", "protected", "unknown_inventory", "physical_unverified", "compensation", "false_request_hash", "wrong_desired", "wrong_read_wire", "equivalent_different_read_wire", "wrong_admission", "reported_call_failure", "failed_context", "at_original_deadline", "pending", "observation"} {
		var r WitnessedExpansionReadReturn
		if json.Unmarshal(failedServingWire(t, raw), &r) != nil {
			t.Fatal("M107 whole independent fault copy")
		}
		switch fault {
		case "foreign_server":
			r.Plan.Server.ID = "174243599"
		case "foreign_birth":
			r.Plan.Server.CreatedAt = "2000-01-01T00:00:00Z"
		case "missing_original_ip":
			r.Plan.Server.PrimaryIPv6ID = ""
		case "foreign_ip":
			r.Plan.Server.PrimaryIPv4ID = "999999999"
		case "duplicate_ip":
			r.Plan.Server.PrimaryIPv6ID = r.Plan.Server.PrimaryIPv4ID
		case "unknown_auxiliary":
			r.Plan.AuxiliaryResources = []model.CapacityVMAuxiliaryObservation{{}}
		case "unpaid_flag":
			r.Plan.Server.IndependentBillableResources = false
		case "locked":
			r.Plan.Server.Locked = true
		case "protected":
			r.Plan.Server.ProtectedFromDelete = true
		case "unknown_inventory":
			r.Plan.Server.AuxiliaryInventoryComplete = false
		case "physical_unverified":
			r.Plan.Server.PhysicalSpecVerified = false
		case "compensation":
			r.Plan.Server.CompensationIdentityVerified = true
		case "false_request_hash":
			r.Plan.RequestSHA256 = strings.Repeat("f", 64)
		case "wrong_desired":
			r.Plan.DesiredSpec.NativeName = "foreign"
		case "wrong_read_wire":
			r.ReadWire = []byte(`{}`)
		case "equivalent_different_read_wire":
			r.ReadWire = append([]byte(" "), r.ReadWire...)
		case "wrong_admission":
			r.Read.AdmissionSHA256 = strings.Repeat("f", 64)
			r.ReadWire = failedServingWire(t, r.Read)
		case "reported_call_failure":
			r.CallFailed = true
		case "failed_context":
			r.OriginalContextFailed = true
		case "at_original_deadline":
			r.ReturnedAtCore = r.Read.OriginalDeadlineCore
		case "pending":
			r.Pending = true
		case "observation":
			r.Observation = &model.CapacityVMRetirementObservation{}
		}
		check(fault, r, false)
	}
}

func witnessedExpansion107Catalog(t *testing.T, before, after []byte) {
	t.Helper()
	var b, a map[string]json.RawMessage
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &a) != nil || len(b) != len(a) {
		t.Fatal("M107 whole catalog objects")
	}
	for k, v := range b {
		if k != "functions" && k != "history_wire" && !bytes.Equal(v, a[k]) {
			t.Fatal("M107 changed unrelated complete catalog", k)
		}
	}
	var oldFunctions, newFunctions []map[string]json.RawMessage
	if json.Unmarshal(b["functions"], &oldFunctions) != nil || json.Unmarshal(a["functions"], &newFunctions) != nil || len(newFunctions) != len(oldFunctions)+1 {
		t.Fatal("M107 exact additive helper and replaced guard")
	}
	by := map[string]map[string]json.RawMessage{}
	for _, f := range newFunctions {
		by[string(f["name"])+string(f["arguments"])] = f
	}
	changed := 0
	for _, old := range oldFunctions {
		key := string(old["name"]) + string(old["arguments"])
		next, found := by[key]
		if !found {
			t.Fatal("M107 removed old function", key)
		}
		if !reflect.DeepEqual(old, next) {
			if string(old["name"]) != `"guard_witnessed_unenrolled_expansion_cleanup_event"` {
				t.Fatal("M107 changed unrelated complete function row", key)
			}
			changed++
		}
		delete(by, key)
	}
	if changed != 1 || len(by) != 1 {
		t.Fatal("M107 exact function delta", changed, len(by))
	}
	for _, added := range by {
		if string(added["name"]) != `"witnessed_expansion_inventory_return_valid107"` {
			t.Fatal("M107 unexpected added function")
		}
	}
	var oldWire, newWire string
	var oldHistory, newHistory []map[string]any
	if json.Unmarshal(b["history_wire"], &oldWire) != nil || json.Unmarshal(a["history_wire"], &newWire) != nil || json.Unmarshal([]byte(oldWire), &oldHistory) != nil || json.Unmarshal([]byte(newWire), &newHistory) != nil || len(newHistory) != len(oldHistory)+1 || !reflect.DeepEqual(oldHistory, newHistory[:len(oldHistory)]) || oldHistory[len(oldHistory)-1]["version_id"] != float64(106) || newHistory[len(oldHistory)]["version_id"] != float64(107) || newHistory[len(oldHistory)]["is_applied"] != true {
		t.Fatal("M107 sole actual whole-history append")
	}
}

// This separate variant is declared BEFORE admission and before M106 is
// installed. It is not a rewrite of the real producer, a live admission, or an
// immutable original. Regenerate the owning fixture witness for its one-IP
// settlement instead of substituting a mismatched original hash/signature.
func witnessedExpansion107SinglePrimaryIP(t *testing.T, original *witnessedCleanup106Fixture, migrations string, put func(string, []byte)) {
	t.Helper()
	declared := *original
	parent := original.parent
	settlement := *parent.Settlement
	settlement.AuxiliaryResources = append([]model.CapacityMutationAuxiliaryResource(nil), settlement.AuxiliaryResources[:1]...)
	parent.Settlement = &settlement
	declared.parent = parent
	declared.witness, declared.registration, declared.receipt = capacity.RecoveryFixtureCompensationRegistration(t, declared.Spec, *declared.Spec.GuestRetirementBinding, declared.pre, settlement)
	declared.base = make(map[string][]json.RawMessage, len(original.base))
	parentRows, witnessRows := 0, 0
	for table, rows := range original.base {
		declared.base[table] = append([]json.RawMessage(nil), rows...)
		if table != "capacity_mutation_grants" && table != "capacity_guest_original_create_witnesses" {
			continue
		}
		for i, raw := range rows {
			var row map[string]json.RawMessage
			if json.Unmarshal(raw, &row) != nil {
				t.Fatal("M107 one-IP declared source row")
			}
			if table == "capacity_mutation_grants" && string(row["id"]) == string(failedServingWire(t, declared.pre.OriginalCreateGrantID)) {
				row["grant_record"] = failedServingWire(t, parent)
				declared.base[table][i] = failedServingWire(t, row)
				parentRows++
			}
			if table == "capacity_guest_original_create_witnesses" && string(row["preregistration_id"]) == string(failedServingWire(t, declared.pre.PreregistrationID)) {
				row["witness_sha256"] = failedServingWire(t, capacity.GuestRetirementSHA(declared.witness))
				row["original_record"] = failedServingWire(t, declared.witness)
				row["original_wire"] = failedServingWire(t, "\\x"+hex.EncodeToString(failedServingWire(t, declared.witness)))
				row["recorded_at"] = failedServingWire(t, declared.witness.ObservedAt)
				declared.base[table][i] = failedServingWire(t, row)
				witnessRows++
			}
		}
	}
	if parentRows != 1 || witnessRows != 1 {
		t.Fatal("M107 one-IP exact declared parent/witness rows", parentRows, witnessRows)
	}
	f := witnessedCleanup106Clone(t, &declared, migrations)
	defer f.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before := installedReadinessCatalog(t, f.DB)
	if err := goose.UpToContext(ctx, f.DB, migrations, 107); err != nil {
		t.Fatal("M107 unused Up", err)
	}
	if err := goose.DownContext(ctx, f.DB, migrations); err != nil {
		t.Fatal("M107 unused Down", err)
	}
	after := installedReadinessCatalog(t, f.DB)
	var b, a map[string]json.RawMessage
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &a) != nil {
		t.Fatal("M107 unused full catalog objects")
	}
	// Goose v3.27's PostgreSQL DeleteVersion removes only its own applied
	// version row on a standard unused Down. Every preexisting row, including
	// its native ID/timestamp, must be exact; no row is manually reset here.
	if !bytes.Equal(b["history_wire"], a["history_wire"]) {
		t.Fatal("M107 unused Down changed a preexisting history row")
	}
	if !reflect.DeepEqual(b, a) {
		t.Fatal("M107 unused Down must restore every whole106 catalog row")
	}
	if err := goose.UpToContext(ctx, f.DB, migrations, 107); err != nil {
		t.Fatal("M107 one-IP actual new Up after unused Down", err)
	}
	admission, err := (CapacityStore{DB: f.DB}).RequestWitnessedUnenrolledExpansionCleanup(ctx, f.pre.OriginalCreateGrantID, f.job.JobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal("M107 one-IP canonical admission", err)
	}
	witnessedCleanup106Start(t, f)
	plan := f.private.store.WithOriginalGuestReconcile(f.Workflow, f.private.step(t, "plan-original-guest"), capacity.CurrentGuestCoreSource(), "", "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
	_, current, _, found, err := plan.TryClaimWitnessedExpansionCleanup(ctx, f.Policy)
	if err != nil || !found {
		t.Fatal("M107 one-IP original owner", found, err)
	}
	store, _, found, err := f.private.store.WithOriginalGuestNotifyCanary(f.private.step(t, "retire-original-guest"), capacity.CurrentGuestCoreSource()).BindWitnessedExpansionCleanup(ctx, f.Policy, current.Generation, current.FencingToken, current.LeaseOwner)
	if err != nil || !found {
		t.Fatal("M107 one-IP owner bind", found, err)
	}
	read, err := store.PrepareWitnessedExpansionRead(ctx, f.Policy, "inventory")
	if err != nil {
		t.Fatal("M107 one-IP actual read preparation", err)
	}
	raw := witnessedCleanup106InventoryReturn(t, f, admission, read)
	var valid bool
	if err = f.DB.QueryRowContext(ctx, `SELECT public.witnessed_expansion_inventory_return_valid107($1::jsonb,$2::jsonb,$3::jsonb)`, string(failedServingWire(t, raw)), string(failedServingWire(t, admission)), string(f.Policy.Spec)).Scan(&valid); err != nil || !valid {
		t.Fatal("M107 one-IP exact SQL content", valid, err)
	}
	if _, pending, e := store.RecordWitnessedExpansionRead(ctx, f.Policy, raw); e != nil || pending {
		t.Fatal("M107 one-IP real Go and SQL qualification", pending, e)
	}
	put("M107-ONE-PRIMARY-IP-AND-UNUSED-DOWN.PUBLIC.json", failedServingWire(t, map[string]any{"schema": "witnessed_expansion107_declared_one_primary_ip_fixture_v1", "fixture_only": true, "one_IP_history_declared_before_migration_and_admission": true, "owning_witness_regenerated_for_declared_settlement": true, "real_goose107_up_down_restores_every_whole106_catalog_row": true, "preexisting_whole_history_exact_after_standard_goose_down": true, "real_canonical_admission_claim_bind_prepare_and_inventory_qualification": true, "native_provider_or_Guest_execution_claimed": false, "child_or_provider_send": false}))
}
