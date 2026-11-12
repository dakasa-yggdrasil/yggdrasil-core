//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

// Reuse the existing case's naturally expired M98 and M99 originals. No new
// test ID, dispatch deadline, historical row rewrite or native proof is added.
func retirementContinuationTypedHistoryRegression(t *testing.T, f *installedTimeoutFixture, own CapacityDispatchJob, anchor model.CapacityInstalledProvisionTimeoutDisposition, plan model.CapacityDispatchPreActionPlanDisposition) {
	t.Helper()
	ctx := context.Background()
	beforeOriginals := preActionPlanOriginals(t, f, CapacityDispatchJob{CapacityDispatchEnvelope: CapacityDispatchEnvelope{JobID: uuid.MustParse(plan.JobID)}})
	migrations := filepath.Join(failedServingRepositoryRoot(t), "db", "migrations")
	if err := goose.UpToContext(ctx, f.db, migrations, 100); err != nil {
		t.Fatal("actual schema100 predecessor", err)
	}
	beforeCatalog := preActionPlanCatalog(t, f.db)
	if err := goose.UpToContext(ctx, f.db, migrations, 101); err != nil {
		t.Fatal("actual schema101 typed terminal quiet", err)
	}
	afterCatalog := preActionPlanCatalog(t, f.db)
	retirementContinuation101Catalog(t, beforeCatalog, afterCatalog)
	if own.State != "started" || own.StartedAt == nil || own.ReturnedAt != nil {
		t.Fatal("real started requester required")
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL TIME ZONE 'UTC'"); err != nil {
		t.Fatal(err)
	}
	binding, err := capacity.VMObservationBinding(f.p, f.binding.MutationBindingName)
	if err != nil {
		t.Fatal(err)
	}
	x := retirementForwardSnapshot{policy: f.policy, spec: f.p, binding: binding}
	x.original.Request.Intent.PolicyID = f.policy.ID.String()
	// This is only the existing quiet function's operand projection, not a
	// signed retirement original, admission or authority claim.
	frame := map[string]any{"namespace": f.policy.Metadata.Namespace, "environment": f.p.Environment, "domain": f.p.Domain, "dimension": f.p.Dimension, "destroy_grant_id": "", "original": map[string]any{"Request": map[string]any{"intent": map[string]any{"workflow_id": f.workflow.ID.String(), "policy_id": f.policy.ID.String(), "tuple": map[string]any{"integration_instance_id": binding.IntegrationInstanceID, "scope_checksum": binding.ScopeChecksum, "profile": binding.ProfileName}}}}}
	frameWire := installedTimeoutWire(t, frame)
	quietSQL := func() bool {
		t.Helper()
		var accepted bool
		if err := tx.QueryRowContext(ctx, "SELECT public.retirement_forward_continuation_quiet($1::jsonb,$2::uuid)", string(frameWire), own.RunID).Scan(&accepted); err != nil {
			t.Fatal("independent SQL quiet predicate", err)
		}
		return accepted
	}
	requireQuiet := func(label string) {
		t.Helper()
		if err := retirementForwardContinuationQuietTx(ctx, tx, x, "", own.RunID.String()); err != nil || !quietSQL() {
			t.Fatal(label, "full Go and SQL quiet must both admit genuine terminal history", err)
		}
	}
	// Exact pre-fix Go WHERE control: the two authentic NULL-ACK terminals
	// were both incorrectly counted even though their workflow runs were closed.
	const oldGoCount = `SELECT count(*) FROM public.capacity_dispatch_jobs j WHERE j.run_id::text IS DISTINCT FROM $3 AND ((j.envelope::jsonb#>>'{workflow,namespace}'=$1 AND j.envelope::jsonb#>>'{workflow,name}'=$2) OR j.envelope::jsonb#>>'{workflow,id}' IN(SELECT id::text FROM public.manifests WHERE kind='workflow' AND namespace=$1 AND name=$2)) AND ((j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed')) OR j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL))`
	var oldBusy int
	if err = tx.QueryRowContext(ctx, oldGoCount, f.p.Workflow.Namespace, f.p.Workflow.Name, own.RunID.String()).Scan(&oldBusy); err != nil || oldBusy != 2 {
		t.Fatal("exact old Go guard must reproduce both genuine history blockers", oldBusy, err)
	}
	// Execute only the migration's exact Down definition inside a savepoint.
	// Restoring the savepoint reinstates the new body without changing history.
	migration, err := os.ReadFile(filepath.Join(migrations, "00101_retirement_continuation_typed_terminal_quiet.sql"))
	if err != nil {
		t.Fatal(err)
	}
	down := strings.Split(string(migration), "-- +goose Down")
	if len(down) != 2 {
		t.Fatal("single exact prior-body Down required")
	}
	start, end := strings.Index(down[1], "CREATE OR REPLACE FUNCTION"), strings.LastIndex(down[1], "$$;")
	if start < 0 || end < start {
		t.Fatal("complete prior SQL body required")
	}
	if _, err = tx.ExecContext(ctx, "SAVEPOINT old_quiet_control"); err == nil {
		_, err = tx.ExecContext(ctx, down[1][start:end+3])
	}
	if err != nil || quietSQL() {
		t.Fatal("exact old SQL quiet guard must refuse genuine terminal history", err)
	}
	if _, err = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT old_quiet_control"); err != nil {
		t.Fatal(err)
	}
	requireQuiet("both genuine M98/M99 receipts")

	ids := []uuid.UUID{uuid.MustParse(anchor.JobID), uuid.MustParse(plan.JobID)}
	for _, id := range ids {
		var state string
		var updated time.Time
		if err = tx.QueryRowContext(ctx, "SELECT state,updated_at FROM public.capacity_dispatch_jobs WHERE id=$1", id).Scan(&state, &updated); err != nil {
			t.Fatal(err)
		}
		if err = retirementContinuationTerminalReceiptTx(ctx, tx, id, state, updated); err != nil {
			t.Fatal("genuine private typed reader", err)
		}
		for _, fault := range []string{"missing_receipt", "foreign_terminal_kind", "foreign_timestamp"} {
			candidateID, candidateState, candidateAt := id, state, updated
			switch fault {
			case "missing_receipt":
				candidateID = uuid.New()
			case "foreign_terminal_kind":
				if state == CapacityDispatchInstalledProvisionTimeoutState {
					candidateState = CapacityDispatchPreActionPlanState
				} else {
					candidateState = CapacityDispatchInstalledProvisionTimeoutState
				}
			case "foreign_timestamp":
				candidateAt = updated.Add(time.Second)
			}
			if err = retirementContinuationTerminalReceiptTx(ctx, tx, candidateID, candidateState, candidateAt); err == nil {
				t.Fatal("Go accepted unbound or forged terminal receipt operands", fault)
			}
		}
	}
	retirementContinuation101SQLCandidateFaults(t, tx, frameWire, own.RunID, ids)
	// Existing legal rollback-only competing job shapes isolate dispatch
	// UNKNOWN and returned-without-ACK from the separate workflow quiet guard.
	fixture := &GuestRetirementForwardRecoveryFixture{DB: f.db, Policy: f.policy, Workflow: f.workflow, Spec: f.p, envelope: f.envelope(t)}
	for _, fault := range []string{"unknown", "returned_without_ack"} {
		if _, err = tx.ExecContext(ctx, "SAVEPOINT unresolved_owner"); err != nil {
			t.Fatal(err)
		}
		if err = continuationTestBusyDispatch(t, fixture, ctx, tx, fault); err != nil {
			t.Fatal(err)
		}
		if err = retirementForwardQuietTx(ctx, tx, x, own.RunID.String(), ""); err != nil {
			t.Fatal("closed competing workflow must isolate the dispatch barrier", fault, err)
		}
		if err = retirementForwardContinuationQuietTx(ctx, tx, x, "", own.RunID.String()); !errors.Is(err, ErrCapacityConflict) || quietSQL() {
			t.Fatal("genuine unresolved competing dispatch became quiet", fault, err)
		}
		if _, err = tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT unresolved_owner"); err != nil {
			t.Fatal(err)
		}
	}
	// A real ordinary version append leaves the historical policy immutable
	// and inactive, matching production after the normal 3/.25 restoration.
	p := f.p
	p.Signals = append([]model.CapacitySignalRule(nil), f.p.Signals...)
	for i := range p.Signals {
		p.Signals[i].UpAbove, p.Signals[i].DownBelow = 3, 0.25
	}
	enabled := true
	spec := installedTimeoutWire(t, p)
	newPolicy, err := CreateManifestVersionTx(ctx, tx, model.ManifestDocument{APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: f.policy.Metadata.Namespace, Name: f.policy.Metadata.Name, Active: &enabled}, Spec: spec}, capacity.BusinessCreationSHA256(spec))
	if err != nil || newPolicy.ID == f.policy.ID || newPolicy.Version != f.policy.Version+1 {
		t.Fatal("ordinary compatible append-only policy publication", err)
	}
	var oldActive bool
	if err = tx.QueryRowContext(ctx, "SELECT active FROM public.manifests WHERE id=$1", f.policy.ID).Scan(&oldActive); err != nil || oldActive {
		t.Fatal("actual original policy must now be inactive", oldActive, err)
	}
	requireQuiet("after compatible policy version append")
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeOriginals, preActionPlanOriginals(t, f, CapacityDispatchJob{CapacityDispatchEnvelope: CapacityDispatchEnvelope{JobID: uuid.MustParse(plan.JobID)}})) {
		t.Fatal("typed quiet regression rewrote immutable history")
	}
	dir := os.Getenv("PREACTION_PLAN_LOGS")
	if dir == "" {
		t.Fatal("existing M99 evidence directory required")
	}
	result := map[string]any{"schema": "typed_M98_M99_retirement_quiet_schema101_fixture_v1", "schema_version": 101, "old_go_busy_count": oldBusy, "old_sql_quiet": false, "new_full_go_and_sql_quiet": true, "genuine_M98_job": anchor.JobID, "genuine_M99_job": plan.JobID, "real_started_requester": own.RunID.String(), "forged_or_missing_receipts_refused": true, "unknown_and_returned_without_ack_refused": true, "inactive_original_policy_historical_validators_passed": true, "originals_unchanged": true, "fixture_only": true, "native_cloud": false, "Root_acceptance": false}
	for name, raw := range map[string][]byte{"M101-PG-BEFORE100-CATALOG.original.json": beforeCatalog, "M101-PG-AFTER101-CATALOG.original.json": afterCatalog, "M101-TYPED-TERMINAL-QUIET.RESULT.PUBLIC.json": installedTimeoutWire(t, result)} {
		out, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = out.Write(raw); err == nil {
			err = out.Sync()
		}
		closeErr := out.Close()
		if err != nil || closeErr != nil {
			t.Fatal("whole schema101 CI originals", err, closeErr)
		}
	}
}

// Only the candidate-job operand is replaced by a declared composite value in
// pg_temp. The actual owning job, full production quiet body, public immutable
// ledgers and strict validators remain intact. No stored terminal is forged.
func retirementContinuation101SQLCandidateFaults(t *testing.T, tx *sql.Tx, frame []byte, own uuid.UUID, ids []uuid.UUID) {
	t.Helper()
	var definition string
	if err := tx.QueryRow("SELECT pg_get_functiondef('public.retirement_forward_continuation_quiet(jsonb,uuid)'::regprocedure)").Scan(&definition); err != nil {
		t.Fatal(err)
	}
	const oldName = "FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid)"
	const newName = "FUNCTION pg_temp.retirement_quiet_candidate_fixture(r jsonb, own uuid, candidate jsonb)"
	const from = "AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND"
	const to = "AND NOT EXISTS(SELECT 1 FROM (SELECT (jsonb_populate_record(NULL::public.capacity_dispatch_jobs,candidate)).*) j WHERE j.run_id IS DISTINCT FROM own AND"
	if strings.Count(definition, oldName) != 1 || strings.Count(definition, from) != 1 {
		t.Fatal("exact SQL candidate operand seam required")
	}
	declared := strings.Replace(strings.Replace(definition, oldName, newName, 1), from, to, 1)
	if strings.Replace(strings.Replace(declared, newName, oldName, 1), to, from, 1) != definition {
		t.Fatal("whole SQL candidate inverse differs")
	}
	if _, err := tx.Exec(declared); err != nil {
		t.Fatal("declared SQL operand fixture", err)
	}
	for _, id := range ids {
		var raw []byte
		if err := tx.QueryRow("SELECT to_jsonb(j) FROM public.capacity_dispatch_jobs j WHERE id=$1", id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		for _, fault := range []string{"genuine_control", "missing_receipt", "foreign_terminal_kind", "false_ack", "foreign_timestamp"} {
			var candidate map[string]any
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing_receipt":
				candidate["id"], candidate["run_id"] = uuid.NewString(), uuid.NewString()
			case "foreign_terminal_kind":
				if candidate["state"] == CapacityDispatchInstalledProvisionTimeoutState {
					candidate["state"] = CapacityDispatchPreActionPlanState
				} else {
					candidate["state"] = CapacityDispatchInstalledProvisionTimeoutState
				}
			case "false_ack":
				candidate["finalization_ack_at"] = time.Now().UTC().Format(time.RFC3339Nano)
			case "foreign_timestamp":
				candidate["updated_at"] = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
			}
			var quiet bool
			if err := tx.QueryRow("SELECT pg_temp.retirement_quiet_candidate_fixture($1::jsonb,$2::uuid,$3::jsonb)", string(frame), own, string(installedTimeoutWire(t, candidate))).Scan(&quiet); err != nil || quiet != (fault == "genuine_control") {
				t.Fatal("independent SQL terminal authentication", fault, quiet, err)
			}
		}
	}
}

func retirementContinuation101Catalog(t *testing.T, before, after []byte) {
	t.Helper()
	var old, next map[string]json.RawMessage
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(after, &next) != nil || len(old) != len(next) {
		t.Fatal("complete before100/after101 catalogs required")
	}
	for k, v := range old {
		if k != "functions" && k != "history_wire" && !reflect.DeepEqual(v, next[k]) {
			t.Fatal("schema101 changed unrelated catalog", k)
		}
	}
	var oldFn, nextFn []map[string]any
	if json.Unmarshal(old["functions"], &oldFn) != nil || json.Unmarshal(next["functions"], &nextFn) != nil || len(oldFn) != len(nextFn) {
		t.Fatal("schema101 must not add or remove functions")
	}
	changed := 0
	for i, f := range oldFn {
		if !reflect.DeepEqual(f, nextFn[i]) {
			if f["name"] != "retirement_forward_continuation_quiet" || f["name"] != nextFn[i]["name"] || f["arguments"] != nextFn[i]["arguments"] {
				t.Fatal("schema101 changed unrelated function", f["name"])
			}
			changed++
		}
	}
	var oldWire, nextWire string
	var oldHistory, nextHistory []map[string]any
	if json.Unmarshal(old["history_wire"], &oldWire) != nil || json.Unmarshal(next["history_wire"], &nextWire) != nil || json.Unmarshal([]byte(oldWire), &oldHistory) != nil || json.Unmarshal([]byte(nextWire), &nextHistory) != nil || len(nextHistory) != len(oldHistory)+1 || !reflect.DeepEqual(oldHistory, nextHistory[:len(oldHistory)]) || nextHistory[len(oldHistory)]["version_id"] != float64(101) || nextHistory[len(oldHistory)]["is_applied"] != true || changed != 1 {
		t.Fatal("sole history101 append and sole quiet-function change required")
	}
}
