package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Uses the parent's explicit isolated Unix-socket fixture. No second database
// helper, production DSN, provider operation or runtime adoption is introduced.
func migration73Record(t *testing.T, ctx context.Context, tx *sql.Tx, f failedOriginalFixture) (model.CapacityFailedOriginalDisposition, failedOriginalDispositionSnapshot) {
	t.Helper()
	s, err := loadFailedOriginalDispositionSnapshot(ctx, tx, f.pre.OriginalCreateGrantID, f.jobID.String())
	if err != nil {
		t.Fatal("snapshot", err)
	}
	o := f.absent(t, s.candidate)
	r := model.CapacityFailedOriginalDisposition{
		Schema: model.FailedOriginalDispositionSchema, ID: uuid.NewString(), GrantID: f.pre.OriginalCreateGrantID,
		PreregistrationID: f.pre.PreregistrationID, JobID: f.jobID.String(), RunID: f.runID.String(), Issuer: "collaborator:" + uuid.NewString(),
		OriginalGrantSHA256: s.candidate.OriginalGrantSHA256, OriginalPreregistrationSHA256: s.candidate.OriginalPreregistrationSHA256,
		OriginalWitnessSHA256: s.witnessSHA, OriginalDispatchSHA256: s.dispatchSHA, OriginalRunSHA256: s.runSHA,
		ClosedGeneration: s.intent.Generation, ClosedFencingToken: s.intent.FencingToken + 1, RecordedAt: s.now,
		Observation: o, OriginalAcceptedUnchanged: true, OriginalWitnessPreserved: true, OriginalUnknownACKPreserved: true,
		HistoricalWriterStartState: "unknown", ServingOrBusinessOrSavingsAuthority: false,
	}
	return r, s
}

func migration73Insert(tx *sql.Tx, r model.CapacityFailedOriginalDisposition) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_failed_original_dispositions
	 (id,grant_id,preregistration_id,job_id,run_id,original_grant_sha256,original_preregistration_sha256,original_witness_sha256,original_dispatch_sha256,original_run_sha256,disposition_sha256,original_wire,disposition_record,recorded_at,closed_generation,closed_fencing_token)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16)`,
		r.ID, r.GrantID, r.PreregistrationID, r.JobID, r.RunID, r.OriginalGrantSHA256, r.OriginalPreregistrationSHA256, r.OriginalWitnessSHA256, r.OriginalDispatchSHA256, r.OriginalRunSHA256,
		originalDispositionDigest(raw), raw, string(raw), r.RecordedAt, r.ClosedGeneration, r.ClosedFencingToken)
	return err
}

func migration73Projections(t *testing.T, tx *sql.Tx, r model.CapacityFailedOriginalDisposition, s failedOriginalDispositionSnapshot, omit string) {
	t.Helper()
	if omit != "grant" {
		if _, err := tx.Exec(`UPDATE public.capacity_mutation_grants SET failed_original_disposition_id=$2 WHERE id=$1`, r.GrantID, r.ID); err != nil {
			t.Fatal("grant projection", err)
		}
	}
	if omit != "job" {
		if _, err := tx.Exec(`UPDATE public.capacity_dispatch_jobs SET state='failed_disposed',failed_original_disposition_id=$2,updated_at=clock_timestamp() WHERE id=$1`, r.JobID, r.ID); err != nil {
			t.Fatal("job projection", err)
		}
	}
	if omit != "intent" {
		i := s.intent
		i.Phase = "reconciled_failed_floor"
		i.FloorDegraded = true
		i.RecoveryOnly = false
		i.Decision.ExecutionPermitted = false
		i.FencingToken = r.ClosedFencingToken
		i.LeaseOwner = ""
		i.LeaseExecutorID = ""
		i.LeaseExpiresAt = nil
		raw, err := json.Marshal(i)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(`UPDATE public.capacity_intents SET intent=$5::jsonb WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, i.Namespace, i.Environment, i.Domain, i.Dimension, string(raw)); err != nil {
			t.Fatal("intent projection", err)
		}
	}
}

func TestFailedOriginalDispositionMigration73DeferredLinks(t *testing.T) {
	db := originalDispositionPG(t)
	for _, omit := range []string{"grant", "job", "intent", "none"} {
		t.Run(omit, func(t *testing.T) {
			f := failedOriginalPGFixture(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			r, s := migration73Record(t, ctx, tx, f)
			// Savepoint is legitimate same-transaction insertion, not a replay epoch.
			if _, err = tx.Exec(`SAVEPOINT terminal_insert`); err != nil {
				t.Fatal(err)
			}
			if err = migration73Insert(tx, r); err != nil {
				t.Fatal("insert", err)
			}
			if _, err = tx.Exec(`RELEASE SAVEPOINT terminal_insert`); err != nil {
				t.Fatal(err)
			}
			migration73Projections(t, tx, r, s, omit)
			_, err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`)
			if (err == nil) != (omit == "none") {
				t.Fatalf("incomplete terminal links accepted or full same-commit refused: omit=%s err=%v", omit, err)
			}
		})
	}
}

func TestFailedOriginalDispositionMigration73DirectInsertGuards(t *testing.T) {
	db := originalDispositionPG(t)
	for _, name := range []string{"grant_hash", "pre_hash", "witness_hash", "dispatch_hash", "run_hash", "witness_preserved", "ACK_preserved", "writer_started", "serving_authority", "auxiliary_identity"} {
		t.Run(name, func(t *testing.T) {
			f := failedOriginalPGFixture(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			r, _ := migration73Record(t, ctx, tx, f)
			switch name {
			case "grant_hash":
				r.OriginalGrantSHA256 = strings.Repeat("0", 64)
			case "pre_hash":
				r.OriginalPreregistrationSHA256 = strings.Repeat("0", 64)
			case "witness_hash":
				r.OriginalWitnessSHA256 = strings.Repeat("0", 64)
			case "dispatch_hash":
				r.OriginalDispatchSHA256 = strings.Repeat("0", 64)
			case "run_hash":
				r.OriginalRunSHA256 = strings.Repeat("0", 64)
			case "witness_preserved":
				r.OriginalWitnessPreserved = false
			case "ACK_preserved":
				r.OriginalUnknownACKPreserved = false
			case "writer_started":
				r.HistoricalWriterStartState = "never_started"
			case "serving_authority":
				r.ServingOrBusinessOrSavingsAuthority = true
			case "auxiliary_identity":
				r.Observation.AuxiliaryResources[0].ID = "foreign-original"
			}
			if err = migration73Insert(tx, r); err == nil {
				t.Fatal("forged terminal insert accepted", name)
			}
		})
	}
}

// The owning workflow-run INSERT omits workflow_id. SQL must preserve that
// legitimate NULL while authenticating the complete result and still finding
// active work admitted by the same selector with a NULL workflow_id.
func TestFailedOriginalDispositionMigration73WorkflowIdentityAndActiveWork(t *testing.T) {
	db := originalDispositionPG(t)
	cases := []struct {
		name  string
		allow bool
	}{
		{"null_id", true},
		{"matching_id", true},
		{"foreign_nonnull_id", false},
		{"missing_result_workflow", false},
		{"wrong_result_id", false},
		{"wrong_result_namespace", false},
		{"wrong_result_name", false},
		{"wrong_result_version", false},
		{"active_null_selector", false},
		{"active_exact_id", false},
		{"active_foreign_nonnull_id", true},
		{"active_null_foreign_selector", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := failedOriginalPGFixture(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			// Obtain a valid real snapshot first. Mutations below then exercise
			// the SQL insert guard rather than only the repository validator.
			r, snapshot := migration73Record(t, ctx, tx, f)
			var columnID sql.NullString
			if err = tx.QueryRow(`SELECT workflow_id::text FROM public.workflow_runs WHERE id=$1`, f.runID).Scan(&columnID); err != nil || columnID.Valid {
				t.Fatal("owning INSERT fixture must preserve historical NULL", err)
			}
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := tx.Exec(query, args...); err != nil {
					t.Fatal("declared SQL test setup", err)
				}
			}
			switch c.name {
			case "matching_id":
				exec(`UPDATE public.workflow_runs SET workflow_id=$2 WHERE id=$1`, f.runID, f.record.WorkflowID)
			case "foreign_nonnull_id":
				exec(`UPDATE public.workflow_runs SET workflow_id=$2 WHERE id=$1`, f.runID, uuid.New())
			case "missing_result_workflow":
				exec(`UPDATE public.workflow_runs SET result=result-'workflow' WHERE id=$1`, f.runID)
			case "wrong_result_id":
				exec(`UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,id}',to_jsonb($2::text)) WHERE id=$1`, f.runID, uuid.NewString())
			case "wrong_result_namespace":
				exec(`UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,namespace}',to_jsonb($2::text)) WHERE id=$1`, f.runID, "foreign-namespace")
			case "wrong_result_name":
				exec(`UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,name}',to_jsonb($2::text)) WHERE id=$1`, f.runID, "foreign-name")
			case "wrong_result_version":
				exec(`UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,version}','999'::jsonb) WHERE id=$1`, f.runID)
			case "active_null_selector", "active_exact_id", "active_foreign_nonnull_id", "active_null_foreign_selector":
				var activeID any
				activeName := "original"
				switch c.name {
				case "active_exact_id":
					activeID, activeName = f.record.WorkflowID, "different-selector-same-known-id"
				case "active_foreign_nonnull_id":
					activeID = uuid.New()
				case "active_null_foreign_selector":
					activeName = "unrelated-selector"
				}
				exec(`INSERT INTO public.workflow_runs(id,workflow_id,workflow_namespace,workflow_name,workflow_version,status)
				 SELECT $2,$3::uuid,workflow_namespace,$4,workflow_version,'pending' FROM public.workflow_runs WHERE id=$1`, f.runID, uuid.New(), activeID, activeName)
			}
			// Reclose the exact current row hash so malformed identities cannot
			// be refused merely because a stale snapshot digest was supplied.
			if err = tx.QueryRow(`SELECT encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') FROM public.workflow_runs w WHERE id=$1`, f.runID).Scan(&r.OriginalRunSHA256); err != nil {
				t.Fatal(err)
			}
			err = migration73Insert(tx, r)
			if !c.allow {
				if err == nil {
					t.Fatal("foreign result or active original work accepted", c.name)
				}
				return
			}
			if err != nil {
				t.Fatal("legitimate nullable workflow identity refused", c.name, err)
			}
			migration73Projections(t, tx, r, snapshot, "none")
			if _, err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
				t.Fatal("complete legitimate nullable terminal refused", c.name, err)
			}
		})
	}
}

func TestFailedOriginalDispositionMigration73ClosedHistoryAndLateOwnership(t *testing.T) {
	db := originalDispositionPG(t)
	f := failedOriginalPGFixture(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.store.CompleteFailedOriginalDisposition(ctx, owner, f.absent(t, owner.Candidate()))
	if err != nil {
		t.Fatal(err)
	}
	var originalJob string
	if err = db.QueryRow(`SELECT to_jsonb(j)::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, f.jobID).Scan(&originalJob); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, query string
		args        []any
	}{
		{"ledger_update", `UPDATE public.capacity_failed_original_dispositions SET recorded_at=clock_timestamp() WHERE id=$1`, []any{r.ID}},
		{"ledger_delete", `DELETE FROM public.capacity_failed_original_dispositions WHERE id=$1`, []any{r.ID}},
		{"grant_rewrite", `UPDATE public.capacity_mutation_grants SET grant_record=jsonb_set(grant_record,'{state}','"expired"') WHERE id=$1`, []any{r.GrantID}},
		{"grant_reset", `UPDATE public.capacity_mutation_grants SET failed_original_disposition_id=NULL WHERE id=$1`, []any{r.GrantID}},
		{"job_return", `UPDATE public.capacity_dispatch_jobs SET return_error='new result' WHERE id=$1`, []any{r.JobID}},
		{"job_deadline", `UPDATE public.capacity_dispatch_jobs SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, []any{r.JobID}},
		{"job_ACK", `UPDATE public.capacity_dispatch_jobs SET finalization_ack_at=clock_timestamp() WHERE id=$1`, []any{r.JobID}},
		{"job_reopen", `UPDATE public.capacity_dispatch_jobs SET state='unknown',failed_original_disposition_id=NULL WHERE id=$1`, []any{r.JobID}},
		{"job_delete", `DELETE FROM public.capacity_dispatch_jobs WHERE id=$1`, []any{r.JobID}},
		{"run_success", `UPDATE public.workflow_runs SET status='succeeded' WHERE id=$1`, []any{r.RunID}},
		{"late_enroll", `INSERT INTO public.capacity_vm_original_enrollments(preregistration_id) VALUES($1)`, []any{r.PreregistrationID}},
		{"late_install", `INSERT INTO public.capacity_guest_original_installations(preregistration_id) VALUES($1)`, []any{r.PreregistrationID}},
		{"late_factory", `INSERT INTO public.capacity_factory_original_grant_bindings(grant_id) VALUES($1)`, []any{r.GrantID}},
		{"late_retirement", `INSERT INTO public.capacity_vm_retirement_intents(id,preregistration_id) VALUES($1,$2)`, []any{uuid.New(), r.PreregistrationID}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := db.Exec(c.query, c.args...); err == nil {
				t.Fatal("closed original rewritten or adopted", c.name)
			}
		})
	}
	var grant, afterJob, run string
	if err = db.QueryRow(`SELECT grant_record::text FROM public.capacity_mutation_grants WHERE id=$1`, r.GrantID).Scan(&grant); err != nil || grant != f.rawGrant {
		t.Fatal("accepted original changed", err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(j)::text FROM public.capacity_dispatch_jobs j WHERE id=$1`, f.jobID).Scan(&afterJob); err != nil || afterJob != originalJob {
		t.Fatal("original return changed", err)
	}
	if err = db.QueryRow(`SELECT to_jsonb(w)::text FROM public.workflow_runs w WHERE id=$1`, f.runID).Scan(&run); err != nil || run != f.originalRun {
		t.Fatal("original failed workflow changed", err)
	}
	// A distinct independently owned next history is not blocked by old pointers.
	next := failedOriginalPGFixture(t, db)
	// A complete declared enrollment in the distinct next history must remain
	// insertable; sparse rows fail schema63 before testing terminal isolation.
	enrolledFailedSQLRecordFromFixture(t, db, next)
}
