//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

func installedReadinessCatalog(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	const query = `SELECT jsonb_build_object(
 'server_version_num',current_setting('server_version_num')::int,
 'history_wire',(SELECT json_agg(row_to_json(g) ORDER BY id)::text FROM public.goose_db_version g),
 'functions',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname COLLATE "C",pg_get_function_identity_arguments(p.oid) COLLATE "C"),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind='f'),
 'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',c.conname,'kind',c.contype,'validated',c.convalidated,'deferrable',c.condeferrable,'deferred',c.condeferred,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY r.relname COLLATE "C",c.conname COLLATE "C"),'[]'::jsonb) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public'),
 'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',g.tgname,'enabled',g.tgenabled,'definition',pg_get_triggerdef(g.oid,false)) ORDER BY r.relname COLLATE "C",g.tgname COLLATE "C"),'[]'::jsonb) FROM pg_trigger g JOIN pg_class r ON r.oid=g.tgrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND NOT g.tgisinternal),
 'columns',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'default',pg_get_expr(d.adbin,d.adrelid),'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE a.attcollation::regcollation::text END) ORDER BY r.relname COLLATE "C",a.attnum),'[]'::jsonb) FROM pg_attribute a JOIN pg_class r ON r.oid=a.attrelid JOIN pg_namespace n ON n.oid=r.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND r.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped),
 'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',x.relname,'unique',i.indisunique,'primary',i.indisprimary,'valid',i.indisvalid,'ready',i.indisready,'definition',pg_get_indexdef(i.indexrelid,0,false)) ORDER BY r.relname COLLATE "C",x.relname COLLATE "C"),'[]'::jsonb) FROM pg_index i JOIN pg_class r ON r.oid=i.indrelid JOIN pg_class x ON x.oid=i.indexrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public'))::text`
	var raw []byte
	if err := db.QueryRow(query).Scan(&raw); err != nil {
		t.Fatal("complete all-public PG handoff catalog", err)
	}
	return raw
}

func installedReadinessMigrationCatalog(t *testing.T, f *installedTimeoutFixture) {
	t.Helper()
	put := func(name string, raw []byte) map[string]any {
		t.Helper()
		dir := os.Getenv("INSTALLED_TIMEOUT_LOGS")
		if dir == "" {
			return nil
		}
		path := filepath.Join(dir, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := file.Write(raw); err != nil || n != len(raw) {
			file.Close()
			t.Fatal("whole catalog original", n, err)
		}
		if err = file.Sync(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		return map[string]any{"path": path, "sha256": capacity.BusinessCreationSHA256(raw), "bytes": len(raw)}
	}
	root := failedServingRepositoryRoot(t) + "/db/migrations"
	if err := goose.UpToContext(context.Background(), f.db, root, 99); err != nil {
		t.Fatal("actual complete schema99 predecessor", err)
	}
	before := installedReadinessCatalog(t, f.db)
	beforeRef := put("M100-PG-BEFORE99-CATALOG.original.json", before)
	if err := goose.UpToContext(context.Background(), f.db, root, 100); err != nil {
		t.Fatal("actual append-only handoff schema", err)
	}
	after := installedReadinessCatalog(t, f.db)
	afterRef := put("M100-PG-AFTER100-CATALOG.original.json", after)
	type row map[string]any
	type catalog struct {
		Version     int    `json:"server_version_num"`
		History     string `json:"history_wire"`
		Functions   []row  `json:"functions"`
		Constraints []row  `json:"constraints"`
		Triggers    []row  `json:"triggers"`
		Columns     []row  `json:"columns"`
		Indexes     []row  `json:"indexes"`
	}
	var old, next catalog
	if json.Unmarshal(before, &old) != nil || json.Unmarshal(after, &next) != nil || old.Version != next.Version || (next.Version/10000 != 16 && next.Version/10000 != 17) {
		t.Fatal("whole PG16/17 before99/after100 catalog required")
	}
	var priorHistory, currentHistory []row
	if json.Unmarshal([]byte(old.History), &priorHistory) != nil || json.Unmarshal([]byte(next.History), &currentHistory) != nil || len(priorHistory) == 0 || priorHistory[len(priorHistory)-1]["version_id"] != float64(99) || len(currentHistory) != len(priorHistory)+1 || !reflect.DeepEqual(priorHistory, currentHistory[:len(priorHistory)]) || currentHistory[len(priorHistory)]["version_id"] != float64(100) || currentHistory[len(priorHistory)]["is_applied"] != true {
		t.Fatal("M100 did not solely append to whole M99 history")
	}
	key := func(r row) string { return r["name"].(string) + "(" + r["arguments"].(string) + ")" }
	oldFunctions, nextFunctions := map[string]row{}, map[string]row{}
	for _, fn := range old.Functions {
		oldFunctions[key(fn)] = fn
	}
	for _, fn := range next.Functions {
		nextFunctions[key(fn)] = fn
	}
	changed, added := []string{}, []string{}
	for name, fn := range oldFunctions {
		got, exists := nextFunctions[name]
		if !exists || !reflect.DeepEqual(fn, got) && fn["name"] != "guard_installed_timeout_origin" {
			t.Fatal("M100 changed unrelated prior function", name)
		}
		if !reflect.DeepEqual(fn, got) {
			changed = append(changed, fn["name"].(string))
		}
	}
	for name, fn := range nextFunctions {
		if _, exists := oldFunctions[name]; !exists {
			added = append(added, fn["name"].(string))
		}
	}
	want := []string{"immutable_installed_readiness_handoff", "installed_readiness_failed_ack_valid", "installed_readiness_closed_canaries_valid", "installed_readiness_handoff_valid", "installed_readiness_handoff_members_match", "guard_installed_readiness_handoff_insert", "installed_readiness_handoff_fresh_canaries", "installed_readiness_handoff_transition", "guard_installed_readiness_handoff_intent", "require_installed_readiness_handoff_links", "guard_installed_readiness_handoff_no_grant", "guard_installed_readiness_handoff_history"}
	sort.Strings(want)
	sort.Strings(added)
	if !reflect.DeepEqual(added, want) || !reflect.DeepEqual(changed, []string{"guard_installed_timeout_origin"}) {
		t.Fatal("exact12 new functions and sole narrow M98 replacement required", added, changed)
	}
	const table = "capacity_installed_readiness_exhausted_handoffs"
	historical := func(rows []row) []row {
		out := []row{}
		for _, r := range rows {
			if r["table"] != table {
				out = append(out, r)
			}
		}
		return out
	}
	if !reflect.DeepEqual(old.Constraints, historical(next.Constraints)) || !reflect.DeepEqual(old.Columns, historical(next.Columns)) || !reflect.DeepEqual(old.Indexes, historical(next.Indexes)) {
		t.Fatal("M100 changed an old public constraint, column or index")
	}
	for _, constraint := range next.Constraints {
		if constraint["validated"] != true {
			t.Fatal("unvalidated public constraint after M100", constraint["name"])
		}
	}
	columns := []string{}
	for _, column := range next.Columns {
		if column["table"] == table {
			columns = append(columns, column["name"].(string))
		}
	}
	wantColumns := []string{"id", "original_disposition_id", "namespace", "environment", "domain", "dimension", "original_record", "original_wire", "record_sha256", "original_intent_wire", "failed_jobs_wire", "failed_runs_wire", "previous_canaries_wire", "members_wire", "marker_wire", "successor_intent_wire", "successor_job_id", "successor_run_id", "recorded_at"}
	if !reflect.DeepEqual(columns, wantColumns) {
		t.Fatal("exact new19-column archive required", columns)
	}
	triggers := map[string]row{}
	for _, trigger := range next.Triggers {
		triggers[trigger["table"].(string)+"/"+trigger["name"].(string)] = trigger
	}
	for _, trigger := range old.Triggers {
		name := trigger["table"].(string) + "/" + trigger["name"].(string)
		if !reflect.DeepEqual(trigger, triggers[name]) {
			t.Fatal("M100 changed historical trigger", name)
		}
		delete(triggers, name)
	}
	wantTriggers := []string{table + "/installed_readiness_handoff_insert", table + "/installed_readiness_handoff_immutable", table + "/installed_readiness_handoff_complete_links", "capacity_intents/installed_readiness_handoff_intent", "capacity_mutation_grants/installed_readiness_handoff_no_grant", "capacity_dispatch_jobs/installed_readiness_handoff_failed_job", "workflow_runs/installed_readiness_handoff_failed_run"}
	if len(triggers) != len(wantTriggers) {
		t.Fatal("exact7 new triggers required", len(triggers))
	}
	for _, name := range wantTriggers {
		if triggers[name] == nil || triggers[name]["enabled"] != "O" {
			t.Fatal("required enabled M100 trigger missing", name)
		}
	}
	if os.Getenv("INSTALLED_TIMEOUT_LOGS") != "" {
		proof := map[string]any{"schema": "installed_readiness_handoff_schema100_pg_catalog_v1", "source_commit": capacity.CurrentGuestCoreSource(), "postgres_major": next.Version / 10000, "before99_ref": beforeRef, "after100_ref": afterRef, "whole_history_sole100_append": true, "old_public_functions_changed": changed, "new_public_functions": added, "all_old_constraints_columns_indexes_unchanged": true, "all_old_triggers_unchanged": true, "new_table_columns": columns, "new_triggers": wantTriggers, "all_constraints_validated": true, "fixture_only": true, "native_authority": false, "production_authority": false}
		put("M100-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", append(installedTimeoutWire(t, proof), '\n'))
	}
}

// Declared old issuer operands are installed before the original INSERTs.
// The genuine test build and every immutable historical row remain unchanged.
func installedReadinessFixtureOldIssuer(t *testing.T, f *installedTimeoutFixture) func() {
	t.Helper()
	installedReadinessMigrationCatalog(t, f)
	old := "d083f7d5d52e15c22feb38fff56e024354ac86ae"
	release := registerInstalledReadinessFixtureIssuer(t, f.db, f.policy.ID, f.workflow.ID, old)
	s := CapacityStore{DB: f.db, WorkflowID: f.workflow.ID}
	if guestAuthorityIssueSource(s, f.policy, "installed_reconcile") != old {
		t.Fatal("declared old fixture issuer was not scoped")
	}
	otherDB, otherWorkflow, otherPolicy := s, s, f.policy
	otherDB.DB = new(sql.DB)
	otherWorkflow.WorkflowID = uuid.New()
	otherPolicy.ID = uuid.New()
	for _, got := range []string{guestAuthorityIssueSource(otherDB, f.policy, "installed_reconcile"), guestAuthorityIssueSource(otherWorkflow, f.policy, "installed_reconcile"), guestAuthorityIssueSource(s, otherPolicy, "installed_reconcile"), guestAuthorityIssueSource(s, f.policy, "canary_challenge")} {
		if got != capacity.CurrentGuestCoreSource() {
			t.Fatal("declared fixture issuer leaked outside its exact scope")
		}
	}
	return func() {
		release()
		if guestAuthorityIssueSource(s, f.policy, "installed_reconcile") != capacity.CurrentGuestCoreSource() {
			t.Fatal("declared old issuer remained after release")
		}
	}
}

func installedReadinessCompletionOperands(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob, intent model.CapacityIntent) (CapacityStore, model.CapacityAssessment) {
	t.Helper()
	now := time.Now().UTC()
	inv := f.inventory(t, len(f.reg), now)
	snapshot, err := capacity.GuestReconcileSnapshot(f.policy, f.p, inv, now)
	if err != nil {
		t.Fatal(err)
	}
	a := model.CapacityAssessment{Snapshot: snapshot}
	for _, signal := range f.p.Signals {
		value := 0.1
		a.Evidence = append(a.Evidence, model.CapacityEvidence{Name: signal.Name, SourceIdentity: signal.SourceIdentity, Unit: signal.Unit, RequireData: true, Matched: true, DataState: "present", Value: &value, RangeMin: &value, RangeMax: &value, SourceSampledAt: now, WindowStart: now.Add(-300 * time.Second), WindowEnd: now, Samples: f.p.MinSamples, CoverageComplete: true, MaxGapSeconds: 5})
	}
	if err = capacity.ValidateAssessment(f.p, a, now); err != nil {
		t.Fatal("declared complete handoff assessment", err)
	}
	var step model.WorkflowStepSpec
	for _, candidate := range f.steps {
		if candidate.ID == "refresh-original-membership" {
			step = candidate
		}
	}
	b := f.p.GuestNotifyReconcileBinding.MemberCoverage
	count := float64(len(f.reg))
	coverage := model.CapacityMetricRangeObservation{Operation: capacity.ObserveMetricRange, Binding: b.BindingName, BindingSHA256: b.BindingSHA256, EvaluatedAt: now, OK: true, Reason: "complete", CapacityEvidence: model.CapacityEvidence{Name: capacity.OriginalGuestMemberCoverageName, SourceIdentity: "production/notify/" + f.p.Profiles[0].Provider + "/reporting-members", Unit: "members", RequireData: true, Matched: true, DataState: "present", Value: &count, RangeMin: &count, RangeMax: &count, SourceSampledAt: now, WindowStart: now.Add(-30 * time.Second), WindowEnd: now, Samples: 7, CoverageComplete: true, MaxGapSeconds: 5}}
	s := CapacityStore{DB: f.db, ExecutionEnabled: true, WorkflowID: f.workflow.ID, OriginalRunID: job.RunID, ExecutorID: intent.LeaseExecutorID}
	return s.WithOriginalGuestReconcile(f.workflow, step, capacity.CurrentGuestCoreSource(), "provision", "", inv, coverage).WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource()), a
}

func installedReadinessNextDispatch(t *testing.T, f *installedTimeoutFixture) CapacityDispatchJob {
	t.Helper()
	e := f.envelope(t)
	queued, merged, err := f.enqueue(e)
	if err != nil || merged || queued.JobID != e.JobID {
		t.Fatal("distinct readiness dispatch", merged, err)
	}
	claimed, err := ClaimCapacityDispatch(context.Background(), f.db, e.Realm, e.Environment, uuid.New(), 30*time.Second)
	if err != nil || claimed.JobID != e.JobID {
		t.Fatal("claim readiness dispatch", err)
	}
	started, err := StartCapacityDispatch(context.Background(), f.db, claimed)
	if err != nil || started.StartedAt == nil || started.LeaseExpiresAt == nil || started.LeaseExpiresAt.Sub(*started.StartedAt) < 4*time.Minute {
		t.Fatal("original five-minute readiness dispatch", err)
	}
	return started
}

func installedReadinessResume(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob, old model.CapacityIntent) model.CapacityIntent {
	t.Helper()
	s, a := installedReadinessCompletionOperands(t, f, job, old)
	s.ExecutorID = uuid.NewString()
	s.guestReconcile.step = f.steps[0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, eligible, err := s.TryResumeInstalledGuest(ctx, f.policy, a)
	if err != nil || !eligible || got.Generation != old.Generation || got.FencingToken != old.FencingToken+1 || got.InstalledGuestReconcile == nil || got.InstalledGuestReconcile.Attempt != old.InstalledGuestReconcile.Attempt+1 || got.InstalledGuestReconcile.NewRunID != job.RunID.String() {
		t.Fatal("genuine next bounded installed resume", eligible, err)
	}
	return got
}

// Reproduce the retained old writer after all original canaries pass. Finish
// ACKs its actual PostgreSQL refusal before the untouched lease expires.
func installedReadinessFailAndACK(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob, intent model.CapacityIntent) {
	t.Helper()
	s, _ := installedReadinessCompletionOperands(t, f, job, intent)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	started := time.Now().UTC().Truncate(time.Microsecond)
	installedReadinessFreshCanaries(t, f, s, intent)
	_, a := installedReadinessCompletionOperands(t, f, job, intent)
	proposed := intent
	proposed.Phase, proposed.Assessment = "prepared", a
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&proposed.UpdatedAt); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	_, phaseErr := tx.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT(namespace,environment,domain,dimension) DO UPDATE SET intent=EXCLUDED.intent,updated_at=EXCLUDED.updated_at`, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, proposed)), proposed.UpdatedAt)
	rollbackErr := tx.Rollback()
	var pg *pq.Error
	if !errors.As(phaseErr, &pg) || string(pg.Code) != "P0001" || pg.Message != "installed timeout readiness requires retained prior intent" || rollbackErr != nil {
		t.Fatal("genuine old-writer phase refusal", phaseErr, rollbackErr)
	}
	returned := time.Now().UTC().Truncate(time.Microsecond)
	response := capacityDispatchResponse(job.CapacityDispatchEnvelope, "failed")
	response.StartedAt, response.FinishedAt = *job.StartedAt, returned
	var wf model.WorkflowManifestSpec
	if err := json.Unmarshal(f.workflow.Spec, &wf); err != nil {
		t.Fatal(err)
	}
	ordered, err := manifestengine.WorkflowExecutionOrder(wf)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range ordered {
		step := model.WorkflowRunStepResult{ID: spec.ID, Kind: "yggdrasil", Operation: manifestengine.NormalizeWorkflowStepOperation(spec), Capability: manifestengine.NormalizeWorkflowStepCapability(spec), Status: "skipped", StartedAt: intent.UpdatedAt, FinishedAt: intent.UpdatedAt}
		if spec.ID == "plan-original-guest" {
			step.Status, step.Attempts, step.StartedAt = "succeeded", 1, *job.StartedAt
			step.Metadata = map[string]any{"mode": "refresh", "reason": "installed_original_readiness_reconcile", "generation": intent.Generation, "fencing_token": intent.FencingToken}
		} else if spec.ID == "refresh-original-membership" {
			step.Status, step.Attempts, step.Error = "failed", 1, "original Guest reconciliation held"
			step.StartedAt, step.FinishedAt = started, returned
			step.Metadata = map[string]any{"original_guest_reconcile_refusal_stage": "advance_prepared"}
		} else {
			step.Metadata = map[string]any{"condition": spec.Condition, "skip_reason": "condition"}
		}
		response.Steps = append(response.Steps, step)
	}
	if err = FinishCapacityDispatch(context.Background(), f.db, job, response, returned, phaseErr); !errors.Is(err, phaseErr) || errors.Is(err, ErrCapacityDispatchUnknown) {
		t.Fatal("actual failed return was not ACKed", err)
	}
	var accepted bool
	if err = f.db.QueryRow(`SELECT j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at IS NOT NULL AND w.status='failed' AND w.finished_at=j.returned_at AND j.lease_expires_at>j.finalization_ack_at FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1`, job.JobID).Scan(&accepted); err != nil || !accepted {
		t.Fatal("whole failed ACK original is incomplete", accepted, err)
	}
}

func installedReadinessWaitNaturalExpiry(t *testing.T, f *installedTimeoutFixture, intent model.CapacityIntent) {
	t.Helper()
	var remaining float64
	if err := f.db.QueryRow("SELECT GREATEST(0,EXTRACT(EPOCH FROM((intent->>'lease_expires_at')::timestamptz-clock_timestamp()))) FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4", f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension).Scan(&remaining); err != nil || remaining > 90 {
		t.Fatal("bounded original readiness lease", remaining, err)
	}
	time.Sleep(time.Duration(remaining*float64(time.Second)) + 2*time.Millisecond)
	var expired, same bool
	if err := f.db.QueryRow("SELECT (intent->>'lease_expires_at')::timestamptz<=clock_timestamp(),intent=$5::jsonb FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4", f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, intent))).Scan(&expired, &same); err != nil || !expired || !same {
		t.Fatal("intent expiry was not natural and byte-preserving", expired, same, err)
	}
}

func installedReadinessFreshCanaries(t *testing.T, f *installedTimeoutFixture, store CapacityStore, intent model.CapacityIntent) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for i, receipt := range f.receipts {
		epoch, usage := intent, "initial_useful_membership"
		if store.guestNotifyMaintenanceOrigin() {
			var err error
			epoch.Generation, epoch.FencingToken, epoch.LeaseOwner, err = store.GuestNotifyMaintenanceEpoch(ctx, f.policy, f.pre[i].PreregistrationID)
			if err != nil {
				t.Fatal("restored policy maintenance epoch", i+1, err)
			}
			usage = "steady_useful_membership"
		}
		var delay float64
		if err := f.db.QueryRow(`SELECT COALESCE(GREATEST(0,EXTRACT(EPOCH FROM(max(recorded_at)+$1*interval '1 second'-clock_timestamp()))),0) FROM public.capacity_guest_notify_canary_challenges WHERE phase='publish' AND preregistration_id=$2`, f.p.GuestNotifyCanaryBinding.MinimumPublicationIntervalSeconds, f.pre[i].PreregistrationID).Scan(&delay); err != nil || delay > float64(f.p.GuestNotifyCanaryBinding.MinimumPublicationIntervalSeconds)+0.1 {
			t.Fatal("bounded genuine publication interval", delay, err)
		}
		if delay > 0 {
			time.Sleep(time.Duration(delay*float64(time.Second)) + 2*time.Millisecond)
		}
		probe := func(c model.CapacityGuestNotifyCanaryChallenge, publication *capacity.GuestNotifyPublicationReply) *capacity.GuestNotifyPublicationReply {
			t.Helper()
			c = capacity.RecoveryFixtureCanaryNonce(t, c, receipt.Enrollment)
			if err := store.FinalizeGuestNotifyCanaryNonce(ctx, f.policy, epoch.Generation, epoch.FencingToken, epoch.LeaseOwner, c, failedServingHTTP(t, c.GuestNonce, time.Now().UTC())); err != nil {
				t.Fatal("handoff nonce", i+1, err)
			}
			if err := store.ReserveGuestNotifyCanarySend(ctx, f.policy, epoch.Generation, epoch.FencingToken, epoch.LeaseOwner, c); err != nil {
				t.Fatal("handoff original send", i+1, err)
			}
			response, facts := capacity.RecoveryFixtureCanaryResponse(t, f.p, c, receipt.Enrollment, publication)
			returned := failedServingHTTP(t, response, response.OriginalReadStartedAt.Add(-time.Millisecond))
			if delay := time.Until(returned.DriverReturnedAt) + time.Millisecond; delay > 0 {
				time.Sleep(delay)
			}
			if _, err := store.RecordGuestNotifyCanaryReturn(ctx, f.policy, epoch.Generation, epoch.FencingToken, epoch.LeaseOwner, c, returned); err != nil {
				t.Fatal("handoff accepted useful original", i+1, err)
			}
			return facts
		}
		pub, err := store.IssueGuestNotifyCanaryPublication(ctx, f.policy, epoch.Generation, epoch.FencingToken, epoch.LeaseOwner, f.pre[i].PreregistrationID, usage, failedServingKey('c'))
		if err != nil {
			t.Fatal("handoff publication", i+1, err)
		}
		facts := probe(pub, nil)
		read, err := store.IssueGuestNotifyCanaryRead(ctx, f.policy, epoch.Generation, epoch.FencingToken, epoch.LeaseOwner, f.pre[i].PreregistrationID, usage, pub.ChallengeID, failedServingKey('c'))
		if err != nil {
			t.Fatal("handoff read", i+1, err)
		}
		probe(read, facts)
	}
}

func installedReadinessArchiveVectors(t *testing.T, f *installedTimeoutFixture, original string) {
	t.Helper()
	clone := func(raw string) map[string]any {
		t.Helper()
		var row map[string]any
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	decode := func(row map[string]any, key string, out any) {
		t.Helper()
		text, ok := row[key].(string)
		if !ok || !strings.HasPrefix(text, `\x`) {
			t.Fatal("whole bytea original required", key)
		}
		raw, err := hex.DecodeString(text[2:])
		if err != nil || json.Unmarshal(raw, out) != nil {
			t.Fatal("closed original bytea JSON", key, err)
		}
	}
	put := func(row map[string]any, key string, value any) []byte {
		raw := installedTimeoutWire(t, value)
		row[key] = `\x` + hex.EncodeToString(raw)
		return raw
	}
	valid := func(row map[string]any, want bool) {
		t.Helper()
		var got bool
		if err := f.db.QueryRow("SELECT public.installed_readiness_handoff_valid(json_populate_record(NULL::public.capacity_installed_readiness_exhausted_handoffs,$1::json))", string(installedTimeoutWire(t, row))).Scan(&got); err != nil || got != want {
			t.Fatal("independent SQL archive validity", got, want, err)
		}
	}
	whole := clone(original)
	valid(whole, true)
	var jobs, runs, markers []map[string]any
	var canaries map[string]json.RawMessage
	decode(whole, "failed_jobs_wire", &jobs)
	decode(whole, "failed_runs_wire", &runs)
	decode(whole, "previous_canaries_wire", &canaries)
	if err := json.Unmarshal(canaries["authority_markers"], &markers); err != nil || len(jobs) != 3 || len(runs) != 3 || len(markers) != 3 {
		t.Fatal("all three whole failed ACK originals required", err)
	}
	for i := range jobs {
		issue := markers[i]["original_record"].(map[string]any)
		markerRaw, err := base64.StdEncoding.DecodeString(issue["installed_reconcile_marker_base64"].(string))
		if err != nil {
			t.Fatal(err)
		}
		marker := clone(string(markerRaw))
		check := func(j, w map[string]any, want bool) {
			t.Helper()
			var got bool
			if err := f.db.QueryRow("SELECT public.installed_readiness_failed_ack_valid($1::jsonb,$2::jsonb,$3::jsonb)", string(installedTimeoutWire(t, j)), string(installedTimeoutWire(t, w)), string(markerRaw)).Scan(&got); err != nil || got != want {
				t.Fatal("independent SQL genuine failed ACK", i+1, got, want, err)
			}
		}
		check(jobs[i], runs[i], true)
		missing := clone(string(installedTimeoutWire(t, jobs[i])))
		missing["finalization_ack_at"] = nil
		check(missing, runs[i], false)
		wrong := clone(string(installedTimeoutWire(t, runs[i])))
		for _, rawStep := range wrong["result"].(map[string]any)["steps"].([]any) {
			step := rawStep.(map[string]any)
			if step["id"] == "refresh-original-membership" {
				step["metadata"].(map[string]any)["original_guest_reconcile_refusal_stage"] = "fresh_original_canary"
			}
		}
		check(jobs[i], wrong, false)
		if marker["attempt"] != float64(i+1) {
			t.Fatal("archive attempts were relabelled", i+1)
		}
	}
	// Rebind the entire hash chain on each hostile proposal. A failure must
	// come from retained originals/semantics rather than a stale digest.
	for _, fault := range []string{"tuple_drift", "same_source", "missing_ACK"} {
		row := clone(original)
		record := row["original_record"].(map[string]any)
		switch fault {
		case "tuple_drift":
			var members []map[string]any
			decode(row, "members_wire", &members)
			members[0]["tuple"].(map[string]any)["resource_id"] = "foreign-installed-member"
			record["members_sha256"] = capacity.BusinessCreationSHA256(put(row, "members_wire", members))
			var matches bool
			if err := f.db.QueryRow("SELECT public.installed_readiness_handoff_members_match(json_populate_record(NULL::public.capacity_installed_readiness_exhausted_handoffs,$1::json))", string(installedTimeoutWire(t, row))).Scan(&matches); err != nil || matches {
				t.Fatal("independent SQL tuple drift was admitted", matches, err)
			}
		case "same_source":
			record["admitting_core_source"] = record["old_issuer_core_source"]
		case "missing_ACK":
			var altered []map[string]any
			decode(row, "failed_jobs_wire", &altered)
			altered[2]["finalization_ack_at"] = nil
			record["failed_jobs_sha256"] = capacity.BusinessCreationSHA256(put(row, "failed_jobs_wire", altered))
		}
		row["record_sha256"] = capacity.BusinessCreationSHA256(put(row, "original_wire", record))
		var marker, successor map[string]any
		decode(row, "marker_wire", &marker)
		marker["handoff_sha256"], marker["core_source"] = row["record_sha256"], record["admitting_core_source"]
		put(row, "marker_wire", marker)
		decode(row, "successor_intent_wire", &successor)
		successor["installed_readiness_handoff"] = marker
		put(row, "successor_intent_wire", successor)
		valid(row, false)
	}
	for _, query := range []string{"UPDATE public.capacity_installed_readiness_exhausted_handoffs SET recorded_at=recorded_at+interval '1 second' WHERE id=$1", "DELETE FROM public.capacity_installed_readiness_exhausted_handoffs WHERE id=$1"} {
		tx, err := f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(query, whole["id"])
		rollbackErr := tx.Rollback()
		var pg *pq.Error
		if !errors.As(err, &pg) || string(pg.Code) != "P0001" || pg.Message != "installed readiness exhausted handoff is immutable" || rollbackErr != nil {
			t.Fatal("immutable handoff history changed", err, rollbackErr)
		}
	}
	var unique bool
	if err := f.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attname='original_disposition_id' WHERE c.conrelid='public.capacity_installed_readiness_exhausted_handoffs'::regclass AND c.contype='u' AND c.conkey=ARRAY[a.attnum]::smallint[])`).Scan(&unique); err != nil || !unique {
		t.Fatal("one permanent archive per M98 origin is not storage-enforced", unique, err)
	}
}

func installedReadinessRefusesProviderGrant(t *testing.T, f *installedTimeoutFixture, generation int64) {
	t.Helper()
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec("INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) SELECT $2,namespace,environment,domain,dimension,$3,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at FROM public.capacity_mutation_grants WHERE id=$1", f.pre[0].OriginalCreateGrantID, uuid.NewString(), generation)
	rollbackErr := tx.Rollback()
	var pg *pq.Error
	if !errors.As(err, &pg) || string(pg.Code) != "P0001" || pg.Message != "readiness handoff generation cannot acquire provider mutation authority" || rollbackErr != nil {
		t.Fatal("readiness-only generation acquired provider authority", err, rollbackErr)
	}
}

// This remains inside the existing eight_members owner process: original300s
// plus three real90s intent leases leaves150s of its unchanged12minute cap.
func (f *installedTimeoutFixture) exhaustedReadinessHandoff(t *testing.T, firstJob CapacityDispatchJob, first model.CapacityIntent, releaseIssuer func()) {
	t.Helper()
	// The retained-marker INSERT refusal is still exercised in this eight-
	// member lane before any genuinely new-generation handoff exists.
	proposed := first
	proposed.Phase = "prepared"
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at) VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT(namespace,environment,domain,dimension) DO UPDATE SET intent=EXCLUDED.intent,updated_at=EXCLUDED.updated_at`, f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, proposed)), proposed.UpdatedAt)
	rollbackErr := tx.Rollback()
	var pg *pq.Error
	if !errors.As(err, &pg) || string(pg.Code) != "P0001" || pg.Message != "installed timeout readiness requires retained prior intent" || rollbackErr != nil {
		t.Fatal("eight-member M98 INSERT refusal changed", err, rollbackErr)
	}
	before := f.preserved(t)
	job, current := firstJob, first
	var successorJob CapacityDispatchJob
	for attempt := 1; attempt <= 3; attempt++ {
		if current.InstalledGuestReconcile == nil || current.InstalledGuestReconcile.Attempt != attempt {
			t.Fatal("attempt was not created by the actual bounded resume", attempt)
		}
		installedReadinessFailAndACK(t, f, job, current)
		if attempt == 3 {
			releaseIssuer()
			successorJob = installedReadinessNextDispatch(t, f)
			s, a := installedReadinessCompletionOperands(t, f, successorJob, current)
			s.ExecutorID = uuid.NewString()
			s.guestReconcile.step = f.steps[0]
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, _, eligible, claimErr := s.TryClaimInstalledReadinessHandoff(ctx, f.policy, a)
			cancel()
			if eligible {
				t.Fatal("live third intent lease was archived", claimErr)
			}
		}
		installedReadinessWaitNaturalExpiry(t, f, current)
		if attempt < 3 {
			job = installedReadinessNextDispatch(t, f)
			current = installedReadinessResume(t, f, job, current)
		}
	}
	afterAttempts := f.preserved(t)
	for table, raw := range before {
		if strings.HasPrefix(table, "capacity_guest_notify_canary_") {
			if raw != "[]" {
				t.Fatal("old source-assessment fixture unexpectedly had canary originals", table)
			}
			continue
		}
		if afterAttempts[table] != raw {
			t.Fatal("three failed ACKs changed old provider/Guest originals", table)
		}
	}
	for _, table := range []string{"capacity_guest_notify_canary_challenges", "capacity_guest_notify_canary_returns", "capacity_guest_notify_canary_sends"} {
		var count int
		if err := f.db.QueryRow("SELECT count(*) FROM public." + table).Scan(&count); err != nil || count != 3*2*len(f.reg) {
			t.Fatal("all three old attempts must retain all publish/read originals", table, count, err)
		}
	}
	s, a := installedReadinessCompletionOperands(t, f, successorJob, current)
	s.ExecutorID = uuid.NewString()
	s.guestReconcile.step = f.steps[0]
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if _, eligible, err := s.TryResumeInstalledGuest(ctx, f.policy, a); err != nil || eligible {
		t.Fatal("ordinary fourth resume was admitted", eligible, err)
	}
	unchanged := func() {
		t.Helper()
		var count int
		var same bool
		if err := f.db.QueryRow("SELECT count(*) FROM public.capacity_installed_readiness_exhausted_handoffs").Scan(&count); err != nil || count != 0 {
			t.Fatal("refused handoff left an archive", count, err)
		}
		if err := f.db.QueryRow("SELECT intent=$5::jsonb FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4", f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, current))).Scan(&same); err != nil || !same {
			t.Fatal("refused handoff changed exhausted epoch", same, err)
		}
	}
	for _, fault := range []string{"execution_off", "foreign_source", "incomplete_inventory"} {
		candidate := s
		private := *s.guestReconcile
		candidate.guestReconcile = &private
		switch fault {
		case "execution_off":
			candidate.ExecutionEnabled = false
		case "foreign_source":
			candidate.guestReconcile.source = "d083f7d5d52e15c22feb38fff56e024354ac86ae"
		case "incomplete_inventory":
			candidate.guestReconcile.inventory.Members = append([]model.CapacityVMFleetInventoryMember(nil), candidate.guestReconcile.inventory.Members[:len(f.reg)-1]...)
		}
		if _, _, eligible, err := candidate.TryClaimInstalledReadinessHandoff(ctx, f.policy, a); eligible {
			t.Fatal("unsafe handoff admitted", fault, err)
		}
		unchanged()
	}
	tx, err = f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) SELECT $2,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,'settled','{}'::jsonb,clock_timestamp()+interval '1 minute' FROM public.capacity_mutation_grants WHERE id=$1", f.historicalGrantID, uuid.NewString())
	if err != nil {
		tx.Rollback()
		t.Fatal("declared unresolved ordinary grant", err)
	}
	_, _, pendingAdmitted, pendingErr := s.tryClaimInstalledReadinessHandoffTx(ctx, tx, f.policy, f.p, a)
	rollbackErr = tx.Rollback()
	if pendingAdmitted || !errors.Is(pendingErr, ErrCapacityConflict) || rollbackErr != nil {
		t.Fatal("unresolved provider authority admitted a handoff", pendingAdmitted, pendingErr, rollbackErr)
	}
	unchanged()
	claimedStore, claimed, eligible, err := s.TryClaimInstalledReadinessHandoff(ctx, f.policy, a)
	if err != nil || !eligible || claimed.Generation != current.Generation+1 || claimed.FencingToken != current.FencingToken+1 || claimed.Phase != "preparing" || claimed.InstalledReadinessHandoff == nil || claimed.InstalledGuestReconcile != nil || claimed.LeaseOwner == current.LeaseOwner || claimed.LeaseExecutorID != s.ExecutorID || claimed.LeaseExpiresAt == nil {
		t.Fatal("genuine new readiness-only generation unavailable", eligible, err)
	}
	marker := claimed.InstalledReadinessHandoff
	if marker.ExhaustedGeneration != current.Generation || marker.ExhaustedFence != current.FencingToken || marker.ClaimGeneration != claimed.Generation || marker.ClaimFence != claimed.FencingToken || marker.RunID != successorJob.RunID.String() || marker.ExecutorID != s.ExecutorID || marker.CoreSource != capacity.CurrentGuestCoreSource() || claimed.Decision.ExecutionPermitted || claimed.Decision.Action != "hold" || claimed.Decision.Units != len(f.reg) || !claimed.LeaseExpiresAt.After(claimed.UpdatedAt) || claimed.LeaseExpiresAt.Sub(claimed.UpdatedAt) > 90*time.Second {
		t.Fatal("handoff is not a distinct, current-build readiness-only epoch")
	}
	installedReadinessRefusesProviderGrant(t, f, claimed.Generation)
	var archiveBefore string
	if err = f.db.QueryRow("SELECT row_to_json(h)::text FROM public.capacity_installed_readiness_exhausted_handoffs h").Scan(&archiveBefore); err != nil {
		t.Fatal(err)
	}
	installedReadinessArchiveVectors(t, f, archiveBefore)
	if _, _, repeated, err := s.TryClaimInstalledReadinessHandoff(ctx, f.policy, a); repeated {
		t.Fatal("origin received a repeated handoff", err)
	}
	completion, _ := installedReadinessCompletionOperands(t, f, successorJob, claimed)
	o := completion.guestReconcile
	claimedStore = claimedStore.WithOriginalGuestReconcile(o.workflow, o.step, o.source, o.mode, o.requestID, o.inventory, o.reporting).WithOriginalGuestNotifyCanary(o.step, o.source)
	epochStore, epoch, found, err := claimedStore.OriginalGuestInstalledReadinessHandoffEpoch(ctx, f.policy)
	if err != nil || !found || !reflect.DeepEqual(claimed, epoch) {
		t.Fatal("same original handoff epoch was not recovered", found, err)
	}
	epochStore = epochStore.WithOriginalGuestReconcile(o.workflow, o.step, o.source, o.mode, o.requestID, o.inventory, o.reporting).WithOriginalGuestNotifyCanary(o.step, o.source)
	installedReadinessFreshCanaries(t, f, epochStore, claimed)
	completion, a = installedReadinessCompletionOperands(t, f, successorJob, claimed)
	o = completion.guestReconcile
	epochStore = epochStore.WithOriginalGuestReconcile(o.workflow, o.step, o.source, o.mode, o.requestID, o.inventory, o.reporting)
	preserved := f.preserved(t)
	var promoted model.CapacityIntent
	for _, phase := range []string{"prepared", "canary", "promoted"} {
		got, err := epochStore.AdvanceOriginalGuest(ctx, f.policy, claimed.Generation, claimed.FencingToken, claimed.LeaseOwner, phase, a)
		if err != nil || got.Phase != phase || got.Generation != claimed.Generation || got.FencingToken != claimed.FencingToken || !reflect.DeepEqual(got.InstalledReadinessHandoff, claimed.InstalledReadinessHandoff) {
			t.Fatal("handoff actual readiness phase", phase, err)
		}
		if phase == "promoted" {
			if got.LeaseOwner != "" || got.LeaseExecutorID != "" || got.LeaseExpiresAt != nil {
				t.Fatal("handoff promotion did not release its one original lease")
			}
		} else if got.LeaseOwner != claimed.LeaseOwner || got.LeaseExecutorID != claimed.LeaseExecutorID || !reflect.DeepEqual(got.LeaseExpiresAt, claimed.LeaseExpiresAt) {
			t.Fatal("handoff phase renewed its lease", phase)
		}
		if !reflect.DeepEqual(preserved, f.preserved(t)) {
			t.Fatal("handoff phase altered old or signed canary originals", phase)
		}
		var archiveAfter string
		if err = f.db.QueryRow("SELECT row_to_json(h)::text FROM public.capacity_installed_readiness_exhausted_handoffs h").Scan(&archiveAfter); err != nil || archiveAfter != archiveBefore {
			t.Fatal("handoff changed its immutable exhausted archive", phase, err)
		}
		var allOriginalsValid bool
		if err = f.db.QueryRow("SELECT public.installed_readiness_handoff_valid(h) FROM public.capacity_installed_readiness_exhausted_handoffs h").Scan(&allOriginalsValid); err != nil || !allOriginalsValid {
			t.Fatal("phase changed a retained full job/run/issuer/M98 original", phase, err)
		}
		promoted = got
	}
	if _, _, repeated, err := epochStore.TryClaimInstalledReadinessHandoff(ctx, f.policy, a); repeated {
		t.Fatal("promoted successor received a child handoff", err)
	}
	installedReadinessSuccessACK(t, f, successorJob, promoted)
	promoted = installedReadinessStablePolicyRestore(t, f, successorJob, promoted)
	installedReadinessRefusesProviderGrant(t, f, claimed.Generation)
	installedReadinessEvidence(t, f, archiveBefore, promoted)
}

func installedReadinessSuccessACK(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob, promoted model.CapacityIntent) {
	t.Helper()
	returned := time.Now().UTC().Truncate(time.Microsecond)
	response := capacityDispatchResponse(job.CapacityDispatchEnvelope, "succeeded")
	response.StartedAt, response.FinishedAt = *job.StartedAt, returned
	var wf model.WorkflowManifestSpec
	if err := json.Unmarshal(f.workflow.Spec, &wf); err != nil {
		t.Fatal(err)
	}
	ordered, err := manifestengine.WorkflowExecutionOrder(wf)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range ordered {
		step := model.WorkflowRunStepResult{ID: spec.ID, Kind: "yggdrasil", Operation: manifestengine.NormalizeWorkflowStepOperation(spec), Capability: manifestengine.NormalizeWorkflowStepCapability(spec), Status: "skipped", StartedAt: promoted.UpdatedAt, FinishedAt: promoted.UpdatedAt}
		switch spec.ID {
		case "plan-original-guest":
			step.Status, step.Attempts, step.StartedAt = "succeeded", 1, *job.StartedAt
			step.Metadata = map[string]any{"mode": "refresh", "reason": installedReadinessHandoffReason, "generation": promoted.Generation, "fencing_token": promoted.FencingToken}
		case "refresh-original-membership":
			step.Status, step.Attempts, step.FinishedAt = "succeeded", 1, returned
			if err := json.Unmarshal(installedTimeoutWire(t, promoted), &step.Metadata); err != nil {
				t.Fatal(err)
			}
		default:
			step.Metadata = map[string]any{"condition": spec.Condition, "skip_reason": "condition"}
		}
		response.Steps = append(response.Steps, step)
	}
	if err = FinishCapacityDispatch(context.Background(), f.db, job, response, returned, nil); err != nil {
		t.Fatal("actual promoted fixture return ACK", err)
	}
	var ack bool
	if err = f.db.QueryRow("SELECT state='returned' AND return_status='succeeded' AND finalization_ack_at IS NOT NULL FROM public.capacity_dispatch_jobs WHERE id=$1", job.JobID).Scan(&ack); err != nil || !ack {
		t.Fatal("genuine promoted job ACK missing", ack, err)
	}
}

func installedReadinessStablePolicyRestore(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob, promoted model.CapacityIntent) model.CapacityIntent {
	t.Helper()
	// Exercise the actual Go transition guard on a declared next proposal,
	// without writing any counter or bypassing the real ordinary hold clocks.
	proposal := promoted
	proposal.Generation++
	proposal.Phase, proposal.InstalledReadinessHandoff = "proposed", nil
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	guardStore, _ := installedReadinessCompletionOperands(t, f, job, promoted)
	guardErr := guardStore.guardInstalledReadinessHandoffTransitionTx(context.Background(), tx, f.policy, f.p, &promoted, &proposal, time.Now().UTC())
	rollbackErr := tx.Rollback()
	if guardErr != nil || rollbackErr != nil {
		t.Fatal("stable next proposal marker-drop guard", guardErr, rollbackErr)
	}
	assess := func(want model.CapacityIntent) model.CapacityIntent {
		t.Helper()
		s, a := installedReadinessCompletionOperands(t, f, job, want)
		for i := range a.Evidence {
			value := 1.0
			a.Evidence[i].Value, a.Evidence[i].RangeMin, a.Evidence[i].RangeMax = &value, &value, &value
		}
		s.ExecutorID = uuid.NewString()
		s.guestReconcile.step, s.guestReconcile.mode = f.steps[0], ""
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		got, err := s.AssessOriginalGuest(ctx, f.policy, a)
		if err != nil || got.Generation != promoted.Generation || got.FencingToken != promoted.FencingToken || got.Phase != "promoted" || got.Decision.Action != "hold" || got.InstalledReadinessHandoff != nil || got.LeaseOwner != "" || got.LeaseExecutorID != "" || got.LeaseExpiresAt != nil {
			t.Fatal("stable ordinary assessment lost the promoted unleased epoch", err)
		}
		return got
	}
	stable := assess(promoted)
	for _, thresholds := range [][2]float64{{1000, 0.001}, {3, 0.25}} {
		previous := f.policy
		copyPolicy := f.p
		copyPolicy.Signals = append([]model.CapacitySignalRule(nil), f.p.Signals...)
		for i := range copyPolicy.Signals {
			copyPolicy.Signals[i].UpAbove, copyPolicy.Signals[i].DownBelow = thresholds[0], thresholds[1]
		}
		next := previous
		next.ID, next.Version = uuid.New(), previous.Version+1
		next.Spec = installedTimeoutWire(t, copyPolicy)
		next.Checksum = capacity.BusinessCreationSHA256(next.Spec)
		tx, err := f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec("UPDATE public.manifests SET active=false WHERE id=$1", previous.ID); err == nil {
			_, err = tx.Exec("INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,true)", next.ID, next.Metadata.Namespace, next.Metadata.Name, next.Version, next.Checksum, string(next.Spec))
		}
		if err != nil {
			tx.Rollback()
			t.Fatal("append-only compatible policy publication", err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		f.policy, f.p = next, copyPolicy
		stable = assess(stable)
	}
	if f.p.Signals[0].UpAbove != 3 || f.p.Signals[0].DownBelow != 0.25 {
		t.Fatal("original ordinary policy thresholds were not restored")
	}
	s, _ := installedReadinessCompletionOperands(t, f, job, stable)
	s.ExecutorID = uuid.NewString()
	s.guestReconcile.mode = "refresh"
	installedReadinessFreshCanaries(t, f, s, stable)
	return stable
}

func installedReadinessEvidence(t *testing.T, f *installedTimeoutFixture, archive string, promoted model.CapacityIntent) {
	t.Helper()
	dir := os.Getenv("INSTALLED_TIMEOUT_LOGS")
	if dir == "" {
		return
	}
	var receipt []byte
	if err := f.db.QueryRow("SELECT row_to_json(d)::text FROM public.capacity_dispatch_installed_provision_timeout_dispositions d").Scan(&receipt); err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"schema": "installed_readiness_handoff_source_fixture_v1", "source_commit": capacity.CurrentGuestCoreSource(), "fixture_only": true, "native_authority": false, "production_authority": false, "original_dispatch_deadline_seconds": 300, "three_natural_readiness_lease_seconds": 90, "ordinary_fourth_attempt_refused": true, "three_actual_failed_ACKs_preserved": true, "provider_mutations_authorized": false, "old_M98_receipt": json.RawMessage(receipt), "exhausted_archive": json.RawMessage(archive), "actual_fixture_promoted_intent": promoted}
	raw := append(installedTimeoutWire(t, proof), '\n')
	file, err := os.OpenFile(filepath.Join(dir, "M100-HANDOFF-EIGHT-MEMBERS.SOURCE.original.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		file.Close()
		t.Fatal("whole handoff fixture evidence", n, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
