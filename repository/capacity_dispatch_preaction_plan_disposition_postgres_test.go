//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// All rows are declared signed operands in owned local PG16/17 databases.
// They are not Native observations. The old M98 constructor and eight cases
// remain unchanged. A retained owner is used only by the explicit two-process
// repeat case: phase A closes two real 300s dispatches, phase B closes the third.
type preActionPlanDBOwner struct {
	name string
	keep bool
}

func preActionPlanDB(t *testing.T, owner *preActionPlanDBOwner) *sql.DB {
	t.Helper()
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") || os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Fatal("explicit disposable fixture gate required")
	}
	u, err := url.Parse(os.Getenv("FAILED_SERVING_FIXTURE_ADMIN_URL"))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Path != "/postgres" {
		t.Fatal("explicit fixture admin URL required")
	}
	host, socket := u.Hostname(), u.Query().Get("host")
	if host != "127.0.0.1" && host != "localhost" && host != "::1" && !(host == "" && strings.HasPrefix(socket, "/")) {
		t.Fatal("remote PostgreSQL refused")
	}
	want, err := strconv.Atoi(os.Getenv("FAILED_SERVING_TEST_PG_MAJOR"))
	if err != nil || (want != 16 && want != 17) {
		t.Fatal("explicit PG16/17 fixture major required")
	}
	adminURL := u.String()
	openAdmin := func() *sql.DB {
		admin, x := sql.Open("postgres", adminURL)
		if x != nil {
			t.Fatal(x)
		}
		admin.SetMaxOpenConns(1)
		admin.SetMaxIdleConns(1)
		var address string
		var major int
		if x = admin.QueryRow("SELECT COALESCE(inet_server_addr()::text,'unix'),current_setting('server_version_num')::int/10000").Scan(&address, &major); x != nil || !failedServingLocalServer(host, address) || major != want {
			admin.Close()
			t.Fatal("actual isolated PostgreSQL identity/major differs", x)
		}
		return admin
	}
	admin := openAdmin()
	name := owner.name
	reopening := name != ""
	if name == "" {
		name = "preaction_plan_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		owner.name = name
	} else if suffix := strings.TrimPrefix(name, "preaction_plan_fixture_"); !strings.HasPrefix(name, "preaction_plan_fixture_") || len(suffix) != 32 {
		t.Fatal("owned repeat database identifier refused")
	} else if id, e := uuid.Parse(suffix); e != nil || strings.ReplaceAll(id.String(), "-", "") != suffix {
		t.Fatal("canonical owned repeat database identifier refused")
	}
	exists := false
	if err = admin.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)", name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if reopening && !exists {
		t.Fatal("retained authentic fixture database missing")
	}
	if !exists {
		if _, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
			admin.Close()
			t.Fatal(err)
		}
	}
	if err = admin.Close(); err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if e := db.Close(); e != nil {
			t.Error("work database close", e)
		}
		if owner.keep {
			return
		}
		cleanup := openAdmin()
		if _, e := cleanup.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)"); e != nil {
			t.Error("disposable database cleanup", e)
		}
		if e := cleanup.Close(); e != nil {
			t.Error("cleanup admin close", e)
		}
	})
	var actual string
	if err = db.QueryRow("SELECT current_database()").Scan(&actual); err != nil || actual != name || !strings.HasPrefix(actual, "preaction_plan_fixture_") {
		t.Fatal("owned UUID database identity differs", err)
	}
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if err = goose.UpToContext(context.Background(), db, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 93); err != nil {
			t.Fatal("actual closed93 fixture prefix", err)
		}
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || (!exists && version != 93) || (exists && version != 99) {
		t.Fatal("exact owned fixture schema required", version, err)
	}
	return db
}
func newPreActionAnchorFixture(t *testing.T, n int, owner *preActionPlanDBOwner) *installedTimeoutFixture {
	t.Helper()
	capacity.RecoveryFixtureApprovalScope(t)
	f := &installedTimeoutFixture{db: preActionPlanDB(t, owner), pre: make([]model.CapacityGuestOriginalProvisioningPreregistration, n), reg: make([]model.CapacityGuestOriginalProvisioningRegistration, n), receipts: make([]model.CapacityGuestOriginalProvisioningReceipt, n), installed: make([]model.CapacityGuestOriginalInstallationConfirmation, n)}
	if err := goose.UpToContext(context.Background(), f.db, failedServingRepositoryRoot(t)+"/db/migrations", 97); err != nil {
		t.Fatal("actual schema97 predecessor", err)
	}
	if err := goose.UpToContext(context.Background(), f.db, failedServingRepositoryRoot(t)+"/db/migrations", 98); err != nil {
		t.Fatal("actual schema98", err)
	}
	if n == 8 {
		h := installedTimeoutHistoricalFixture(t, f.db, "dakasa-production", "production", "notify", "original_notify_hetzner_vm_members")
		historyCtx, cancelHistory := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelHistory()
		owner, e := h.store.BeginOriginalCreateDisposition(historyCtx, h.pre.OriginalCreateGrantID, "declared-historical-owner")
		if e != nil {
			t.Fatal("genuine historical disposition Begin", e)
		}
		closed, e := h.store.CompleteOriginalCreateDisposition(historyCtx, owner, h.native(t, owner.Candidate()))
		if e != nil {
			t.Fatal("genuine historical disposition Complete", e)
		}
		var state, pointer string
		if e = f.db.QueryRow("SELECT state,original_disposition_id::text FROM public.capacity_mutation_grants WHERE id=$1", closed.GrantID).Scan(&state, &pointer); e != nil || state != "settled" || pointer != closed.ID {
			t.Fatal("genuine terminal SETTLED history", state, pointer, e)
		}
		f.historicalGrantID = closed.GrantID
	}
	historyAt := time.Now().UTC().Add(-60 * time.Second).Truncate(time.Microsecond)
	p, b, r, receipt, installed := capacity.RecoveryFixtureInstalledSlotDuring(t, 1, historyAt, historyAt.Add(420*time.Second))
	f.p, f.binding = p, b
	f.p.ExecutionEnabled, f.p.LeaseSeconds = true, 300
	if err := capacity.RegisterRecoveryFixtureApproval(f.p, b, "hetzner"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n-1; i++ {
		_, _, f.reg[i], f.receipts[i], f.installed[i] = capacity.RecoveryFixtureInstalledSlotDuring(t, i+1, historyAt, historyAt.Add(420*time.Second))
		f.pre[i] = f.reg[i].Result.ProductionClock.Authority.Preregistration
	}
	f.reg[0], f.receipts[0], f.installed[0] = r, receipt, installed
	f.pre[0] = r.Result.ProductionClock.Authority.Preregistration
	pre := f.pre[0]
	f.policy = model.Manifest{ID: uuid.MustParse(pre.PolicyID), Kind: "capacity_policy", Checksum: pre.PolicyChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: "dakasa-production", Name: "installed-timeout-unit", Active: true}, Spec: installedTimeoutWire(t, f.p)}
	var err error
	f.steps, err = capacity.OriginalGuestReconcileGraph(f.policy, f.p)
	if err != nil {
		t.Fatal(err)
	}
	enabled, no := true, false
	wfSpec := model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *", CatchupPolicy: "skip"}}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: "dakasa-production", Name: "unit-rbac"}}, DispatchMode: "async", InputSchema: model.WorkflowInputSchemaSpec{Required: []string{"policy"}, AdditionalProperties: &no, Properties: map[string]model.IntegrationSchemaProperty{"policy": {Type: "object"}}}, Steps: f.steps}
	f.workflow = model.Manifest{ID: uuid.MustParse(pre.WorkflowID), Kind: "workflow", Checksum: pre.WorkflowChecksum, Version: 1, Metadata: model.ManifestMetadata{Namespace: f.p.Workflow.Namespace, Name: f.p.Workflow.Name, Active: true}, Spec: installedTimeoutWire(t, wfSpec)}
	for _, m := range []model.Manifest{f.policy, f.workflow} {
		f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1',$2,$3,$4,1,$5,$6::jsonb,true)", m.ID, m.Kind, m.Metadata.Namespace, m.Metadata.Name, m.Checksum, string(m.Spec))
	}
	mutation := f.p.MutationBindings[0]
	f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_type','test-recovery','unit-type',1,$2,'{}'::jsonb,true)", mutation.IntegrationTypeID, mutation.IntegrationTypeChecksum)
	f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','integration_instance','test-recovery','unit-instance',1,$2,$3::jsonb,true)", mutation.IntegrationInstanceID, mutation.IntegrationChecksum, string(installedTimeoutWire(t, map[string]any{"type_ref": map[string]any{"manifest_id": mutation.IntegrationTypeID}})))
	f.rbac = CapacityDispatchManifestPin{ID: uuid.New(), Namespace: f.policy.Metadata.Namespace, Name: "unit-rbac", Version: 1, Checksum: capacityDispatchSHA([]byte("declared-rbac"))}
	f.exec(t, "INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active)VALUES($1,'v1','rbac',$2,$3,1,$4,'{}'::jsonb,true)", f.rbac.ID, f.rbac.Namespace, f.rbac.Name, f.rbac.Checksum)
	for i := 0; i < n-1; i++ {
		f.seedMember(t, i, false)
	}
	f.original = f.envelope(t)
	queued, coalesced, err := f.enqueue(f.original)
	if err != nil || coalesced || queued.JobID != f.original.JobID {
		t.Fatal("new original dispatch", coalesced, err)
	}
	f.job, err = ClaimCapacityDispatch(context.Background(), f.db, f.original.Realm, f.original.Environment, uuid.New(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f.job, err = StartCapacityDispatch(context.Background(), f.db, f.job)
	if err != nil {
		t.Fatal(err)
	}
	if f.job.StartedAt == nil || f.job.LeaseExpiresAt == nil || f.job.LeaseExpiresAt.Sub(*f.job.StartedAt) < 4*time.Minute {
		t.Fatal("production original300s context must remain intact")
	}
	preActionPlanObserveRunStart(t, f.job)
	reserved := time.Now().UTC().Truncate(time.Microsecond)
	_, _, f.reg[n-1], f.receipts[n-1], f.installed[n-1] = capacity.RecoveryFixtureInstalledSlotDuring(t, n, reserved, *f.job.LeaseExpiresAt)
	selected := f.reg[n-1].Result.ProductionClock.Authority.Preregistration
	f.pre[n-1] = selected
	now := time.Now().UTC()
	snapshot, err := capacity.GuestReconcileSnapshot(f.policy, f.p, f.inventory(t, n-1, now), now)
	if err != nil {
		t.Fatal(err)
	}
	f.intent = model.CapacityIntent{Namespace: f.policy.Metadata.Namespace, PolicyName: f.policy.Metadata.Name, PolicyID: f.policy.ID, PolicyChecksum: f.policy.Checksum, Environment: f.p.Environment, Domain: f.p.Domain, Dimension: f.p.Dimension, Generation: selected.Generation, FencingToken: selected.Fence, Phase: "preparing", LeaseOwner: selected.LeaseOwner, LeaseExecutorID: selected.ExecutorID, LeaseExpiresAt: f.job.LeaseExpiresAt, Decision: model.CapacityDecision{Action: "expand", ExecutionPermitted: true, Profile: mutation.ProfileName, Units: n, Floor: 1}, BaselineSnapshot: snapshot, Assessment: model.CapacityAssessment{Snapshot: snapshot}, UpdatedAt: now}
	if f.historicalGrantID != "" {
		// Declared initial current epoch after a real closed historical disposition.
		// Only the mutable intent changes; all historical originals remain exact.
		f.exec(t, "UPDATE public.capacity_intents SET intent=$5::jsonb,updated_at=$6 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4", f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, f.intent)), now)
	} else {
		f.exec(t, "INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at)VALUES($1,$2,$3,$4,$5::jsonb,$6)", f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, string(installedTimeoutWire(t, f.intent)), now)
	}
	// No future storage timestamp: wait for the actual signed installation time.
	time.Sleep(time.Until(f.receipts[n-1].RecordedAt.Add(time.Second)) + time.Millisecond)
	f.seedMember(t, n-1, false)
	return f
}

var preActionInvocationStarts sync.Map // Test-only actual RunWorkflow entry clocks, never persisted rewrites.

func preActionPlanObserveRunStart(t *testing.T, job CapacityDispatchJob) {
	t.Helper()
	at := time.Now().UTC()
	if job.StartedAt == nil || job.LeaseExpiresAt == nil || !at.After(*job.StartedAt) || !at.Before(*job.LeaseExpiresAt) {
		t.Fatal("actual distinct invocation start must be inside the unchanged dispatch lease")
	}
	preActionInvocationStarts.Store(job.RunID, at)
	t.Cleanup(func() { preActionInvocationStarts.Delete(job.RunID) })
}

func preActionPlanStart(t *testing.T, f *installedTimeoutFixture, queued CapacityDispatchJob) CapacityDispatchJob {
	t.Helper()
	j, err := ClaimCapacityDispatch(context.Background(), f.db, f.original.Realm, f.original.Environment, uuid.New(), 30*time.Second)
	if err != nil || j.JobID != queued.JobID || j.RunID != queued.RunID {
		t.Fatal("exact queued successor claim", err)
	}
	j, err = StartCapacityDispatch(context.Background(), f.db, j)
	if err != nil || j.StartedAt == nil || j.LeaseExpiresAt == nil || j.LeaseExpiresAt.Sub(*j.StartedAt) < 4*time.Minute {
		t.Fatal("natural original300s claim", err)
	}
	preActionPlanObserveRunStart(t, j)
	return j
}

func preActionPlanResponse(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob) model.RunWorkflowResponse {
	t.Helper()
	r := capacityDispatchResponse(job.CapacityDispatchEnvelope, "failed")
	actual, ok := preActionInvocationStarts.Load(job.RunID)
	if !ok {
		t.Fatal("actual invocation start was not retained")
	}
	r.StartedAt, r.FinishedAt = actual.(time.Time), time.Now().UTC()
	r.Metadata = map[string]any{}
	for key, value := range job.Metadata {
		r.Metadata[key] = value
	}
	r.Metadata["failed_step"] = "plan-original-guest"
	tailAt := time.Now().UTC()
	if tailAt.Before(r.FinishedAt) {
		t.Fatal("actual aborted-tail clock went backwards")
	}
	var spec model.WorkflowManifestSpec
	if err := json.Unmarshal(f.workflow.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	ordered, err := manifestengine.WorkflowExecutionOrder(spec)
	if err != nil || len(ordered) != 7 {
		t.Fatal("real seven-step graph", err)
	}
	for i, step := range ordered {
		v := model.WorkflowRunStepResult{ID: step.ID, Kind: strings.ToLower(strings.TrimSpace(step.Use.Kind)), Operation: manifestengine.NormalizeWorkflowStepOperation(step), Capability: manifestengine.NormalizeWorkflowStepCapability(step), Status: "skipped", Error: "workflow aborted after step \"plan-original-guest\" failed", StartedAt: tailAt, FinishedAt: tailAt}
		if i == 0 {
			v.Status, v.Attempts, v.Error = "failed", 1, "original Guest reconciliation held"
			v.StartedAt, v.FinishedAt = r.StartedAt, r.FinishedAt
			v.Metadata = map[string]any{"original_guest_reconcile_refusal_stage": "installed_resume_claim"}
		}
		r.Steps = append(r.Steps, v)
	}
	return r
}

func preActionPlanObservedReturn(response model.RunWorkflowResponse) time.Time {
	// Capture the actual caller return after the producer's raw nanosecond
	// tail, at the storage precision used by FinishCapacityDispatch itself.
	last := response.FinishedAt
	for _, step := range response.Steps {
		if step.FinishedAt.After(last) {
			last = step.FinishedAt
		}
	}
	for {
		at := time.Now().UTC().Truncate(time.Microsecond)
		if !at.Before(last) {
			return at
		}
	}
}

func preActionPlanFinish(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob) {
	t.Helper()
	time.Sleep(time.Until(*job.LeaseExpiresAt) + 2*time.Millisecond)
	response := preActionPlanResponse(t, f, job)
	at := preActionPlanObservedReturn(response)
	if err := FinishCapacityDispatch(context.Background(), f.db, job, response, at, context.DeadlineExceeded); !errors.Is(err, ErrCapacityDispatchUnknown) {
		t.Fatal("actual failed PLAN unknown return", err)
	}
	old, err := readCapacityDispatchJob(context.Background(), f.db, job.JobID, false)
	if err != nil || old.State != "unknown" || old.FinalizationAckAt != nil || old.ReturnedAt == nil {
		t.Fatal("honest unknown/ACKnull", err)
	}
}

func preActionPlanAnchored(t *testing.T, n int, owner *preActionPlanDBOwner, schema99 bool) (*installedTimeoutFixture, model.CapacityInstalledProvisionTimeoutDisposition, CapacityDispatchJob) {
	t.Helper()
	f := newPreActionAnchorFixture(t, n, owner)
	if schema99 {
		if err := goose.UpToContext(context.Background(), f.db, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 99); err != nil {
			t.Fatal("actual additive schema99", err)
		}
	}
	f.finish(t, "source_assessment", true)
	original := f.preserved(t)
	queued, merged, err := f.enqueue(f.envelope(t))
	if err != nil || merged {
		t.Fatal("real M98 anchor and distinct successor", err)
	}
	anchor, err := ReadCapacityDispatchInstalledProvisionTimeoutDisposition(context.Background(), f.db, f.original.JobID)
	if err != nil || anchor.ID == "" || len(anchor.Members) != n {
		t.Fatal("authenticated original M98 root anchor", err)
	}
	if !reflect.DeepEqual(original, f.preserved(t)) {
		t.Fatal("anchor creation rewrote provider/Guest/oldrun")
	}
	return f, anchor, queued
}

func preActionPlanOriginals(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob) map[string]string {
	t.Helper()
	out := f.preserved(t)
	var dispatch, run string
	if err := f.db.QueryRow("SELECT (to_jsonb(j)-ARRAY['state','updated_at'])::text,row_to_json(w)::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1", job.JobID).Scan(&dispatch, &run); err != nil {
		t.Fatal(err)
	}
	out["failed_plan_dispatch_except_terminal"], out["failed_plan_whole_run"] = dispatch, run
	return out
}

func preActionPlanAdmit(t *testing.T, f *installedTimeoutFixture, failed CapacityDispatchJob, anchor model.CapacityInstalledProvisionTimeoutDisposition) (CapacityDispatchJob, model.CapacityDispatchPreActionPlanDisposition) {
	t.Helper()
	before := preActionPlanOriginals(t, f, failed)
	next := f.envelope(t)
	queued, merged, err := f.enqueue(next)
	if err != nil || merged || queued.JobID != next.JobID || queued.RunID != next.RunID {
		t.Fatal("one fresh queued successor", merged, err)
	}
	receipt, err := ReadCapacityDispatchPreActionPlanDisposition(context.Background(), f.db, failed.JobID)
	if err != nil || receipt.RootAnchorID != anchor.ID || receipt.JobID != failed.JobID.String() || receipt.RunID != failed.RunID.String() || receipt.SuccessorJobID != queued.JobID.String() || receipt.SuccessorRunID != queued.RunID.String() || receipt.Generation != f.intent.Generation || receipt.FencingToken != f.intent.FencingToken {
		t.Fatal("typed pre-action root/successor identity", receipt, err)
	}
	if !reflect.DeepEqual(before, preActionPlanOriginals(t, f, failed)) {
		t.Fatal("pre-action classification rewrote originals")
	}
	var count int
	if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_preaction_plan_dispositions WHERE job_id=$1", failed.JobID).Scan(&count); err != nil || count != 1 {
		t.Fatal("one immutable receipt", count, err)
	}
	if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id JOIN public.capacity_dispatch_wakes k ON k.job_id=j.id WHERE j.id=$1 AND j.run_id=$2 AND j.state='queued' AND j.started_at IS NULL AND w.finished_at IS NULL", queued.JobID, queued.RunID).Scan(&count); err != nil || count != 1 {
		t.Fatal("same-commit queued job/run/wake", count, err)
	}
	return queued, receipt
}

func preActionPlanDeniedSQL(t *testing.T, f *installedTimeoutFixture, query string, args ...any) {
	t.Helper()
	tx, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(query, args...)
	if err == nil {
		err = tx.Commit()
	} else {
		_ = tx.Rollback()
	}
	if err == nil {
		t.Fatal("unauthenticated direct write unexpectedly committed")
	}
}

type preActionPlanHandoff struct {
	Schema             string `json:"schema"`
	Database           string `json:"database"`
	AnchorJobID        string `json:"anchor_job_id"`
	AnchorID           string `json:"anchor_id"`
	FirstPlanJobID     string `json:"first_plan_job_id"`
	FirstDispositionID string `json:"first_disposition_id"`
	SuccessorJobID     string `json:"successor_job_id"`
	SuccessorRunID     string `json:"successor_run_id"`
	PolicyID           string `json:"policy_id"`
	WorkflowID         string `json:"workflow_id"`
	Source             string `json:"source"`
	PostgresMajor      int    `json:"postgres_major"`
}

func preActionPlanSaveHandoff(t *testing.T, owner *preActionPlanDBOwner, f *installedTimeoutFixture, anchor model.CapacityInstalledProvisionTimeoutDisposition, first model.CapacityDispatchPreActionPlanDisposition, queued CapacityDispatchJob) {
	t.Helper()
	path := os.Getenv("PREACTION_PLAN_HANDOFF")
	if !filepath.IsAbs(path) {
		t.Fatal("explicit private handoff path required")
	}
	major, err := strconv.Atoi(os.Getenv("FAILED_SERVING_TEST_PG_MAJOR"))
	if err != nil {
		t.Fatal(err)
	}
	value := preActionPlanHandoff{Schema: "preaction_plan_repeat_owned_fixture_ids_v1", Database: owner.name, AnchorJobID: anchor.JobID, AnchorID: anchor.ID, FirstPlanJobID: first.JobID, FirstDispositionID: first.ID, SuccessorJobID: queued.JobID.String(), SuccessorRunID: queued.RunID.String(), PolicyID: f.policy.ID.String(), WorkflowID: f.workflow.ID.String(), Source: capacity.CurrentGuestCoreSource(), PostgresMajor: major}
	raw := append(installedTimeoutWire(t, value), '\n')
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	n, err := out.Write(raw)
	if err != nil || n != len(raw) {
		out.Close()
		t.Fatal("complete handoff write", err)
	}
	if err = out.Sync(); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	owner.keep = true
}

func preActionPlanLoadHandoff(t *testing.T) (*installedTimeoutFixture, model.CapacityInstalledProvisionTimeoutDisposition, CapacityDispatchJob, preActionPlanHandoff) {
	t.Helper()
	path := os.Getenv("PREACTION_PLAN_HANDOFF")
	before, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > 65536 {
		t.Fatal("authentic private handoff file required", err)
	}
	raw, err := os.ReadFile(path)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(before, after) || after.Size() != int64(len(raw)) || before.ModTime() != after.ModTime() {
		t.Fatal("unstable handoff", err, statErr)
	}
	var h preActionPlanHandoff
	var fields map[string]json.RawMessage
	major, err := strconv.Atoi(os.Getenv("FAILED_SERVING_TEST_PG_MAJOR"))
	if err != nil || json.Unmarshal(raw, &h) != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 12 || h.Schema != "preaction_plan_repeat_owned_fixture_ids_v1" || h.Source != capacity.CurrentGuestCoreSource() || h.PostgresMajor != major {
		t.Fatal("closed same-Source/PG handoff required")
	}
	for _, text := range []string{h.AnchorJobID, h.AnchorID, h.FirstPlanJobID, h.FirstDispositionID, h.SuccessorJobID, h.SuccessorRunID, h.PolicyID, h.WorkflowID} {
		if id, e := uuid.Parse(text); e != nil || id == uuid.Nil || id.String() != text {
			t.Fatal("canonical handoff identity required")
		}
	}
	capacity.RecoveryFixtureApprovalScope(t)
	owner := &preActionPlanDBOwner{name: h.Database}
	f := &installedTimeoutFixture{db: preActionPlanDB(t, owner)}
	anchor, err := ReadCapacityDispatchInstalledProvisionTimeoutDisposition(context.Background(), f.db, uuid.MustParse(h.AnchorJobID))
	if err != nil || anchor.ID != h.AnchorID || anchor.PolicyID != h.PolicyID {
		t.Fatal("stored original M98 anchor differs from handoff", err)
	}
	first, err := ReadCapacityDispatchPreActionPlanDisposition(context.Background(), f.db, uuid.MustParse(h.FirstPlanJobID))
	if err != nil || first.ID != h.FirstDispositionID || first.RootAnchorID != anchor.ID || first.SuccessorJobID != h.SuccessorJobID || first.SuccessorRunID != h.SuccessorRunID {
		t.Fatal("stored phase-A receipt/successor differs", err)
	}
	loadManifest := func(id string) model.Manifest {
		var m model.Manifest
		if err := f.db.QueryRow("SELECT id,kind,namespace,name,version,checksum,spec,active FROM public.manifests WHERE id=$1", id).Scan(&m.ID, &m.Kind, &m.Metadata.Namespace, &m.Metadata.Name, &m.Version, &m.Checksum, &m.Spec, &m.Metadata.Active); err != nil {
			t.Fatal(err)
		}
		return m
	}
	f.policy, f.workflow = loadManifest(h.PolicyID), loadManifest(h.WorkflowID)
	if err = json.Unmarshal(f.policy.Spec, &f.p); err != nil || f.p.GuestRetirementBinding == nil {
		t.Fatal("stored original policy", err)
	}
	f.binding = *f.p.GuestRetirementBinding
	if err = capacity.RegisterRecoveryFixtureApproval(f.p, f.binding, "hetzner"); err != nil {
		t.Fatal(err)
	}
	f.steps, err = capacity.OriginalGuestReconcileGraph(f.policy, f.p)
	if err != nil {
		t.Fatal(err)
	}
	original, err := readCapacityDispatchJob(context.Background(), f.db, uuid.MustParse(h.AnchorJobID), false)
	if err != nil {
		t.Fatal(err)
	}
	f.original, f.job, f.rbac = original.CapacityDispatchEnvelope, original, original.RBAC
	var intentWire []byte
	if err = f.db.QueryRow("SELECT original_intent_wire FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=$1", anchor.ID).Scan(&intentWire); err != nil || json.Unmarshal(intentWire, &f.intent) != nil {
		t.Fatal("stored immutable original intent", err)
	}
	n := len(anchor.Members)
	f.pre = make([]model.CapacityGuestOriginalProvisioningPreregistration, n)
	f.reg = make([]model.CapacityGuestOriginalProvisioningRegistration, n)
	f.receipts = make([]model.CapacityGuestOriginalProvisioningReceipt, n)
	f.installed = make([]model.CapacityGuestOriginalInstallationConfirmation, n)
	for i, member := range anchor.Members {
		var pre, reg, receipt, installed []byte
		if member.Slot != i+1 {
			t.Fatal("original ordered members")
		}
		if err = f.db.QueryRow("SELECT p.original_wire,e.registration_wire,e.receipt_wire,x.original_wire FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=p.id JOIN public.capacity_guest_original_installations x ON x.preregistration_id=p.id WHERE p.id=$1", member.PreregistrationID).Scan(&pre, &reg, &receipt, &installed); err != nil || json.Unmarshal(pre, &f.pre[i]) != nil || json.Unmarshal(reg, &f.reg[i]) != nil || json.Unmarshal(receipt, &f.receipts[i]) != nil || json.Unmarshal(installed, &f.installed[i]) != nil {
			t.Fatal("stored original signed member wires", err)
		}
	}
	queued, err := readCapacityDispatchJob(context.Background(), f.db, uuid.MustParse(h.SuccessorJobID), false)
	if err != nil || queued.State != "queued" || queued.RunID.String() != h.SuccessorRunID {
		t.Fatal("phase-B exact queued successor", err)
	}
	return f, anchor, queued, h
}

func preActionPlanSQLVectors(t *testing.T, f *installedTimeoutFixture, failed CapacityDispatchJob) {
	t.Helper()
	var record, dispatch, run, intent, members, evidence []byte
	if err := f.db.QueryRow("SELECT original_wire,original_dispatch_wire,original_run_wire,original_intent_wire,members_wire,evidence_wire FROM public.capacity_dispatch_preaction_plan_dispositions WHERE job_id=$1", failed.JobID).Scan(&record, &dispatch, &run, &intent, &members, &evidence); err != nil {
		t.Fatal(err)
	}
	check := func(label string, r, d, w, i, m, e []byte, want bool) {
		t.Helper()
		var accepted bool
		if err := f.db.QueryRow("SELECT public.preaction_failed_plan_valid($1::jsonb,$2,$3,$4,$5,$6)", string(r), d, w, i, m, e).Scan(&accepted); err != nil || accepted != want {
			t.Fatal(label, "independent SQL proof", accepted, err)
		}
	}
	check("genuine historical receipt", record, dispatch, run, intent, members, evidence, true)
	var base map[string]any
	if err := json.Unmarshal(record, &base); err != nil || len(base) != 19 {
		t.Fatal("closed19 original record", err)
	}
	for _, key := range []string{"id", "job_id", "run_id", "root_anchor_id", "policy_id", "policy_checksum", "generation", "fencing_token", "successor_job_id", "successor_run_id", "original_deadline", "original_returned_at"} {
		var r map[string]any
		if err := json.Unmarshal(record, &r); err != nil {
			t.Fatal(err)
		}
		switch key {
		case "policy_checksum":
			r[key] = strings.Repeat("f", 64)
		case "generation", "fencing_token":
			r[key] = r[key].(float64) + 1
		case "original_deadline", "original_returned_at":
			r[key] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		case "id":
			r[key] = uuid.Nil.String()
		case "successor_job_id":
			r[key] = r["job_id"]
		case "successor_run_id":
			r[key] = r["run_id"]
		default:
			r[key] = uuid.NewString()
		}
		check("changed record "+key, installedTimeoutWire(t, r), dispatch, run, intent, members, evidence, false)
	}
	// Reseal the changed wire's digest so a hash-only checker is insufficient.
	for _, target := range []string{"original_dispatch_sha256", "original_run_sha256", "original_intent_sha256", "members_sha256", "evidence_sha256"} {
		var r map[string]any
		if err := json.Unmarshal(record, &r); err != nil {
			t.Fatal(err)
		}
		d, w, i, m, e := append([]byte(nil), dispatch...), append([]byte(nil), run...), append([]byte(nil), intent...), append([]byte(nil), members...), append([]byte(nil), evidence...)
		var changed []byte
		switch target {
		case "original_dispatch_sha256":
			var v map[string]any
			json.Unmarshal(d, &v)
			v["envelope_sha256"] = strings.Repeat("e", 64)
			changed = installedTimeoutWire(t, v)
			d = changed
		case "original_run_sha256":
			var v map[string]any
			json.Unmarshal(w, &v)
			v["status"] = "succeeded"
			changed = installedTimeoutWire(t, v)
			w = changed
		case "original_intent_sha256":
			var v map[string]any
			json.Unmarshal(i, &v)
			v["fencing_token"] = v["fencing_token"].(float64) + 1
			changed = installedTimeoutWire(t, v)
			i = changed
		case "members_sha256":
			var v []map[string]any
			json.Unmarshal(m, &v)
			v[0]["create_grant_id"] = uuid.NewString()
			changed = installedTimeoutWire(t, v)
			m = changed
		case "evidence_sha256":
			var v map[string]any
			json.Unmarshal(e, &v)
			v["foreign_caller_claim"] = true
			changed = installedTimeoutWire(t, v)
			e = changed
		}
		r[target] = capacity.BusinessCreationSHA256(changed)
		check("resealed "+target, installedTimeoutWire(t, r), d, w, i, m, e, false)
	}
	for _, field := range []string{"return_error", "finalization_error", "workflow_error"} {
		var r map[string]any
		json.Unmarshal(record, &r)
		d, w := dispatch, run
		if field == "workflow_error" {
			var v map[string]any
			json.Unmarshal(run, &v)
			v["error"] = "rewritten historical error"
			w = installedTimeoutWire(t, v)
			r["original_run_sha256"] = capacity.BusinessCreationSHA256(w)
		} else {
			var v map[string]any
			json.Unmarshal(dispatch, &v)
			v[field] = "rewritten historical error"
			d = installedTimeoutWire(t, v)
			r["original_dispatch_sha256"] = capacity.BusinessCreationSHA256(d)
		}
		check("independently resealed error "+field, installedTimeoutWire(t, r), d, w, intent, members, evidence, false)
	}
	var scan map[string]any
	if err := json.Unmarshal(evidence, &scan); err != nil {
		t.Fatal(err)
	}
	for key := range scan {
		if key == "schema" || key == "base" {
			continue
		}
		bads := []any{float64(1), true, nil}
		if key == "current_intent_matches_anchor" || key == "current_members_match_anchor" {
			bads = []any{false, float64(1), nil}
		}
		for _, bad := range bads {
			var changed map[string]any
			json.Unmarshal(evidence, &changed)
			changed[key] = bad
			raw := installedTimeoutWire(t, changed)
			var r map[string]any
			json.Unmarshal(record, &r)
			r["evidence_sha256"] = capacity.BusinessCreationSHA256(raw)
			check("no-effect field "+key, installedTimeoutWire(t, r), dispatch, run, intent, members, raw, false)
		}
	}
	var spec model.WorkflowManifestSpec
	if err := json.Unmarshal(f.workflow.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	var storedRun struct {
		Result json.RawMessage `json:"result"`
	}
	var good model.RunWorkflowResponse
	if json.Unmarshal(run, &storedRun) != nil || json.Unmarshal(storedRun.Result, &good) != nil {
		t.Fatal("authentic saved response required")
	}
	if !preActionFailedPlanResult(installedTimeoutWire(t, good), failed, spec, *failed.StartedAt, *failed.ReturnedAt) {
		t.Fatal("genuine seven-step failed plan refused")
	}
	for _, fault := range []string{"active_after_plan", "attempted_after_plan", "conditional_skip", "abort_error", "step_order", "kind", "capability", "clock", "stage_missing", "stage_extra", "workflow", "metadata", "run_start_before_dispatch", "run_start_at_deadline", "step_before_run_start", "skip_before_response_finish", "skip_after_actual_return", "failed_step_metadata"} {
		var r model.RunWorkflowResponse
		if err := json.Unmarshal(installedTimeoutWire(t, good), &r); err != nil {
			t.Fatal(err)
		}
		switch fault {
		case "active_after_plan":
			r.Steps[1].Status = "succeeded"
		case "attempted_after_plan":
			r.Steps[1].Attempts = 1
		case "conditional_skip":
			r.Steps[1].Metadata = map[string]any{"condition": "{{ steps.plan-original-guest.metadata.mode }} == provision", "skip_reason": "condition"}
		case "abort_error":
			r.Steps[1].Error = ""
		case "step_order":
			r.Steps[1], r.Steps[2] = r.Steps[2], r.Steps[1]
		case "kind":
			r.Steps[0].Kind = "integration"
		case "capability":
			r.Steps[0].Capability = "capacity.complete_original_guest"
		case "clock":
			r.Steps[1].StartedAt = failed.StartedAt.Add(-time.Nanosecond)
		case "stage_missing":
			r.Steps[0].Metadata = nil
		case "stage_extra":
			r.Steps[0].Metadata["claimed_safe"] = true
		case "workflow":
			r.Workflow.ID = uuid.New()
		case "metadata":
			r.Metadata["foreign"] = true
		case "run_start_before_dispatch":
			r.StartedAt = failed.StartedAt.Add(-time.Nanosecond)
		case "run_start_at_deadline":
			r.StartedAt = *failed.LeaseExpiresAt
		case "step_before_run_start":
			r.Steps[0].StartedAt = r.StartedAt.Add(-time.Nanosecond)
		case "skip_before_response_finish":
			r.Steps[1].StartedAt = r.FinishedAt.Add(-time.Nanosecond)
		case "skip_after_actual_return":
			r.Steps[6].FinishedAt = failed.ReturnedAt.Add(time.Nanosecond)
		case "failed_step_metadata":
			delete(r.Metadata, "failed_step")
		}
		if preActionFailedPlanResult(installedTimeoutWire(t, r), failed, spec, *failed.StartedAt, *failed.ReturnedAt) {
			t.Fatal("malformed actual graph accepted", fault)
		}
	}
}

func preActionPlanNoReceipt(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob) {
	t.Helper()
	var count int
	if err := f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_preaction_plan_dispositions WHERE job_id=$1", job.JobID).Scan(&count); err != nil || count != 0 {
		t.Fatal("refused original acquired receipt", count, err)
	}
}

func preActionPlanRefusedAdmission(t *testing.T, f *installedTimeoutFixture, job CapacityDispatchJob, next CapacityDispatchEnvelope) {
	t.Helper()
	before := f.preserved(t)
	var originalRun, dispatchBefore, dispatchAfter, runAfter string
	query := "SELECT row_to_json(w)::text,(to_jsonb(j)-ARRAY['pending_wake_count','updated_at'])::text FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1"
	if err := f.db.QueryRow(query, job.JobID).Scan(&originalRun, &dispatchBefore); err != nil {
		t.Fatal(err)
	}
	current, err := readCapacityDispatchJob(context.Background(), f.db, job.JobID, false)
	if err != nil {
		t.Fatal(err)
	}
	got, merged, err := f.enqueue(next)
	if err != nil || !merged || got.JobID != job.JobID || got.RunID != job.RunID || got.PendingWakeCount != current.PendingWakeCount+1 {
		t.Fatal("ineligible unknown/live plan was not retained", merged, err)
	}
	preActionPlanNoReceipt(t, f, job)
	if err = f.db.QueryRow(query, job.JobID).Scan(&runAfter, &dispatchAfter); err != nil || originalRun != runAfter || dispatchBefore != dispatchAfter || !reflect.DeepEqual(before, f.preserved(t)) {
		t.Fatal("refused admission changed immutable originals", err)
	}
}

func TestCapacityDispatchPreActionFailedPlanDispositionPostgres(t *testing.T) {
	for _, name := range []string{"closed_failed_plan_after_M98_anchor", "second_failed_plan_phase_a", "second_failed_plan_phase_b", "concurrent_wakes_single_successor", "committed_resume_cannot_be_relabelled", "wire_shape_and_effect_guards", "deferred_links_and_immutability", "catalog_index_and_old_schema", "unanchored_plan_refused"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			owner := &preActionPlanDBOwner{}
			if name == "second_failed_plan_phase_b" {
				f, anchor, queued, h := preActionPlanLoadHandoff(t)
				job := preActionPlanStart(t, f, queued)
				preActionPlanFinish(t, f, job)
				failed, err := readCapacityDispatchJob(ctx, f.db, job.JobID, false)
				if err != nil {
					t.Fatal(err)
				}
				next, second := preActionPlanAdmit(t, f, failed, anchor)
				if second.RootAnchorID != anchor.ID || second.ID == h.FirstDispositionID || second.JobID == h.FirstPlanJobID {
					t.Fatal("repeat did not retain exact root with distinct receipt")
				}
				started := preActionPlanStart(t, f, next)
				f.resume(t, started, true)
				for _, id := range []string{h.FirstPlanJobID, second.JobID} {
					historical, err := ReadCapacityDispatchPreActionPlanDisposition(ctx, f.db, uuid.MustParse(id))
					if err != nil || historical.RootAnchorID != anchor.ID {
						t.Fatal("historical reader invalid after genuine fresh fence", err)
					}
				}
				var count int
				if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_preaction_plan_dispositions").Scan(&count); err != nil || count != 2 {
					t.Fatal("repeat receipt uniqueness", count, err)
				}
				return
			}
			if name == "unanchored_plan_refused" {
				f := newPreActionAnchorFixture(t, 2, owner)
				if err := goose.UpToContext(ctx, f.db, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 99); err != nil {
					t.Fatal(err)
				}
				preActionPlanFinish(t, f, f.job)
				failed, err := readCapacityDispatchJob(ctx, f.db, f.job.JobID, false)
				if err != nil {
					t.Fatal(err)
				}
				preActionPlanRefusedAdmission(t, f, failed, f.envelope(t))
				return
			}
			n := 2
			if name == "closed_failed_plan_after_M98_anchor" {
				n = 8
			}
			f, anchor, queued := preActionPlanAnchored(t, n, owner, name != "catalog_index_and_old_schema")
			job := preActionPlanStart(t, f, queued)
			if name == "wire_shape_and_effect_guards" {
				// Genuine STARTED context remains live and cannot be disposed.
				got, merged, err := f.enqueue(f.envelope(t))
				if err != nil || !merged || got.JobID != job.JobID {
					t.Fatal("live context admitted", merged, err)
				}
				preActionPlanNoReceipt(t, f, job)
				response := preActionPlanResponse(t, f, job)
				at := preActionPlanObservedReturn(response)
				err = FinishCapacityDispatch(ctx, f.db, job, response, at, errors.New("declared original planner failure"), func(context.Context) error { return errors.New("declared observed ACK loss") })
				if !errors.Is(err, ErrCapacityDispatchUnknown) {
					t.Fatal("actual early first-commit/ACK failure", err)
				}
				early, readErr := readCapacityDispatchJob(ctx, f.db, job.JobID, false)
				var returnedError, finalizationError, workflowError string
				if readErr != nil || early.State != "unknown" || early.FinalizationAckAt != nil || early.ReturnedAt == nil || !early.ReturnedAt.Before(*early.LeaseExpiresAt) || !time.Now().Before(*early.LeaseExpiresAt) {
					t.Fatal("actual early unknown before unmodified deadline", readErr)
				}
				if err = f.db.QueryRow("SELECT j.return_error,j.finalization_error,w.error FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=$1", job.JobID).Scan(&returnedError, &finalizationError, &workflowError); err != nil || returnedError == "" || finalizationError == "" || returnedError == finalizationError || workflowError != finalizationError {
					t.Fatal("honest first-return versus finalization error domains", err)
				}
				preActionPlanRefusedAdmission(t, f, early, f.envelope(t))
			}
			if name == "concurrent_wakes_single_successor" {
				f.db.SetMaxOpenConns(2)
				f.db.SetMaxIdleConns(2)
				for i := 1; i < MaxCapacityDispatchPendingWakes; i++ {
					got, merged, err := f.enqueue(f.envelope(t))
					if err != nil || !merged || got.JobID != job.JobID {
						t.Fatal("bounded pending wakes", merged, err)
					}
				}
				if _, _, err := f.enqueue(f.envelope(t)); !errors.Is(err, ErrCapacityDispatchSaturated) {
					t.Fatal("original pending cap changed", err)
				}
			}
			if name == "committed_resume_cannot_be_relabelled" {
				f.resume(t, job, true)
			}
			if name == "wire_shape_and_effect_guards" {
				time.Sleep(time.Until(*job.LeaseExpiresAt) + 2*time.Millisecond)
			} else {
				preActionPlanFinish(t, f, job)
			}
			failed, err := readCapacityDispatchJob(ctx, f.db, job.JobID, false)
			if err != nil {
				t.Fatal(err)
			}
			if name == "committed_resume_cannot_be_relabelled" {
				preActionPlanRefusedAdmission(t, f, failed, f.envelope(t))
				return
			}
			if name == "catalog_index_and_old_schema" {
				// Schema98 has no new ledger; the automatic old behavior must
				// remain coalescing without an undefined-function transaction.
				got, merged, err := f.enqueue(f.envelope(t))
				if err != nil || !merged || got.JobID != failed.JobID {
					t.Fatal("missing99 compatibility", merged, err)
				}
				before := preActionPlanCatalog(t, f.db)
				if err = goose.UpToContext(ctx, f.db, filepath.Join(failedServingRepositoryRoot(t), "db", "migrations"), 99); err != nil {
					t.Fatal(err)
				}
				preActionPlanCatalogArtifact(t, f.db, before)
			}
			if name == "wire_shape_and_effect_guards" {
				for _, fault := range []string{"principal", "binding", "rbac", "authorization", "workflow", "policy"} {
					next := f.envelope(t)
					switch fault {
					case "principal":
						next.PrincipalSHA256 = strings.Repeat("1", 64)
					case "binding":
						next.BindingSHA256 = strings.Repeat("2", 64)
					case "rbac":
						next.RBAC.ID = uuid.New()
					case "authorization":
						pin := next.RBAC
						next.AuthorizationPolicy = &pin
					case "workflow":
						next.Workflow.Checksum = strings.Repeat("3", 64)
					case "policy":
						next.Policy.Checksum = strings.Repeat("4", 64)
					}
					preActionPlanRefusedAdmission(t, f, failed, next)
				}
			}
			if name == "wire_shape_and_effect_guards" {
				for _, fault := range []struct {
					query string
					args  []any
				}{
					{"INSERT INTO public.capacity_intent_events(namespace,environment,domain,dimension,generation,fencing_token,phase,receipt_ref) VALUES($1,$2,$3,$4,$5,$6,'preparing','declared-forbidden-new-event')", []any{f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, f.intent.Generation, f.intent.FencingToken}},
					{"UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{generation}',to_jsonb($5::bigint)) WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4", []any{f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, f.intent.Generation + 1}},
					{"UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{fencing_token}',to_jsonb($5::bigint)) WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4", []any{f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension, f.intent.FencingToken + 1}},
					{"UPDATE public.capacity_resource_slots SET resource_id='foreign-resource',slot_record=jsonb_set(slot_record,'{resource_id}',to_jsonb('foreign-resource'::text)) WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND slot=2", []any{f.policy.Metadata.Namespace, f.p.Environment, f.p.Domain, f.p.Dimension}},
				} {
					tx, err := f.db.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = tx.Exec(fault.query, fault.args...); err != nil {
						tx.Rollback()
						t.Fatal("declared independent stored fault", err)
					}
					retained, merged, err := EnqueueCapacityDispatch(ctx, tx, f.envelope(t))
					if err != nil || !merged || retained.JobID != failed.JobID {
						tx.Rollback()
						t.Fatal("independent current/effect fault admitted", merged, err)
					}
					var count int
					if err = tx.QueryRow("SELECT count(*) FROM public.capacity_dispatch_preaction_plan_dispositions WHERE job_id=$1", failed.JobID).Scan(&count); err != nil || count != 0 {
						tx.Rollback()
						t.Fatal("fault obtained receipt", count, err)
					}
					if err = tx.Rollback(); err != nil {
						t.Fatal(err)
					}
				}
			}
			if name == "deferred_links_and_immutability" {
				preActionPlanDeniedSQL(t, f, "UPDATE public.capacity_dispatch_jobs SET state='preaction_plan_disposed' WHERE id=$1", failed.JobID)
				// Production admission must roll back its receipt, terminal and
				// explicit successor together when the caller rolls back.
				tx, err := f.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				candidate := f.envelope(t)
				admitted, merged, err := EnqueueCapacityDispatch(ctx, tx, candidate)
				if err != nil || merged || admitted.JobID != candidate.JobID {
					tx.Rollback()
					t.Fatal("actual transactional admission", merged, err)
				}
				if err = tx.Rollback(); err != nil {
					t.Fatal(err)
				}
				preActionPlanNoReceipt(t, f, failed)
				var exists bool
				if err = f.db.QueryRow("SELECT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE id=$1) OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE id=$2)", candidate.JobID, candidate.RunID).Scan(&exists); err != nil || exists {
					t.Fatal("rolled back successor escaped", err)
				}
				for _, fault := range []string{"missing_wake", "wrong_run_inputs"} {
					tx, err := f.db.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					candidate := f.envelope(t)
					next, merged, err := EnqueueCapacityDispatch(ctx, tx, candidate)
					if err != nil || merged {
						tx.Rollback()
						t.Fatal("deferred-link setup", err)
					}
					if fault == "missing_wake" {
						_, err = tx.Exec("DELETE FROM public.capacity_dispatch_wakes WHERE job_id=$1", next.JobID)
					} else {
						_, err = tx.Exec("UPDATE public.workflow_runs SET inputs=jsonb_build_object('foreign',true) WHERE id=$1", next.RunID)
					}
					if err != nil {
						tx.Rollback()
						t.Fatal("deferred-link fault must reach COMMIT", fault, err)
					}
					if err = tx.Commit(); err == nil || !strings.Contains(err.Error(), "preaction plan needs one exact distinct queued successor") {
						t.Fatal("deferred link did not reject COMMIT", fault, err)
					}
					preActionPlanNoReceipt(t, f, failed)
				}
				tx, err = f.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				forged := f.envelope(t)
				version := forged.Workflow.Version
				if err = InsertWorkflowRunTx(ctx, tx, forged.RunID, model.ManifestSelector{Namespace: forged.Workflow.Namespace, Name: forged.Workflow.Name, Version: &version}, forged.Inputs, forged.Metadata); err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
				forgedWire, err := encodeCapacityDispatchEnvelope(forged)
				if err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
				_, err = tx.Exec("INSERT INTO public.capacity_dispatch_jobs SELECT (jsonb_populate_record(NULL::public.capacity_dispatch_jobs,(SELECT to_jsonb(j) FROM public.capacity_dispatch_jobs j WHERE id=$1)||jsonb_build_object('id',$2::uuid,'run_id',$3::uuid,'envelope',$4::text,'envelope_sha256',$5::text,'state','preaction_plan_disposed'))).*", failed.JobID, forged.JobID, forged.RunID, string(forgedWire), capacityDispatchSHA(forgedWire))
				_ = tx.Rollback()
				if err == nil || !strings.Contains(err.Error(), "preaction plan terminal needs retained original job") {
					t.Fatal("direct terminal INSERT guard", err)
				}
			}
			if name == "concurrent_wakes_single_successor" {
				type answer struct {
					job    CapacityDispatchJob
					merged bool
					err    error
				}
				results := make(chan answer, 4)
				var wg sync.WaitGroup
				for i := 0; i < 4; i++ {
					next := f.envelope(t)
					wg.Add(1)
					go func() { defer wg.Done(); got, merged, err := f.enqueue(next); results <- answer{got, merged, err} }()
				}
				wg.Wait()
				close(results)
				fresh := 0
				var winner CapacityDispatchJob
				var ids []uuid.UUID
				for v := range results {
					if v.err != nil {
						t.Fatal(v.err)
					}
					ids = append(ids, v.job.JobID)
					if !v.merged {
						fresh++
						winner = v.job
					}
				}
				if fresh != 1 {
					t.Fatal("racing admission count", fresh)
				}
				for _, id := range ids {
					if id != winner.JobID {
						t.Fatal("racing wakes split successor")
					}
				}
				receipt, err := ReadCapacityDispatchPreActionPlanDisposition(ctx, f.db, failed.JobID)
				if err != nil || receipt.RootAnchorID != anchor.ID || receipt.SuccessorJobID != winner.JobID.String() {
					t.Fatal("race immutable receipt", err)
				}
				var count int
				if err = f.db.QueryRow("SELECT count(*) FROM public.capacity_dispatch_preaction_plan_dispositions").Scan(&count); err != nil || count != 1 {
					t.Fatal("race receipt uniqueness", count, err)
				}
				return
			}
			next, receipt := preActionPlanAdmit(t, f, failed, anchor)
			if name == "second_failed_plan_phase_a" {
				preActionPlanSaveHandoff(t, owner, f, anchor, receipt, next)
				return
			}
			if name == "wire_shape_and_effect_guards" {
				preActionPlanSQLVectors(t, f, failed)
			}
			if name == "deferred_links_and_immutability" {
				preActionPlanDeniedSQL(t, f, "UPDATE public.capacity_dispatch_preaction_plan_dispositions SET recorded_at=recorded_at+interval '1 second' WHERE id=$1", receipt.ID)
				preActionPlanDeniedSQL(t, f, "DELETE FROM public.capacity_dispatch_preaction_plan_dispositions WHERE id=$1", receipt.ID)
				preActionPlanDeniedSQL(t, f, "UPDATE public.capacity_dispatch_jobs SET state='unknown' WHERE id=$1", failed.JobID)
				preActionPlanDeniedSQL(t, f, "UPDATE public.workflow_runs SET error='changed historical failure' WHERE id=$1", failed.RunID)
			}
			before := preActionPlanOriginals(t, f, failed)
			started := preActionPlanStart(t, f, next)
			f.resume(t, started, true)
			historical, err := ReadCapacityDispatchPreActionPlanDisposition(ctx, f.db, failed.JobID)
			if err != nil || historical.ID != receipt.ID || historical.RootAnchorID != anchor.ID {
				t.Fatal("reader lost historical proof after fresh intent fence", err)
			}
			if !reflect.DeepEqual(before, preActionPlanOriginals(t, f, failed)) {
				t.Fatal("read-only installed readiness changed originals")
			}
		})
	}
}

func preActionPlanCatalog(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	query := "SELECT jsonb_build_object('server_version_num',current_setting('server_version_num')::int,'history_wire',(SELECT json_agg(row_to_json(g) ORDER BY id)::text FROM public.goose_db_version g),'functions',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind='f'),'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',c.conname,'kind',c.contype,'validated',c.convalidated,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY r.relname,c.conname),'[]'::jsonb) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public'),'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',g.tgname,'enabled',g.tgenabled,'definition',pg_get_triggerdef(g.oid,false)) ORDER BY r.relname,g.tgname),'[]'::jsonb) FROM pg_trigger g JOIN pg_class r ON r.oid=g.tgrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND NOT g.tgisinternal),'columns',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'has_default',a.atthasdef) ORDER BY r.relname,a.attnum),'[]'::jsonb) FROM pg_attribute a JOIN pg_class r ON r.oid=a.attrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND r.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped),'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',r.relname,'name',c.relname,'definition',pg_get_indexdef(x.indexrelid),'predicate',pg_get_expr(x.indpred,x.indrelid),'expressions',pg_get_expr(x.indexprs,x.indrelid),'valid',x.indisvalid,'ready',x.indisready,'live',x.indislive,'primary',x.indisprimary,'unique',x.indisunique,'keys',x.indkey::text,'key_count',x.indnkeyatts,'method',am.amname) ORDER BY r.relname,c.relname),'[]'::jsonb) FROM pg_index x JOIN pg_class r ON r.oid=x.indrelid JOIN pg_class c ON c.oid=x.indexrelid JOIN pg_namespace n ON n.oid=r.relnamespace JOIN pg_am am ON am.oid=c.relam WHERE n.nspname='public'))::text"
	var raw []byte
	if err := db.QueryRow(query).Scan(&raw); err != nil {
		t.Fatal("complete actual schema98/99 catalog", err)
	}
	return raw
}

func preActionPlanCatalogArtifact(t *testing.T, db *sql.DB, before []byte) {
	t.Helper()
	after := preActionPlanCatalog(t, db)
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
		t.Fatal("actual PG16/17 catalogs required")
	}
	var previous, current []map[string]any
	if json.Unmarshal([]byte(old.History), &previous) != nil || json.Unmarshal([]byte(next.History), &current) != nil || len(current) != len(previous)+1 || !reflect.DeepEqual(previous, current[:len(previous)]) || current[len(previous)]["version_id"] != float64(99) || current[len(previous)]["is_applied"] != true {
		t.Fatal("history not sole99 append")
	}
	key := func(r row) string { return r["table"].(string) + "/" + r["name"].(string) }
	rows := func(v []row) map[string]row {
		m := map[string]row{}
		for _, r := range v {
			m[key(r)] = r
		}
		return m
	}
	fnKey := func(r row) string { return r["name"].(string) + "(" + r["arguments"].(string) + ")" }
	newFn := map[string]row{}
	for _, r := range next.Functions {
		newFn[fnKey(r)] = r
	}
	changed := []string{}
	for _, r := range old.Functions {
		n, ok := newFn[fnKey(r)]
		if !ok {
			t.Fatal("removed historical function", r["name"])
		}
		if !reflect.DeepEqual(r, n) {
			if r["name"] != "guard_capacity_dispatch_job" {
				t.Fatal("unrelated prior function changed", r["name"])
			}
			changed = append(changed, r["name"].(string))
		}
	}
	if len(changed) != 1 {
		t.Fatal("exact old guard-prefix extension required", changed)
	}
	oldC, newC := rows(old.Constraints), rows(next.Constraints)
	for _, name := range []string{"capacity_dispatch_jobs_state_v10_check", "capacity_dispatch_jobs_lifecycle_v10_check"} {
		k := "capacity_dispatch_jobs/" + name
		if oldC[k] == nil || newC[k] != nil {
			t.Fatal("old predicate replacement", name)
		}
		delete(oldC, k)
	}
	for _, name := range []string{"capacity_dispatch_jobs_state_v11_check", "capacity_dispatch_jobs_lifecycle_v11_check"} {
		k := "capacity_dispatch_jobs/" + name
		if newC[k] == nil || newC[k]["validated"] != true {
			t.Fatal("new validated predicate", name)
		}
		delete(newC, k)
	}
	newTable := "capacity_dispatch_preaction_plan_dispositions"
	for k, r := range newC {
		if r["validated"] != true {
			t.Fatal("unvalidated constraint", k)
		}
		if r["table"] == newTable {
			delete(newC, k)
		}
	}
	if !reflect.DeepEqual(oldC, newC) {
		t.Fatal("unrelated prior constraints changed")
	}
	for _, pair := range [][2][]row{{old.Triggers, next.Triggers}, {old.Columns, next.Columns}, {old.Indexes, next.Indexes}} {
		currentRows := rows(pair[1])
		for _, r := range pair[0] {
			if !reflect.DeepEqual(r, currentRows[key(r)]) {
				t.Fatal("historical catalog row changed", key(r))
			}
		}
	}
	columns, unique := 0, 0
	expectedColumns := map[string]string{"id": "uuid", "job_id": "uuid", "run_id": "uuid", "successor_job_id": "uuid", "successor_run_id": "uuid", "original_record": "jsonb", "original_wire": "bytea", "original_dispatch_wire": "bytea", "original_run_wire": "bytea", "original_intent_wire": "bytea", "members_wire": "bytea", "evidence_wire": "bytea", "recorded_at": "timestamp with time zone"}
	uniqueNumbers := map[string]bool{}
	for _, r := range next.Columns {
		if r["table"] == newTable {
			columns++
			name := r["name"].(string)
			if r["not_null"] != true || r["has_default"] != false || expectedColumns[name] != r["type"] {
				t.Fatal("new ledger explicit closed column", r)
			}
			if name == "id" || name == "job_id" || name == "run_id" || name == "successor_job_id" || name == "successor_run_id" {
				uniqueNumbers[strconv.Itoa(int(r["number"].(float64)))] = true
			}
		}
	}
	if columns != 13 {
		t.Fatal("closed13 ledger columns", columns)
	}
	fk, deferred := 0, 0
	for _, r := range next.Constraints {
		if r["table"] == newTable && r["kind"] == "f" {
			fk++
			if strings.Contains(r["definition"].(string), "DEFERRABLE INITIALLY DEFERRED") {
				deferred++
			}
		}
	}
	if fk != 4 || deferred != 2 {
		t.Fatal("four causal foreign keys and two deferred successor links", fk, deferred)
	}
	var partial row
	seenUnique := map[string]bool{}
	for _, r := range next.Indexes {
		if r["table"] == newTable {
			if r["valid"] != true || r["ready"] != true || r["live"] != true || r["unique"] != true || r["key_count"] != float64(1) {
				t.Fatal("new ledger index invalid", r)
			}
			unique++
			seenUnique[r["keys"].(string)] = true
		}
		if r["name"] == "capacity_dispatch_failed_workflow_returned_idx" {
			partial = r
		}
	}
	if !reflect.DeepEqual(uniqueNumbers, seenUnique) {
		t.Fatal("five unique original/successor identities", uniqueNumbers, seenUnique)
	}
	if unique != 5 || partial == nil || partial["table"] != "capacity_dispatch_jobs" || partial["valid"] != true || partial["ready"] != true || partial["live"] != true || partial["unique"] != false || partial["method"] != "btree" || partial["key_count"] != float64(2) {
		t.Fatal("exact actual five unique and valid lookup indexes", unique, partial)
	}
	var exact bool
	if err := db.QueryRow("SELECT x.indkey[0]=0 AND x.indkey[1]=a.attnum AND x.indnkeyatts=2 AND NOT x.indisunique AND pg_get_expr(x.indexprs,x.indrelid) LIKE '%workflow%' AND pg_get_expr(x.indexprs,x.indrelid) LIKE '%envelope%' AND pg_get_expr(x.indpred,x.indrelid) LIKE '%returned%' AND pg_get_expr(x.indpred,x.indrelid) LIKE '%failed%' AND pg_get_expr(x.indpred,x.indrelid) LIKE '%finalization_ack_at IS NOT NULL%' FROM pg_index x JOIN pg_class c ON c.oid=x.indexrelid JOIN pg_attribute a ON a.attrelid=x.indrelid AND a.attname='returned_at' WHERE c.oid='public.capacity_dispatch_failed_workflow_returned_idx'::regclass").Scan(&exact); err != nil || !exact {
		t.Fatal("actual index expression/key/predicate", err)
	}
	dir := os.Getenv("PREACTION_PLAN_LOGS")
	if !filepath.IsAbs(dir) {
		t.Fatal("explicit owned catalog evidence directory required")
	}
	put := func(name string, raw []byte) map[string]any {
		p := filepath.Join(dir, name)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		n, err := f.Write(raw)
		if err != nil || n != len(raw) {
			f.Close()
			t.Fatal("whole catalog evidence", err)
		}
		if err = f.Sync(); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		return map[string]any{"path": p, "bytes": len(raw), "sha256": capacity.BusinessCreationSHA256(raw)}
	}
	beforeRef := put("M99-PG-BEFORE98-CATALOG.original.json", before)
	afterRef := put("M99-PG-AFTER99-CATALOG.original.json", after)
	files, err := filepath.Glob(filepath.Join(failedServingRepositoryRoot(t), "db", "migrations", "00099_*.sql"))
	if err != nil || len(files) != 1 {
		t.Fatal("sole migration99 Source", files, err)
	}
	sqlSource, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"schema": "preaction_failed_plan_schema99_pg_catalog_v1", "source_commit": capacity.CurrentGuestCoreSource(), "postgres_major": next.Version / 10000, "fixture_only": true, "native_authority": false, "before98_ref": beforeRef, "after99_ref": afterRef, "migration99_sha256": capacity.BusinessCreationSHA256(sqlSource), "history_sole99_append": true, "old_public_functions_changed": changed, "new_table_columns": columns, "new_table_unique_indexes": unique, "lookup_index": partial, "all_constraints_validated": true}
	put("M99-PG-CHECK-DEPARSE.RESULT.PUBLIC.json", append(installedTimeoutWire(t, manifest), '\n'))
}
