package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/lib/pq"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

// This is CI source/SQL/transport provenance, never useful physical capacity.
// The actual selected Prometheus fixture computes its original range response.
type demandFixture struct {
	dispatchHTTPFixture
	source model.Manifest
	broker *amqp.Connection
	event  repository.CapacityDemandEvent
}

// Remote-CI-only loss of the return acknowledgement, AFTER the one original
// pq Commit has returned success. Every original connection interface below
// is delegated unchanged; this never fabricates the commit or replays SQL.
type demandOriginalConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.QueryerContext
	driver.ExecerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

type demandAckConnector struct {
	driver.Connector
	lost             atomic.Bool
	commits          atomic.Int64
	auditCommits     atomic.Int64
	otherCommits     atomic.Int64
	admissionCommits atomic.Int64
	wakeStatements   atomic.Int64
	cursorStatements atomic.Int64
	cause            error
	cursorID         string
	heldRunID        string
	entered          chan struct{}
	release          chan struct{}
	holdOnce         sync.Once
}

func (c *demandAckConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	original, ok := conn.(demandOriginalConn)
	if !ok {
		return nil, errors.Join(errors.New("original pq interfaces missing"), conn.Close())
	}
	return &demandAckConn{demandOriginalConn: original, owner: c}, nil
}

type demandAckConn struct {
	demandOriginalConn
	owner  *demandAckConnector
	mu     sync.Mutex
	active *demandAckTx
}

func (c *demandAckConn) Begin() (driver.Tx, error) {
	tx, err := c.demandOriginalConn.Begin()
	return c.wrapTx(tx, err)
}

func (c *demandAckConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.demandOriginalConn.BeginTx(ctx, opts)
	return c.wrapTx(tx, err)
}

func (c *demandAckConn) wrapTx(tx driver.Tx, err error) (driver.Tx, error) {
	if err != nil {
		return nil, err
	}
	wrapped := &demandAckTx{Tx: tx, conn: c}
	c.mu.Lock()
	c.active = wrapped
	c.mu.Unlock()
	return wrapped, nil
}

// Classify only the SQL actually accepted by the original pq connection in
// this exact TX. An authorization audit Commit cannot consume lost-ACK quota.
func (c *demandAckConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	result, err := c.demandOriginalConn.ExecContext(ctx, query, args)
	if err == nil && result != nil {
		if n, countErr := result.RowsAffected(); countErr == nil && n == 1 {
			c.mu.Lock()
			if tx := c.active; tx != nil {
				if strings.HasPrefix(query, "INSERT INTO public.capacity_dispatch_wakes ") {
					tx.wake = true
					c.owner.wakeStatements.Add(1)
				}
				if strings.HasPrefix(query, "UPDATE public.workflow_event_trigger_state SET last_cursor=") && len(args) > 0 {
					if id, ok := args[0].Value.(string); ok && c.owner.cursorID != "" && id == c.owner.cursorID {
						tx.cursor = true
						c.owner.cursorStatements.Add(1)
					}
				}
			}
			c.mu.Unlock()
		}
	}
	return result, err
}

func (c *demandAckConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.demandOriginalConn.QueryContext(ctx, query, args)
	if err == nil && rows != nil && strings.HasPrefix(strings.TrimSpace(query), "INSERT INTO public.event_log (") && len(args) == 11 {
		c.mu.Lock()
		if c.active != nil {
			if args[1].Value == "authorization.evaluated" {
				c.active.audit = true
			}
			if args[1].Value == "workflow.run.completed" && args[4].Value == c.owner.heldRunID {
				c.active.heldCompletion = true
			}
		}
		c.mu.Unlock()
	}
	return rows, err
}

type demandAckTx struct {
	driver.Tx
	conn           *demandAckConn
	wake, cursor   bool
	audit          bool
	heldCompletion bool
}

func (tx *demandAckTx) Commit() error {
	if tx.heldCompletion {
		tx.conn.owner.holdOnce.Do(func() {
			close(tx.conn.owner.entered)
			<-tx.conn.owner.release
		})
	}
	err := tx.Tx.Commit()
	tx.conn.mu.Lock()
	admission := tx.wake && tx.cursor
	tx.conn.active = nil
	tx.conn.mu.Unlock()
	if err == nil {
		tx.conn.owner.commits.Add(1)
		if admission {
			tx.conn.owner.admissionCommits.Add(1)
			if tx.conn.owner.lost.Swap(false) {
				return tx.conn.owner.cause
			}
		} else if tx.audit {
			tx.conn.owner.auditCommits.Add(1)
		} else {
			tx.conn.owner.otherCommits.Add(1)
		}
	}
	return err
}

func (tx *demandAckTx) Rollback() error {
	err := tx.Tx.Rollback()
	tx.conn.mu.Lock()
	tx.conn.active = nil
	tx.conn.mu.Unlock()
	return err
}

type demandLog struct {
	raw      bytes.Buffer
	overflow bool
}

func (b *demandLog) Write(p []byte) (int, error) {
	if b.raw.Len()+len(p) > 1<<20 {
		b.overflow = true
		return len(p), nil
	}
	return b.raw.Write(p)
}

func demandMetricProducer(t *testing.T, input any) (map[string]any, error) {
	t.Helper()
	binary := os.Getenv("CAPACITY_METRIC_FIXTURE_BINARY")
	if binary == "" {
		return nil, errors.New("exact remote metric source producer required")
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json")
	raw, err := json.Marshal(input)
	if err != nil || os.WriteFile(in, raw, 0600) != nil {
		return nil, errors.New("bounded fixture input unavailable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestCapacityCoreMetricSourceFixtureProducer$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CAPACITY_NATIVE_INPUT_FILE="+in, "CAPACITY_NATIVE_OUTPUT_FILE="+out)
	var log demandLog
	cmd.Stdout = &log
	cmd.Stderr = &log
	err = cmd.Run() // original Start/Wait, including actual output copier returns
	if err != nil || dispatchContext(ctx) != nil || log.overflow {
		return nil, errors.New("original compiled metric producer unresolved")
	}
	f, err := os.Open(out)
	if err != nil {
		return nil, errors.New("native fixture output unavailable")
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, 1<<20+1))
	closeErr := f.Close()
	if errors.Join(readErr, closeErr, dispatchContext(ctx)) != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("original fixture output read/Close unresolved")
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return nil, errors.New("native fixture output malformed")
	}
	return value, nil
}

func newDemandFixture(t *testing.T) demandFixture {
	t.Helper()
	return newDemandFixtureWithEvent(t, true)
}

func newDemandFixtureWithEvent(t *testing.T, emit bool) demandFixture {
	t.Helper()
	f := dispatchHTTPPostgresFixture(t)
	if os.Getenv("REQUIRE_CAPACITY_POSTGRES") != "true" {
		t.Fatal("demand gate must own actual PostgreSQL")
	}
	broker, err := amqp.Dial(os.Getenv("CAPACITY_DISPATCH_BROKER_URL"))
	if err != nil {
		t.Fatal("original remote broker required")
	}
	f.server.rabbitmq = broker
	t.Setenv("BROKER_URL", os.Getenv("CAPACITY_DISPATCH_BROKER_URL"))
	t.Cleanup(func() {
		if !broker.IsClosed() && broker.Close() != nil {
			t.Error("original broker Close unresolved")
		}
	})
	metricAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/query_range" || r.ParseForm() != nil {
			t.Error("original range request differs")
			w.WriteHeader(400)
			return
		}
		query := r.Form.Get("query")
		if query != "fixed-pressure" && query != "min(timestamp(fixed-source))" {
			t.Error("unbound query")
			w.WriteHeader(400)
			return
		}
		start, _ := strconv.ParseInt(r.Form.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(r.Form.Get("end"), 10, 64)
		if end-start != 60 || r.Form.Get("step") != "15" {
			t.Error("native grid differs")
		}
		points := [][]any{}
		for at := start; at <= end; at += 15 {
			v := "0.9"
			if query != "fixed-pressure" {
				v = strconv.FormatInt(at, 10)
			}
			points = append(points, []any{at, v})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": []any{map[string]any{"metric": map[string]string{"service": "api"}, "values": points}}}})
	}))
	t.Cleanup(metricAPI.Close)
	config := map[string]any{"prometheus_url": metricAPI.URL, "evidence_bindings": map[string]any{"api-pressure": map[string]any{"name": "load", "source_identity": "prom/api", "unit": "ratio", "value_query": "fixed-pressure", "source_timestamp_query": "min(timestamp(fixed-source))", "expected_labels": map[string]string{"service": "api"}, "window_seconds": 60, "step_seconds": 15, "max_source_age_seconds": 30, "max_gap_seconds": 15, "min_samples": 3}}}
	request := model.AdapterExecuteIntegrationRequest{Operation: capacity.ObserveMetricRange, Capability: capacity.ObserveMetricRange, Input: map[string]any{"binding": "api-pressure"}, Integration: model.AdapterExecuteIntegrationContext{InstanceSpec: model.IntegrationInstanceManifestSpec{Config: config}}}
	seed, err := demandMetricProducer(t, map[string]any{"mode": "seed", "request": request})
	if err != nil {
		t.Fatal(err)
	}
	var typ model.IntegrationTypeManifestSpec
	raw, _ := json.Marshal(seed["describe"])
	if json.Unmarshal(raw, &typ) != nil {
		t.Fatal("native Describe unavailable")
	}
	typ.Adapter.Transport = "http_json"
	typ.Adapter.Queues = model.IntegrationAdapterQueue{}
	typ.Adapter.Endpoints = model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute"}
	typ.InstanceSchema.Properties["base_url"] = model.IntegrationSchemaProperty{Type: "string"}
	var describe model.AdapterDescribeResponse
	raw, _ = json.Marshal(typ)
	if json.Unmarshal(raw, &describe) != nil {
		t.Fatal("source Describe invalid")
	}
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/describe":
			_ = json.NewEncoder(w).Encode(describe)
		case "/execute":
			var req model.AdapterExecuteIntegrationRequest
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.Operation != capacity.ObserveMetricRange || req.Capability != req.Operation {
				t.Error("fixed source operation differs")
				w.WriteHeader(400)
				return
			}
			value, err := demandMetricProducer(t, map[string]any{"mode": "complete", "request": req})
			if err != nil {
				t.Error("actual compiled range source did not return")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(value)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(adapter.Close)
	typeManifest := f.create("integration_type", "demand-metrics", typ)
	instance := f.create("integration_instance", "demand-metrics", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typeManifest.ID.String()}, Status: "active", Config: mergeDemandConfig(config, adapter.URL)})
	enabled := true
	source := f.create("workflow", "metric-pulse", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "schedule", Enabled: &enabled, Schedule: &model.WorkflowScheduleTriggerSpec{CronExpression: "*/5 * * * *", Timezone: "UTC"}}, Steps: []model.WorkflowStepSpec{{ID: "range", Use: model.WorkflowStepUseSpec{Kind: "integration", Capability: capacity.ObserveMetricRange, InstanceRef: &model.ManifestSelector{ManifestID: instance.ID.String()}}, With: map[string]any{"binding": "api-pressure"}}}})
	p := f.spec
	binding := *p.ControllerBinding
	binding.DemandSource = &model.CapacityDemandSourceBinding{Mode: "core_workflow_completion_v1", ManifestID: source.ID.String(), Namespace: source.Metadata.Namespace, Name: source.Metadata.Name, Version: source.Version, Checksum: source.Checksum, MaxAgeSeconds: 60}
	p.ControllerBinding = &binding
	f.policy, f.spec = f.create("capacity_policy", "pods", p), p
	scope := demandScope(capacityDemandPolicy{f.policy, f.spec})
	cursorID, err := scope.CursorID()
	if err != nil {
		t.Fatal("fixed per-dimension cursor identity invalid")
	}
	var oldCursor string
	cursorErr := f.db.QueryRow(`SELECT last_cursor FROM public.workflow_event_trigger_state WHERE id=$1`, cursorID).Scan(&oldCursor)
	if cursorErr != nil && !errors.Is(cursorErr, sql.ErrNoRows) {
		t.Fatal("original private cursor unknown")
	}
	t.Cleanup(func() {
		if _, err := f.db.Exec(`DELETE FROM public.event_log WHERE aggregate_type='workflow_run' AND payload->'workflow_ref'->>'namespace'=$1`, source.Metadata.Namespace); err != nil {
			t.Error(err)
		}
		if errors.Is(cursorErr, sql.ErrNoRows) {
			_, err = f.db.Exec(`DELETE FROM public.workflow_event_trigger_state WHERE id=$1`, cursorID)
		} else {
			_, err = f.db.Exec(`UPDATE public.workflow_event_trigger_state SET last_cursor=$2 WHERE id=$1`, cursorID, oldCursor)
		}
		if err != nil {
			t.Error("private cursor restoration unresolved")
		}
	})
	d := demandFixture{dispatchHTTPFixture: f, source: source, broker: broker}
	if emit {
		d.event = d.publishOriginal(t)
	}
	return d
}

func mergeDemandConfig(config map[string]any, url string) map[string]any {
	out := map[string]any{}
	for k, v := range config {
		out[k] = v
	}
	out["base_url"] = url
	return out
}

func (f demandFixture) completeOriginal(t *testing.T) (model.RunWorkflowResponse, uuid.UUID) {
	t.Helper()
	id := uuid.New()
	version := f.source.Version
	metadata := map[string]any{"triggered_by": "workflow_scheduler", "manifest_id": f.source.ID.String(), "scheduled_for": time.Now().UTC().Truncate(time.Minute).Format(time.RFC3339)}
	selector := model.ManifestSelector{Namespace: f.source.Metadata.Namespace, Name: f.source.Metadata.Name, Version: &version}
	if repository.InsertWorkflowRun(t.Context(), f.db, id, selector, nil, metadata) != nil || repository.MarkWorkflowRunRunning(t.Context(), f.db, id, time.Now().UTC()) != nil {
		t.Fatal("original source run preparation unresolved")
	}
	response, err := messagecontroller.RunWorkflow(t.Context(), f.broker, f.db, model.RunWorkflowRequest{Workflow: selector})
	if err != nil || response.Status != "succeeded" || len(response.Steps) != 1 {
		t.Fatal("original source workflow did not return")
	}
	if repository.FinalizeWorkflowRun(t.Context(), f.db, id, response.Status, response, "", time.Now().UTC()) != nil {
		t.Fatal("original source row did not finalize")
	}
	return response, id
}

func (f demandFixture) publishOriginal(t *testing.T) repository.CapacityDemandEvent {
	t.Helper()
	response, id := f.completeOriginal(t)
	messagecontroller.EmitScheduledWorkflowRunCompletedEvent(t.Context(), f.db, zap.NewNop(), response, id)
	var eventID uuid.UUID
	if f.db.QueryRow(`SELECT event_id FROM public.event_log WHERE type='workflow.run.completed' AND idempotency_key=$1`, id.String()).Scan(&eventID) != nil {
		t.Fatal("original completed event missing")
	}
	event, err := repository.ReadCapacityDemandEvent(t.Context(), f.db, eventID)
	if err != nil {
		t.Fatal("original scheduled SQL lineage unresolved", err)
	}
	return event
}

func (f demandFixture) scope() repository.CapacityDemandScope {
	return demandScope(capacityDemandPolicy{f.policy, f.spec})
}

func (f demandFixture) queued(t *testing.T) repository.CapacityDispatchJob {
	t.Helper()
	if err := f.service.runDemandPass(t.Context()); err != nil {
		t.Fatal("original demand admission failed", err)
	}
	var id uuid.UUID
	if f.db.QueryRow(`SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.policy.Metadata.Namespace).Scan(&id) != nil {
		t.Fatal("original private job missing")
	}
	job, err := repository.ReadCapacityDispatchJob(t.Context(), f.db, id)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestCapacityDispatchDemandPostgres(t *testing.T) {
	t.Run("versioned_cursor_fits_original_sql_column", func(t *testing.T) {
		f := newDemandFixture(t)
		scope := f.scope()
		id, err := scope.CursorID()
		preimage, marshalErr := json.Marshal([]string{repository.CapacityDemandCursorID, scope.Realm, scope.Environment, scope.Domain, scope.Dimension})
		if err != nil || marshalErr != nil || len(id) != 64 || id != fmt.Sprintf("%x", sha256.Sum256(preimage)) {
			t.Fatal("versioned complete cursor SHA differs")
		}
		seen := map[string]bool{id: true}
		for _, field := range []string{"realm", "environment", "domain", "dimension"} {
			changed := scope
			switch field {
			case "realm":
				changed.Realm += "-other"
			case "environment":
				changed.Environment += "-other"
			case "domain":
				changed.Domain += "-other"
			case "dimension":
				changed.Dimension += "-other"
			}
			other, err := changed.CursorID()
			if err != nil || len(other) != 64 || seen[other] {
				t.Fatal("fixed dimensions share a cursor identity")
			}
			seen[other] = true
		}
		var columnLimit int
		if err := f.db.QueryRowContext(t.Context(), `SELECT character_maximum_length FROM information_schema.columns WHERE table_schema='public' AND table_name='workflow_event_trigger_state' AND column_name='id'`).Scan(&columnLimit); err != nil || columnLimit != 64 {
			t.Fatal("original native VARCHAR(64) contract changed", err)
		}
		f.queued(t)
		var retainedID, retainedCursor string
		if err := f.db.QueryRowContext(t.Context(), `SELECT id,last_cursor FROM public.workflow_event_trigger_state WHERE id=$1`, id).Scan(&retainedID, &retainedCursor); err != nil || retainedID != id || retainedCursor != strconv.FormatInt(f.event.Sequence, 10) {
			t.Fatal("original wake did not retain its schema-compatible cursor", err)
		}
	})
	t.Run("original_source_return_and_private_job", func(t *testing.T) {
		f := newDemandFixture(t)
		job := f.queued(t)
		if job.Metadata["source_event_id"] != f.event.EventID.String() || job.Metadata["source_run_id"] != f.event.RunID.String() || len(job.Inputs) != 1 || job.MachinePrincipalID != "dispatch-ci" {
			t.Fatal("demand supplied authority/input")
		}
		ran, err := f.service.RunOne(t.Context(), job.Realm, job.Environment)
		if !ran || err == nil {
			t.Fatal("original bound executor must actually return its missing-catalog refusal")
		}
		observed, e := repository.ReadCapacityDispatchJob(t.Context(), f.db, job.JobID)
		if e != nil || observed.StartedAt == nil || observed.ReturnedAt == nil {
			t.Fatal("original call/return missing")
		}
	})
	t.Run("duplicate_and_uncertain_ack_same_ids", func(t *testing.T) {
		f := newDemandFixture(t)
		original, err := pq.NewConnector(os.Getenv("DB_URL"))
		if err != nil {
			t.Fatal("original pq connector missing")
		}
		cause := errors.New("private committed acknowledgement lost")
		cursorID, err := f.scope().CursorID()
		if err != nil || len(cursorID) != 64 {
			t.Fatal("original fixed ACK cursor identity unresolved")
		}
		connector := &demandAckConnector{Connector: original, cause: cause, cursorID: cursorID}
		connector.lost.Store(true)
		owned := sql.OpenDB(connector)
		defer func() {
			f.server.db = f.db
			if owned.Close() != nil {
				t.Error("original acknowledgement pool Close unresolved")
			}
		}()
		f.server.db = owned
		if err := f.service.runDemandPass(t.Context()); !errors.Is(err, cause) || connector.admissionCommits.Load() != 1 || connector.auditCommits.Load() < 1 || connector.otherCommits.Load() != 0 || connector.commits.Load() != connector.auditCommits.Load()+1 || connector.wakeStatements.Load() != 1 || connector.cursorStatements.Load() != 1 || connector.lost.Load() {
			t.Logf("original ACK observations cause_is=%t admissions=%d audits=%d other=%d commits=%d wakes=%d cursors=%d quota_retained=%t", errors.Is(err, cause), connector.admissionCommits.Load(), connector.auditCommits.Load(), connector.otherCommits.Load(), connector.commits.Load(), connector.wakeStatements.Load(), connector.cursorStatements.Load(), connector.lost.Load())
			t.Fatal("lost acknowledgement did not follow actual original Commit")
		}
		// Independent native reads recover the original durable IDs; no second
		// admission transaction or action occurs when the permanent wake already exists.
		f.server.db = f.db
		var auditRows int64
		resource := "workflow:" + f.workflow.Metadata.Namespace + ":" + f.workflow.Metadata.Name
		if err := f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.event_log
			WHERE type='authorization.evaluated' AND schema_version='v1' AND aggregate_type='authorization' AND aggregate_id=$1
			AND payload->>'resource'=$1 AND payload->>'action'='run' AND payload->>'decision'='allow'
			AND payload->'matched_roles'='["controller"]'::jsonb AND payload->'matched_rules'='["controller/allow"]'::jsonb
			AND payload->'rbac_manifest_ref'->>'id'=$2`, resource, f.rbac.ID.String()).Scan(&auditRows); err != nil || auditRows < 1 || auditRows != connector.auditCommits.Load() {
			t.Fatal("original committed audit rows/ordered role-rule payload differ", auditRows, connector.auditCommits.Load(), err != nil)
		}
		var id uuid.UUID
		if f.db.QueryRow(`SELECT id FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.policy.Metadata.Namespace).Scan(&id) != nil {
			t.Fatal("committed original missing")
		}
		a, err := repository.ReadCapacityDispatchJob(t.Context(), f.db, id)
		if err != nil {
			t.Fatal(err)
		}
		cursor, cursorErr := repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
		var retainedWakes int
		if cursorErr != nil || cursor != strconv.FormatInt(f.event.Sequence, 10) || f.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1 AND source_tick=$2`, f.policy.Metadata.Namespace, "event:"+f.event.EventID.String()).Scan(&retainedWakes) != nil || retainedWakes != 1 {
			t.Fatal("actual wake and diagnostic cursor were not committed together")
		}
		b := f.queued(t)
		if a.JobID != b.JobID || a.RunID != b.RunID || b.PendingWakeCount != 1 || connector.admissionCommits.Load() != 1 {
			t.Fatal("GET-only recovery replaced original")
		}
	})
	t.Run("atomic_rollback_and_cursor", func(t *testing.T) {
		f := newDemandFixture(t)
		p, e := f.service.prepareDemand(t.Context(), capacityDemandPolicy{f.policy, f.spec}, f.event)
		if e != nil {
			t.Fatal(e)
		}
		tx, e := f.db.BeginTx(t.Context(), nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if _, _, e = p.Enqueue(t.Context(), tx); e != nil {
			t.Fatal(e)
		}
		cursor, e := repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
		if e != nil {
			t.Fatal(e)
		}
		if e = repository.AdvanceCapacityDemandCursor(t.Context(), tx, f.scope(), cursor, strconv.FormatInt(f.event.Sequence, 10)); e != nil {
			t.Fatal(e)
		}
		if tx.Rollback() != nil {
			t.Fatal("actual rollback missing")
		}
		var count int
		if f.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.policy.Metadata.Namespace).Scan(&count) != nil || count != 0 {
			t.Fatal("partial enqueue survived")
		}
		after, e := repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
		if e != nil || after != cursor {
			t.Fatal("rolled back cursor survived")
		}
		for _, query := range []string{`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, `SELECT count(*) FROM public.workflow_runs WHERE workflow_namespace=$1 AND metadata->>'triggered_by'='capacity_demand'`} {
			if f.db.QueryRow(query, f.policy.Metadata.Namespace).Scan(&count) != nil || count != 0 {
				t.Fatal("rolled back original wake or run survived")
			}
		}
		f.queued(t)
	})
	t.Run("fresh_dimension_survives_other_dimension_hold", func(t *testing.T) {
		for _, mode := range []string{"expired", "revoked", "saturated", "inactive"} {
			t.Run(mode, func(t *testing.T) {
				a, b := newDemandFixtureWithEvent(t, false), newDemandFixtureWithEvent(t, false)
				p := b.spec
				binding := *p.ControllerBinding
				binding.MachinePrincipalID = "dispatch-b"
				p.ControllerBinding = &binding
				b.policy, b.spec = b.create("capacity_policy", "pods", p), p
				allow := b.allow
				allow.Bindings = append([]model.RBACBinding(nil), allow.Bindings...)
				allow.Bindings[0].Subjects = []model.RBACSubject{{Type: "service", ID: "dispatch-b"}}
				b.create("rbac", "dispatch", allow)
				// Prove refusal precedes B in the actual policy ordering, rather
				// than benefiting from random UUIDs that happened to admit B first.
				if a.policy.ID.String() > b.policy.ID.String() {
					a, b = b, a
				}
				var inventory []json.RawMessage
				for _, f := range []demandFixture{a, b} {
					var item []json.RawMessage
					if json.Unmarshal([]byte(testWorkflowMachinePrincipalsJSON(t, "dimension-"+f.spec.ControllerBinding.MachinePrincipalID, f.spec.ControllerBinding.MachinePrincipalID, machineWorkflowRef{Namespace: f.workflow.Metadata.Namespace, Name: f.workflow.Metadata.Name})), &item) != nil || len(item) != 1 {
						t.Fatal("original separate operator inventory unavailable")
					}
					inventory = append(inventory, item[0])
				}
				raw, err := json.Marshal(inventory)
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv(workflowMachinePrincipalsEnv, string(raw))
				_, err = New("dimension-isolation-ci", a.db, a.broker, zap.NewNop(), WithCapacityDispatchServiceReceiver(func(s *CapacityDispatchService) { a.service = s }), func(s *Server) { a.server = s })
				if err != nil {
					t.Fatal("actual separate loaded principals refused", err)
				}
				a.event = a.publishOriginal(t)
				wantA := 0
				switch mode {
				case "expired":
					if _, err = a.db.Exec(`UPDATE public.event_log SET emitted_at=clock_timestamp()-interval '1 hour' WHERE event_id=$1`, a.event.EventID); err != nil {
						t.Fatal(err)
					}
				case "revoked":
					for i := range a.server.workflowRunAuthConfig().principals {
						if a.server.workflowRunAuthConfig().principals[i].PrincipalID == a.spec.ControllerBinding.MachinePrincipalID {
							a.server.workflowRunAuthConfig().principals[i].Status = "revoked"
						}
					}
				case "saturated":
					for i := 0; i < repository.MaxCapacityDispatchPendingWakes; i++ {
						event := a.event
						if i > 0 {
							event = a.publishOriginal(t)
						}
						if err = a.service.admitDemand(t.Context(), capacityDemandPolicy{a.policy, a.spec}, a.scope(), event); err != nil {
							t.Fatal("original A wake setup failed", err)
						}
					}
					a.event = a.publishOriginal(t)
					wantA = repository.MaxCapacityDispatchPendingWakes
				case "inactive":
					if _, err = a.db.Exec(`UPDATE public.manifests SET active=false WHERE id=$1`, a.policy.ID); err != nil {
						t.Fatal(err)
					}
				}
				b.event = b.publishOriginal(t)
				if a.event.Sequence >= b.event.Sequence {
					t.Fatal("native original A refusal must precede fresh B event")
				}
				err = a.service.runDemandPass(t.Context())
				if mode != "expired" && err == nil {
					t.Fatal("A original refusal cause was discarded")
				}
				if mode == "saturated" && !errors.Is(err, repository.ErrCapacityDispatchSaturated) {
					t.Fatal("original A saturation cause erased")
				}
				var n int
				if b.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1 AND source_tick=$2`, b.policy.Metadata.Namespace, "event:"+b.event.EventID.String()).Scan(&n) != nil || n != 1 {
					t.Fatal("fresh original B was blocked by A")
				}
				if a.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, a.policy.Metadata.Namespace).Scan(&n) != nil || n != wantA {
					t.Fatal("refused A was admitted or original wakes changed")
				}
				if b.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1 AND started_at IS NOT NULL`, b.policy.Metadata.Namespace).Scan(&n) != nil || n != 0 {
					t.Fatal("demand started B or promoted native capacity")
				}
				if err = a.service.runDemandPass(t.Context()); mode == "expired" && err != nil {
					t.Fatal(err)
				}
				if b.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, b.policy.Metadata.Namespace).Scan(&n) != nil || n != 1 {
					t.Fatal("B replayed across A HOLD")
				}
			})
		}
	})
	t.Run("lower_sequence_late_original_commit_remains_eligible", func(t *testing.T) {
		f := newDemandFixture(t)
		first := f.queued(t)
		response, runID := f.completeOriginal(t)
		original, err := pq.NewConnector(os.Getenv("DB_URL"))
		if err != nil {
			t.Fatal(err)
		}
		connector := &demandAckConnector{Connector: original, heldRunID: runID.String(), entered: make(chan struct{}), release: make(chan struct{})}
		pool := sql.OpenDB(connector)
		joined := make(chan struct{})
		var release sync.Once
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(func() {
			release.Do(func() { close(connector.release) })
			cancel()
			<-joined
			if err := pool.Close(); err != nil {
				t.Error("actual late-emitter pool Close failed")
			}
		})
		go func() {
			defer close(joined)
			messagecontroller.EmitScheduledWorkflowRunCompletedEvent(ctx, pool, zap.NewNop(), response, runID)
		}()
		select {
		case <-connector.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("original scheduled-emitter Commit was not entered")
		}
		var invisible int
		if f.db.QueryRow(`SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, runID.String()).Scan(&invisible) != nil || invisible != 0 {
			t.Fatal("N1 was already committed before held native Commit")
		}
		n2 := f.publishOriginal(t)
		if f.queued(t).JobID != first.JobID {
			t.Fatal("N2 replaced original active job")
		}
		cursor, err := repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
		if err != nil || cursor != strconv.FormatInt(n2.Sequence, 10) {
			t.Fatal("N2 native admission not independently retained")
		}
		release.Do(func() { close(connector.release) })
		<-joined
		var n1ID uuid.UUID
		if f.db.QueryRow(`SELECT event_id FROM public.event_log WHERE idempotency_key=$1`, runID.String()).Scan(&n1ID) != nil {
			t.Fatal("original N1 actual Commit not observed")
		}
		n1, err := repository.ReadCapacityDemandEvent(t.Context(), f.db, n1ID)
		if err != nil || n1.Sequence >= n2.Sequence || n1.RunID != runID {
			t.Fatal("native lower-sequence late-COMMIT lineage not established")
		}
		after := f.queued(t)
		if after.JobID != first.JobID || after.RunID != first.RunID || after.PendingWakeCount != 3 {
			t.Fatal("lower-sequence original completion lost or replaced original IDs")
		}
		cursor, err = repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
		if err != nil || cursor != strconv.FormatInt(n1.Sequence, 10) {
			t.Fatal("diagnostic cursor cannot record original late admission")
		}
		if f.queued(t).PendingWakeCount != 3 {
			t.Fatal("permanent wake failed native dedup of N1")
		}
	})
	t.Run("broker_outage_retains_original", func(t *testing.T) {
		f := newDemandFixture(t)
		if f.broker.Close() != nil {
			t.Fatal("original broker Close missing")
		}
		job := f.queued(t)
		ran, e := f.service.RunOne(t.Context(), job.Realm, job.Environment)
		if ran || e == nil {
			t.Fatal("broker loss started work")
		}
		out, e := repository.ReadCapacityDispatchJob(t.Context(), f.db, job.JobID)
		if e != nil || out.StartedAt != nil {
			t.Fatal("broker loss consumed original")
		}
		live, e := amqp.Dial(os.Getenv("CAPACITY_DISPATCH_BROKER_URL"))
		if e != nil {
			t.Fatal("original broker recovery unresolved")
		}
		defer func() {
			if live.Close() != nil {
				t.Error("recovered broker Close unresolved")
			}
		}()
		f.server.rabbitmq = live
		ran, e = f.service.RunOne(t.Context(), job.Realm, job.Environment)
		out, readErr := repository.ReadCapacityDispatchJob(t.Context(), f.db, job.JobID)
		if !ran || e == nil || readErr != nil || out.JobID != job.JobID || out.RunID != job.RunID || out.StartedAt == nil || out.ReturnedAt == nil {
			t.Fatal("recovery replaced original or omitted actual refused call/return")
		}
	})
	t.Run("coalesce_saturation_retains_event", func(t *testing.T) {
		f := newDemandFixture(t)
		first := f.queued(t)
		for i := 1; i < 32; i++ {
			f.publishOriginal(t)
			if f.queued(t).JobID != first.JobID {
				t.Fatal("wake replaced original")
			}
		}
		last := f.publishOriginal(t)
		if !errors.Is(f.service.runDemandPass(t.Context()), repository.ErrCapacityDispatchSaturated) {
			t.Fatal("saturation did not refuse")
		}
		cursor, e := repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
		if e != nil || cursor == strconv.FormatInt(last.Sequence, 10) {
			t.Fatal("saturated wake consumed")
		}
		var n int
		if f.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1 AND source_tick=$2`, first.Realm, "event:"+last.EventID.String()).Scan(&n) != nil || n != 0 {
			t.Fatal("saturation silently consumed original event")
		}
		retained, err := repository.ReadCapacityDispatchJob(t.Context(), f.db, first.JobID)
		if err != nil || retained.RunID != first.RunID || retained.PendingWakeCount != repository.MaxCapacityDispatchPendingWakes {
			t.Fatal("saturation changed original active identity or bounded journal")
		}
	})
	t.Run("started_unknown_never_replay", func(t *testing.T) {
		f := newDemandFixture(t)
		job := f.queued(t)
		claim, e := repository.ClaimCapacityDispatch(t.Context(), f.db, job.Realm, job.Environment, uuid.New(), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = repository.StartCapacityDispatch(t.Context(), f.db, claim); e != nil {
			t.Fatal(e)
		}
		f.publishOriginal(t)
		if f.queued(t).JobID != job.JobID {
			t.Fatal("new demand released started original")
		}
		if ran, _ := f.service.RunOne(t.Context(), job.Realm, job.Environment); ran {
			t.Fatal("started invocation replayed")
		}
		// Explicit unknown is only a negative native fixture state. It supplies
		// no original invocation result, metric proof or capacity promotion.
		if _, e := f.db.Exec(`UPDATE public.capacity_dispatch_jobs SET state='unknown' WHERE id=$1 AND state='started'`, job.JobID); e != nil {
			t.Fatal("native unknown fixture unavailable")
		}
		f.publishOriginal(t)
		unknown := f.queued(t)
		if unknown.JobID != job.JobID || unknown.RunID != job.RunID || unknown.State != "unknown" || unknown.ReturnedAt != nil {
			t.Fatal("new demand invented an unknown return")
		}
		if ran, _ := f.service.RunOne(t.Context(), job.Realm, job.Environment); ran {
			t.Fatal("unknown invocation replayed")
		}
	})
	t.Run("binding_principal_and_rbac_refusals", func(t *testing.T) {
		f := newDemandFixture(t)
		inventory := f.server.workflowRunAuthConfig()
		original := inventory.principals[0]
		for _, mode := range []string{"missing", "revoked", "expired", "rotated", "inventory_error", "rbac", "binding"} {
			inventory.principals = []workflowMachinePrincipal{original}
			inventory.err = nil
			switch mode {
			case "missing":
				inventory.principals = nil
			case "revoked":
				inventory.principals[0].Status = "revoked"
			case "expired":
				inventory.principals[0].ExpiresAt = time.Now().Add(-time.Second)
			case "rotated":
				// A queued original envelope cannot adopt a new rotation.
				prepared, err := f.service.prepareDemand(t.Context(), capacityDemandPolicy{f.policy, f.spec}, f.event)
				if err != nil {
					t.Fatal(err)
				}
				inventory.principals[0].RotationID = "new-operator-rotation"
				if _, _, err = f.service.authorizeEnvelope(t.Context(), prepared.envelope); err == nil {
					t.Fatal("new rotation adopted original envelope")
				}
				inventory.principals = nil // current admission must also refuse
			case "inventory_error":
				inventory.err = errors.New("private inventory refusal")
			case "rbac":
				deny := f.allow
				deny.Roles = []model.RBACRole{{Name: "controller", Rules: []model.RBACRule{{Effect: "deny", Resources: []string{"workflow:" + f.workflow.Metadata.Namespace + ":pressure"}, Actions: []string{"run"}}}}}
				f.create("rbac", "dispatch", deny)
			case "binding":
				p := f.spec
				b := *p.ControllerBinding
				b.MachinePrincipalID = "unloaded-operator"
				p.ControllerBinding = &b
				f.create("capacity_policy", "pods", p)
			}
			if f.service.runDemandPass(t.Context()) == nil {
				t.Fatal("current delegation refusal missing", mode)
			}
			var n int
			if f.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_jobs WHERE realm=$1`, f.policy.Metadata.Namespace).Scan(&n) != nil || n != 0 {
				t.Fatal("refused current delegation created work", mode)
			}
			cursor, err := repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
			if err != nil || cursor == strconv.FormatInt(f.event.Sequence, 10) {
				t.Fatal("refused current delegation consumed demand", mode)
			}
			f.create("rbac", "dispatch", f.allow)
			f.policy = f.create("capacity_policy", "pods", f.spec)
		}
		inventory.principals, inventory.err = []workflowMachinePrincipal{original}, nil
		f.queued(t)
	})
	t.Run("caller_payload_cannot_supply_authority", func(t *testing.T) {
		f := newDemandFixture(t)
		var raw []byte
		if f.db.QueryRow(`SELECT payload::text FROM public.event_log WHERE event_id=$1`, f.event.EventID).Scan(&raw) != nil {
			t.Fatal("original exact payload unavailable")
		}
		caller := eventPublishRequest{Type: "workflow.run.completed", AggregateType: "workflow_run", AggregateID: f.event.RunID.String(), Payload: raw, Idempotency: f.event.RunID.String(), Metadata: map[string]any{"idempotency_key": f.event.RunID.String(), "healthy": true, "url": "https://caller.invalid", "token": "caller"}}
		req, e := buildEmitEventRequestFromGeneric(caller)
		if e != nil || req.IdempotencyKey != "" {
			t.Fatal("generic copied private SQL key")
		}
		wire, e := json.Marshal(caller)
		if e != nil {
			t.Fatal("caller fixture malformed")
		}
		response := httptest.NewRecorder()
		f.server.handleEventPublish(response, httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(wire)).WithContext(t.Context()))
		var reply struct {
			EventID uuid.UUID `json:"event_id"`
		}
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &reply) != nil || reply.EventID == uuid.Nil {
			t.Fatal("original generic development HTTP path did not actually return")
		}
		var key sql.NullString
		if f.db.QueryRow(`SELECT idempotency_key FROM public.event_log WHERE event_id=$1`, reply.EventID).Scan(&key) != nil || key.Valid {
			t.Fatal("actual generic publication furnished private SQL lineage")
		}
		if _, e = repository.ReadCapacityDemandEvent(t.Context(), f.db, reply.EventID); e == nil {
			t.Fatal("payload resemblance supplied lineage")
		}
		job := f.queued(t)
		encoded, _ := json.Marshal(job.Inputs)
		if strings.Contains(string(encoded), "caller") || strings.Contains(string(encoded), "healthy") {
			t.Fatal("payload leaked into inputs")
		}
	})
	t.Run("wrong_lineage_and_source_pins_refuse", func(t *testing.T) {
		f := newDemandFixture(t)
		if _, e := repository.ReadCapacityDemandEvent(t.Context(), f.db, uuid.New()); e == nil {
			t.Fatal("missing original accepted")
		}
		// Actual native invalid rows, restored after each refusal. A NULL actor
		// alone cannot admit a missing private key, foreign shape or absent run.
		for _, mutation := range []string{
			`UPDATE public.event_log SET idempotency_key=NULL WHERE event_id=$1`,
			`UPDATE public.event_log SET actor_type='service',actor_id='caller' WHERE event_id=$1`,
			`UPDATE public.event_log SET actor_context='{"caller":true}'::jsonb WHERE event_id=$1`,
			`UPDATE public.event_log SET metadata='{"healthy":true}'::jsonb WHERE event_id=$1`,
			`UPDATE public.event_log SET schema_version='foreign' WHERE event_id=$1`,
			`UPDATE public.event_log SET aggregate_type='foreign' WHERE event_id=$1`,
		} {
			tx, err := f.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.ExecContext(t.Context(), mutation, f.event.EventID); err != nil {
				_ = tx.Rollback()
				t.Fatal("native invalid fixture unresolved")
			}
			// The fixed reader owns a DB, so expose only this test transaction's
			// actual committed invalid row, then restore the original full columns.
			if tx.Commit() != nil {
				t.Fatal("native invalid fixture did not commit")
			}
			_, readErr := repository.ReadCapacityDemandEvent(t.Context(), f.db, f.event.EventID)
			_, restoreErr := f.db.Exec(`UPDATE public.event_log SET idempotency_key=$2,actor_type=NULL,actor_id=NULL,actor_context=NULL,metadata=NULL,schema_version='v1',aggregate_type='workflow_run' WHERE event_id=$1`, f.event.EventID, f.event.RunID.String())
			if restoreErr != nil || readErr == nil {
				t.Fatal("invalid native lineage accepted or restoration unresolved")
			}
		}
		for _, missing := range []struct{ ctx context.Context }{{ctx: nil}} {
			if _, err := repository.ReadCapacityDemandEvent(missing.ctx, f.db, f.event.EventID); err == nil {
				t.Fatal("missing original context accepted")
			}
		}
		p := f.spec
		b := *p.ControllerBinding
		d := *b.DemandSource
		d.Checksum = strings.Repeat("f", 64)
		b.DemandSource = &d
		p.ControllerBinding = &b
		f.policy, f.spec = f.create("capacity_policy", "pods", p), p
		if f.service.runDemandPass(t.Context()) == nil {
			t.Fatal("changed source pin accepted")
		}
	})
	t.Run("stored_version_response_and_manifest_identity_refuse_drift", func(t *testing.T) {
		f := newDemandFixture(t)
		var result, metadata, payload []byte
		var version int
		if err := f.db.QueryRowContext(t.Context(), `SELECT r.workflow_version,r.result::text,r.metadata::text,e.payload::text FROM public.workflow_runs r JOIN public.event_log e ON e.aggregate_id=r.id::text WHERE e.event_id=$1`, f.event.EventID).Scan(&version, &result, &metadata, &payload); err != nil || version != f.source.Version {
			t.Fatal("original exact version fixture unavailable", err)
		}
		for _, mutation := range []struct {
			name, query string
			args        []any
		}{
			{"sql_version_mismatch", `UPDATE public.workflow_runs SET workflow_version=$2 WHERE id=$1`, []any{f.event.RunID, version + 1}},
			{"sql_version_zero", `UPDATE public.workflow_runs SET workflow_version=0 WHERE id=$1`, []any{f.event.RunID}},
			{"sql_version_negative", `UPDATE public.workflow_runs SET workflow_version=-1 WHERE id=$1`, []any{f.event.RunID}},
			{"response_version_zero", `UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,version}','0'::jsonb) WHERE id=$1`, []any{f.event.RunID}},
			{"response_version_foreign", `UPDATE public.workflow_runs SET result=jsonb_set(result,'{workflow,version}',to_jsonb($2::integer)) WHERE id=$1`, []any{f.event.RunID, version + 1}},
			{"metadata_manifest_foreign", `UPDATE public.workflow_runs SET metadata=jsonb_set(metadata,'{manifest_id}',to_jsonb($2::text)) WHERE id=$1`, []any{f.event.RunID, uuid.NewString()}},
			{"payload_version_foreign", `UPDATE public.event_log SET payload=jsonb_set(payload,'{workflow_ref,version}',to_jsonb($2::integer)) WHERE event_id=$1`, []any{f.event.EventID, version + 1}},
		} {
			t.Run(mutation.name, func(t *testing.T) {
				changed, err := f.db.ExecContext(t.Context(), mutation.query, mutation.args...)
				if err != nil {
					t.Fatal("native version mutation unresolved", err)
				}
				if count, err := changed.RowsAffected(); err != nil || count != 1 {
					t.Fatal("native original row mutation unknown", err)
				}
				t.Cleanup(func() {
					if _, err := f.db.ExecContext(context.Background(), `UPDATE public.workflow_runs SET workflow_version=$2,result=$3::jsonb,metadata=$4::jsonb WHERE id=$1`, f.event.RunID, version, string(result), string(metadata)); err != nil {
						t.Error("original run restoration unresolved", err)
					}
					if _, err := f.db.ExecContext(context.Background(), `UPDATE public.event_log SET payload=$2::jsonb WHERE event_id=$1`, f.event.EventID, string(payload)); err != nil {
						t.Error("original completion restoration unresolved", err)
					}
				})
				if _, err := repository.ReadCapacityDemandEvent(t.Context(), f.db, f.event.EventID); err == nil {
					t.Fatal("supplied native version/identity drift accepted")
				}
				if err := f.service.runDemandPass(t.Context()); err == nil {
					t.Fatal("drifted response became a demand admission")
				}
				var wakes int
				if f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, f.policy.Metadata.Namespace).Scan(&wakes) != nil || wakes != 0 {
					t.Fatal("refused version consumed original demand")
				}
			})
		}
		if original, err := repository.ReadCapacityDemandEvent(t.Context(), f.db, f.event.EventID); err != nil || original.SHA256 != f.event.SHA256 {
			t.Fatal("original version/body restoration changed source", err)
		}
	})
	t.Run("stale_or_unknown_demand_is_hold", func(t *testing.T) {
		f := newDemandFixture(t)
		if _, err := f.db.Exec(`UPDATE public.event_log SET emitted_at=clock_timestamp()-interval '1 hour' WHERE event_id=$1`, f.event.EventID); err != nil {
			t.Fatal("native stale fixture unresolved")
		}
		if err := f.service.runDemandPass(t.Context()); err != nil {
			t.Fatal("proven expired event blocked a scan", err)
		}
		var wakes int
		if f.db.QueryRow(`SELECT count(*) FROM public.capacity_dispatch_wakes WHERE realm=$1`, f.policy.Metadata.Namespace).Scan(&wakes) != nil || wakes != 0 {
			t.Fatal("expired event became an admitted wake")
		}
		cursor, err := repository.ReadCapacityDemandCursor(t.Context(), f.db, f.scope())
		if err != nil || cursor == strconv.FormatInt(f.event.Sequence, 10) {
			t.Fatal("stale demand consumed")
		}
		ctx, cancel := context.WithCancelCause(t.Context())
		cause := fmt.Errorf("private source cause")
		cancel(cause)
		if e := f.service.runDemandPass(ctx); !errors.Is(e, cause) {
			t.Fatal("original cancellation cause lost")
		}
	})
	t.Run("native_bound_refusal_is_not_capacity", func(t *testing.T) {
		f := newDemandFixture(t)
		job := f.queued(t)
		_, e := f.service.RunOne(t.Context(), job.Realm, job.Environment)
		if e == nil {
			t.Fatal("unobserved HPA/metrics became capacity")
		}
		record, e := repository.GetWorkflowRun(t.Context(), f.db, job.RunID)
		if e != nil || record.Status != "failed" || record.Result == nil || record.Result.Status != "failed" {
			t.Fatal("original typed refusal hidden")
		}
	})
	t.Run("cron_wire_and_private_cursor_independent", func(t *testing.T) {
		f := newDemandFixture(t)
		cron := f.prepare(t)
		if cron.envelope.Metadata["triggered_by"] != "workflow_scheduler" || strings.HasPrefix(cron.envelope.SourceTick, "event:") {
			t.Fatal("legacy cron origin changed")
		}
		var before string
		if f.db.QueryRow(`SELECT last_cursor FROM public.workflow_event_trigger_state WHERE id='workflow_event_trigger_loop'`).Scan(&before) != nil {
			t.Fatal("original generic cursor missing before demand")
		}
		f.queued(t)
		var generic string
		if f.db.QueryRow(`SELECT last_cursor FROM public.workflow_event_trigger_state WHERE id='workflow_event_trigger_loop'`).Scan(&generic) != nil {
			t.Fatal("generic cursor missing")
		}
		if generic != before {
			t.Fatal("private demand consumed generic cursor")
		}
		t.Setenv(CapacityDispatchEnabledEnv, "false")
		if e := f.service.RunPass(t.Context()); e != nil {
			t.Fatal("default-off worker changed")
		}
	})
}
