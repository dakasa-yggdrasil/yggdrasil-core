package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

// dbForTriggerTest opens a *sql.DB pointing at the integration Postgres or
// skips. Mirrors dbForEventTest in repository/event_test.go.
func dbForTriggerTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping workflow_event_triggers integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

// Use the real CI broker so brokerLive exercises its healthy connection branch.
// The dial deadline includes the AMQP handshake and every case owns its close.
func brokerForTriggerTest(t *testing.T) *amqp.Connection {
	t.Helper()
	url := os.Getenv("CAPACITY_DISPATCH_BROKER_URL")
	if url == "" {
		t.Fatal("actual CI RabbitMQ required by CAPACITY_DISPATCH_BROKER_URL")
	}
	conn, err := amqp.DialConfig(url, amqp.Config{Dial: amqp.DefaultDial(5 * time.Second)})
	if err != nil {
		t.Fatal("open actual workflow trigger broker", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !errors.Is(err, amqp.ErrClosed) {
			t.Error("close actual workflow trigger broker", err)
		}
	})
	return conn
}

// resetTriggerTestState removes only this fixture's original events, matched
// markers, runs and manifests. Foreign events and capacity-owned runs remain.
// Its singleton cursor row still seeds "" before the fixture positions its
// native baseline, so SaveWorkflowEventTriggerCursor finds a row to update.
func resetTriggerTestState(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`
		DELETE FROM public.event_log
		WHERE (
			type = 'manifest.created'
			AND aggregate_type = 'manifest'
			AND aggregate_id = '018f2b4a-1234-7abc-def0-eeeeeeeeeeee'
			AND payload->>'namespace' = 'test-event-trigger'
		) OR (
			type = 'workflow.event.matched'
			AND aggregate_type = 'workflow'
			AND payload->>'workflow_manifest_id' = aggregate_id
			AND aggregate_id IN (
				SELECT id::text FROM public.manifests
				WHERE kind = 'workflow' AND namespace = 'test-event-trigger'
			)
		)
	`); err != nil {
		t.Fatalf("delete fixture event_log: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.workflow_runs WHERE workflow_namespace = 'test-event-trigger'`); err != nil {
		t.Fatalf("delete fixture workflow_runs: %v", err)
	}
	if _, err := db.Exec(
		`DELETE FROM public.manifests WHERE kind = 'workflow' AND namespace = 'test-event-trigger'`,
	); err != nil {
		t.Fatalf("delete test workflow manifests: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO public.workflow_event_trigger_state (id, last_cursor)
		VALUES ('workflow_event_trigger_loop', '')
		ON CONFLICT (id) DO UPDATE SET last_cursor = EXCLUDED.last_cursor, updated_at = NOW()
	`); err != nil {
		t.Fatalf("seed workflow_event_trigger_state: %v", err)
	}
}

// insertEventTriggerWorkflow seeds an active workflow manifest in the
// integration DB with trigger.mode=event configured to match
// type=manifest.created. Returns the manifest id so tests can assert
// against the resulting workflow_run rows.
func insertEventTriggerWorkflow(
	t *testing.T,
	db *sql.DB,
	name string,
	enabled *bool,
	defaultInputs map[string]any,
) string {
	t.Helper()

	spec := model.WorkflowManifestSpec{
		Trigger: model.WorkflowTriggerSpec{
			Mode:    "event",
			Enabled: enabled,
			Event: &model.WorkflowEventTriggerSpec{
				Types:          []string{"manifest.created"},
				PayloadFilters: []model.WorkflowEventPayloadFilter{{Path: "namespace", Operator: "eq", Value: "test-event-trigger"}},
				DefaultInputs:  defaultInputs,
			},
		},
		Steps: []model.WorkflowStepSpec{{
			ID:  "ordinary",
			Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "assert"},
			With: map[string]any{
				"equal": []any{map[string]any{"name": "same", "actual": 1, "expected": 1}},
			},
		}},
	}
	if err := manifest.ValidateWorkflowSpec(spec); err != nil {
		t.Fatalf("validate ordinary reactive fixture: %v", err)
	}
	if httpapi.CapacityScheduleGraphRequiresOwner(spec) || len(spec.Steps) != 1 || manifest.NormalizeWorkflowStepOperation(spec.Steps[0]) != "assert" {
		t.Fatal("ordinary reactive fixture requires a single non-capacity assert step")
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	var id string
	if err := db.QueryRow(`
		INSERT INTO public.manifests
			(api_version, kind, namespace, name, version, active, spec, checksum)
		VALUES ('yggdrasil.io/v1alpha1', 'workflow', 'test-event-trigger', $1, 1, TRUE, $2::jsonb, $3)
		RETURNING id
	`, name, string(specJSON), "sha256:test-checksum-"+name).Scan(&id); err != nil {
		t.Fatalf("insert workflow manifest: %v", err)
	}
	return id
}

// emitMatchingEvent records the current native sequence before inserting this
// fixture's event and positions the original generic cursor at that baseline.
// It returns the EventID and baseline cursor so replay reads the same window.
// The payload remains whatever the test exposes under inputs.event.
func emitMatchingEvent(t *testing.T, db *sql.DB, payload map[string]any) (uuid.UUID, string) {
	t.Helper()
	var baselineSequence int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(sequence), 0) FROM public.event_log`).Scan(&baselineSequence); err != nil {
		t.Fatalf("read native event sequence baseline: %v", err)
	}
	// This is the native cursor format used by repository.encodePullCursor.
	baselineCursor := fmt.Sprintf("seq:%d", baselineSequence)
	if err := repository.SaveWorkflowEventTriggerCursor(context.Background(), db, baselineCursor); err != nil {
		t.Fatalf("position original cursor at native sequence baseline: %v", err)
	}
	if cursor, err := repository.GetWorkflowEventTriggerCursor(context.Background(), db); err != nil || cursor != baselineCursor {
		t.Fatalf("original cursor did not retain native sequence baseline: cursor=%q err=%v", cursor, err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	id, err := repository.EmitEvent(context.Background(), tx, model.EmitEventRequest{
		Type:          "manifest.created",
		SchemaVersion: "v1",
		AggregateType: "manifest",
		AggregateID:   "018f2b4a-1234-7abc-def0-eeeeeeeeeeee",
		Actor:         &model.EventActor{Type: "system", ID: "test"},
		Payload:       payload,
	})
	if err != nil {
		t.Fatalf("emit event: %v", err)
	}
	var emittedSequence int64
	if err := tx.QueryRow(`SELECT sequence FROM public.event_log WHERE event_id = $1`, id).Scan(&emittedSequence); err != nil || emittedSequence <= baselineSequence {
		t.Fatalf("original fixture event did not follow native sequence baseline: sequence=%d baseline=%d err=%v", emittedSequence, baselineSequence, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return id, baselineCursor
}

// recordingDispatcher is the workflowDispatcher fake the trigger-loop tests
// pass into runWorkflowEventTriggersPass. It captures the (runID, req) tuple
// instead of starting an execution goroutine. The original trigger still uses
// the live CI broker gate before calling this recorder.
type recordingDispatcher struct {
	calls []recordedDispatch
}

type recordedDispatch struct {
	RunID uuid.UUID
	Req   model.RunWorkflowRequest
}

func (r *recordingDispatcher) dispatch(_ context.Context, _ *sql.DB, _ *amqp.Connection, runID uuid.UUID, req model.RunWorkflowRequest) {
	r.calls = append(r.calls, recordedDispatch{RunID: runID, Req: req})
}

func validManifestCreatedPayloadForTrigger(name string) map[string]any {
	return map[string]any{
		"manifest_id": "018f2b4a-1234-7abc-def0-123456789abc",
		"kind":        "product",
		"namespace":   "test-event-trigger",
		"name":        name,
		"version":     1,
		"checksum":    "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
	}
}

func TestProcessMatchedTrigger_DispatchesWorkflowRun(t *testing.T) {
	db := dbForTriggerTest(t)
	defer db.Close()
	resetTriggerTestState(t, db)
	conn := brokerForTriggerTest(t)

	manifestID := insertEventTriggerWorkflow(t, db, "wf-dispatch", nil, nil)
	eventID, _ := emitMatchingEvent(t, db, validManifestCreatedPayloadForTrigger("wf-dispatch"))

	rec := &recordingDispatcher{}
	logger := zap.NewNop()
	runWorkflowEventTriggersPass(context.Background(), db, conn, logger, rec.dispatch)

	if len(rec.calls) != 1 {
		t.Fatalf("expected 1 dispatch, got %d", len(rec.calls))
	}
	got := rec.calls[0]
	if got.Req.Workflow.Name != "wf-dispatch" || got.Req.Workflow.Namespace != "test-event-trigger" {
		t.Errorf("workflow selector: got %+v, want namespace=test-event-trigger name=wf-dispatch", got.Req.Workflow)
	}
	if md, ok := got.Req.Metadata["matched_event_id"].(string); !ok || md != eventID.String() {
		t.Errorf("metadata.matched_event_id: got %v, want %s", got.Req.Metadata["matched_event_id"], eventID.String())
	}
	if got.Req.Metadata["triggered_by"] != "workflow_event_triggers" {
		t.Errorf("metadata.triggered_by: got %v, want %q", got.Req.Metadata["triggered_by"], "workflow_event_triggers")
	}

	// A pending workflow_runs row should land for the dispatched id.
	var status string
	if err := db.QueryRow(`SELECT status FROM public.workflow_runs WHERE id = $1`, got.RunID).Scan(&status); err != nil {
		t.Fatalf("query workflow_runs: %v", err)
	}
	if status != "pending" {
		t.Errorf("status: got %q, want %q", status, "pending")
	}

	// And exactly one workflow.event.matched event should be in the log,
	// keyed on the workflow manifest id and the matched event id.
	matched, err := repository.HasWorkflowEventMatched(context.Background(), db, manifestID, eventID.String())
	if err != nil {
		t.Fatalf("HasWorkflowEventMatched: %v", err)
	}
	if !matched {
		t.Errorf("expected workflow.event.matched record, got none")
	}
}

func TestProcessMatchedTrigger_IsIdempotent(t *testing.T) {
	db := dbForTriggerTest(t)
	defer db.Close()
	resetTriggerTestState(t, db)
	conn := brokerForTriggerTest(t)

	insertEventTriggerWorkflow(t, db, "wf-idempotent", nil, nil)
	_, baselineCursor := emitMatchingEvent(t, db, validManifestCreatedPayloadForTrigger("wf-idempotent"))

	rec := &recordingDispatcher{}
	logger := zap.NewNop()

	// First pass: matches, dispatches, advances cursor.
	runWorkflowEventTriggersPass(context.Background(), db, conn, logger, rec.dispatch)
	if len(rec.calls) != 1 {
		t.Fatalf("first pass: expected 1 dispatch, got %d", len(rec.calls))
	}

	// Reset the cursor so a second pass replays the same window. The
	// dedup check (HasWorkflowEventMatched) is what must keep us from
	// dispatching again.
	if _, err := db.Exec(`UPDATE public.workflow_event_trigger_state SET last_cursor = $1 WHERE id = 'workflow_event_trigger_loop'`, baselineCursor); err != nil {
		t.Fatalf("reset cursor: %v", err)
	}

	runWorkflowEventTriggersPass(context.Background(), db, conn, logger, rec.dispatch)
	if len(rec.calls) != 1 {
		t.Fatalf("second pass: expected dispatch count to stay at 1 (dedup), got %d", len(rec.calls))
	}

	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.workflow_runs WHERE workflow_namespace = 'test-event-trigger'`).Scan(&runCount); err != nil {
		t.Fatalf("count workflow_runs: %v", err)
	}
	if runCount != 1 {
		t.Errorf("workflow_runs count: got %d, want 1", runCount)
	}
}

func TestProcessMatchedTrigger_ExposesPayloadAsInputsEvent(t *testing.T) {
	db := dbForTriggerTest(t)
	defer db.Close()
	resetTriggerTestState(t, db)
	conn := brokerForTriggerTest(t)

	insertEventTriggerWorkflow(t, db, "wf-payload", nil, nil)
	payload := validManifestCreatedPayloadForTrigger("wf-payload")
	emitMatchingEvent(t, db, payload)

	rec := &recordingDispatcher{}
	logger := zap.NewNop()
	runWorkflowEventTriggersPass(context.Background(), db, conn, logger, rec.dispatch)

	if len(rec.calls) != 1 {
		t.Fatalf("expected 1 dispatch, got %d", len(rec.calls))
	}
	gotEvent, ok := rec.calls[0].Req.Inputs["event"].(map[string]any)
	if !ok {
		t.Fatalf("inputs.event missing or wrong type: %T", rec.calls[0].Req.Inputs["event"])
	}
	if gotEvent["name"] != "wf-payload" {
		t.Errorf("inputs.event.name: got %v, want %q", gotEvent["name"], "wf-payload")
	}
	if gotEvent["kind"] != "product" {
		t.Errorf("inputs.event.kind: got %v, want %q", gotEvent["kind"], "product")
	}
}

func TestProcessMatchedTrigger_DefaultInputsOverridePayload(t *testing.T) {
	db := dbForTriggerTest(t)
	defer db.Close()
	resetTriggerTestState(t, db)
	conn := brokerForTriggerTest(t)

	// DefaultInputs.event is intentionally a plain string; it should
	// override the payload-derived `event` map per spec ("DefaultInputs
	// wins on key conflicts").
	defaults := map[string]any{
		"event":         "pinned-by-operator",
		"extra_default": "always-here",
	}
	insertEventTriggerWorkflow(t, db, "wf-defaults", nil, defaults)
	emitMatchingEvent(t, db, validManifestCreatedPayloadForTrigger("wf-defaults"))

	rec := &recordingDispatcher{}
	logger := zap.NewNop()
	runWorkflowEventTriggersPass(context.Background(), db, conn, logger, rec.dispatch)

	if len(rec.calls) != 1 {
		t.Fatalf("expected 1 dispatch, got %d", len(rec.calls))
	}
	inputs := rec.calls[0].Req.Inputs
	if got := inputs["event"]; got != "pinned-by-operator" {
		t.Errorf("inputs.event: expected DefaultInputs to override, got %v", got)
	}
	if got := inputs["extra_default"]; got != "always-here" {
		t.Errorf("inputs.extra_default: got %v, want %q", got, "always-here")
	}
}

func TestProcessMatchedTrigger_DisabledTriggerSkipsDispatch(t *testing.T) {
	db := dbForTriggerTest(t)
	defer db.Close()
	resetTriggerTestState(t, db)

	disabled := false
	insertEventTriggerWorkflow(t, db, "wf-disabled", &disabled, nil)
	emitMatchingEvent(t, db, validManifestCreatedPayloadForTrigger("wf-disabled"))

	rec := &recordingDispatcher{}
	logger := zap.NewNop()
	runWorkflowEventTriggersPass(context.Background(), db, nil, logger, rec.dispatch)

	if len(rec.calls) != 0 {
		t.Fatalf("expected no dispatch for disabled trigger, got %d", len(rec.calls))
	}

	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.workflow_runs WHERE workflow_namespace = 'test-event-trigger'`).Scan(&runCount); err != nil {
		t.Fatalf("count workflow_runs: %v", err)
	}
	if runCount != 0 {
		t.Errorf("workflow_runs count: got %d, want 0", runCount)
	}
}
