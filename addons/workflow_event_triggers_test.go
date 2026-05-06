package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	_ "github.com/lib/pq"

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

// resetTriggerTestState makes each test deterministic: empty event_log,
// empty workflow_runs, no scheduled trigger workflows lingering, and the
// cursor row reset to "" so the loop pulls from sequence 0. The state
// table seeds the singleton row up front so SaveWorkflowEventTriggerCursor
// (which UPDATEs) always finds a row to update.
func resetTriggerTestState(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`TRUNCATE TABLE public.event_log RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate event_log: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.workflow_runs`); err != nil {
		t.Fatalf("delete workflow_runs: %v", err)
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
				Types:         []string{"manifest.created"},
				DefaultInputs: defaultInputs,
			},
		},
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

// emitMatchingEvent inserts one manifest.created event into event_log,
// returning the EventID. The payload is whatever the test wants to expose
// to the workflow under inputs.event.
func emitMatchingEvent(t *testing.T, db *sql.DB, payload map[string]any) uuid.UUID {
	t.Helper()
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
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return id
}

// recordingDispatcher is the workflowDispatcher fake the trigger-loop tests
// pass into runWorkflowEventTriggersPass. It captures the (runID, req) tuple
// instead of actually starting a goroutine, so the test asserts deterministically
// on what would have been dispatched without any RabbitMQ involvement.
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

	manifestID := insertEventTriggerWorkflow(t, db, "wf-dispatch", nil, nil)
	eventID := emitMatchingEvent(t, db, validManifestCreatedPayloadForTrigger("wf-dispatch"))

	rec := &recordingDispatcher{}
	logger := zap.NewNop()
	runWorkflowEventTriggersPass(context.Background(), db, nil, logger, rec.dispatch)

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

	insertEventTriggerWorkflow(t, db, "wf-idempotent", nil, nil)
	emitMatchingEvent(t, db, validManifestCreatedPayloadForTrigger("wf-idempotent"))

	rec := &recordingDispatcher{}
	logger := zap.NewNop()

	// First pass: matches, dispatches, advances cursor.
	runWorkflowEventTriggersPass(context.Background(), db, nil, logger, rec.dispatch)
	if len(rec.calls) != 1 {
		t.Fatalf("first pass: expected 1 dispatch, got %d", len(rec.calls))
	}

	// Reset the cursor so a second pass replays the same window. The
	// dedup check (HasWorkflowEventMatched) is what must keep us from
	// dispatching again.
	if _, err := db.Exec(`UPDATE public.workflow_event_trigger_state SET last_cursor = '' WHERE id = 'workflow_event_trigger_loop'`); err != nil {
		t.Fatalf("reset cursor: %v", err)
	}

	runWorkflowEventTriggersPass(context.Background(), db, nil, logger, rec.dispatch)
	if len(rec.calls) != 1 {
		t.Fatalf("second pass: expected dispatch count to stay at 1 (dedup), got %d", len(rec.calls))
	}

	var runCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.workflow_runs`).Scan(&runCount); err != nil {
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

	insertEventTriggerWorkflow(t, db, "wf-payload", nil, nil)
	payload := validManifestCreatedPayloadForTrigger("wf-payload")
	emitMatchingEvent(t, db, payload)

	rec := &recordingDispatcher{}
	logger := zap.NewNop()
	runWorkflowEventTriggersPass(context.Background(), db, nil, logger, rec.dispatch)

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

	// DefaultInputs.event is intentionally a plain string; it should
	// override the payload-derived `event` map per spec ("DefaultInputs
	// wins on key conflicts").
	defaults := map[string]any{
		"event":          "pinned-by-operator",
		"extra_default":  "always-here",
	}
	insertEventTriggerWorkflow(t, db, "wf-defaults", nil, defaults)
	emitMatchingEvent(t, db, validManifestCreatedPayloadForTrigger("wf-defaults"))

	rec := &recordingDispatcher{}
	logger := zap.NewNop()
	runWorkflowEventTriggersPass(context.Background(), db, nil, logger, rec.dispatch)

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
	if err := db.QueryRow(`SELECT COUNT(*) FROM public.workflow_runs`).Scan(&runCount); err != nil {
		t.Fatalf("count workflow_runs: %v", err)
	}
	if runCount != 0 {
		t.Errorf("workflow_runs count: got %d, want 0", runCount)
	}
}
