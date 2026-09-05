package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("workflow_event_triggers", bootstrapWorkflowEventTriggers, 80)
}

// workflowDispatcher is the function the trigger loop calls to actually run a
// workflow asynchronously. Pulled out so tests can substitute a deterministic
// fake without spinning up a RabbitMQ connection.
type workflowDispatcher func(ctx context.Context, db *sql.DB, conn *amqp.Connection, runID uuid.UUID, req model.RunWorkflowRequest)

// bootstrapWorkflowEventTriggers starts a background loop that watches the
// event stream (Gap 1) for events matching event-trigger workflows, emits
// workflow.event.matched events on hits and dispatches the matching
// workflow asynchronously.
//
// Uses pg_try_advisory_lock so only one worker across the fleet runs the
// event loop at a time. Other workers skip the pass and try again next tick.
// On a leader drop (connection lost, process dies), Postgres releases the
// lock automatically and another worker takes over.
func bootstrapWorkflowEventTriggers(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	// RabbitMQ is required to actually dispatch workflows because
	// messagecontroller.RunWorkflow publishes step messages through it.
	// When BROKER_URL is unset (slim/dev mode) the trigger loop still
	// runs and emits workflow.event.matched, but skips the dispatch and
	// logs the skip. Returning an error here would block the addon
	// chain on a soft dependency.
	conn, _ := RabbitMQ(app)

	logger, _ := Logger(app)
	interval := workflowEventTriggersInterval()

	stop := make(chan struct{})
	go runWorkflowEventTriggersLoop(ctx, db, conn, logger, dispatchAsyncWorkflowRunBackground, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runWorkflowEventTriggersLoop(
	ctx context.Context,
	db *sql.DB,
	conn *amqp.Connection,
	logger *zap.Logger,
	dispatch workflowDispatcher,
	interval time.Duration,
	stop <-chan struct{},
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			runWorkflowEventTriggersPass(ctx, db, conn, logger, dispatch)
		}
	}
}

// runWorkflowEventTriggersPass executes one pass. Acquires leadership lock,
// pulls a batch of events from the event stream, matches them against
// active event-trigger workflows, emits workflow.event.matched and
// dispatches the workflow run asynchronously.
func runWorkflowEventTriggersPass(
	ctx context.Context,
	db *sql.DB,
	conn *amqp.Connection,
	logger *zap.Logger,
	dispatch workflowDispatcher,
) {
	leader, err := repository.TryAcquireWorkflowEventTriggerLeadership(ctx, db)
	if err != nil {
		if logger != nil {
			logger.Warn("workflow_event_triggers: acquire leader lock failed", zap.Error(err))
		}
		return
	}
	if !leader {
		// Another worker is the leader; skip this pass.
		return
	}
	defer func() {
		_ = repository.ReleaseWorkflowEventTriggerLeadership(ctx, db)
	}()

	// Load the event-trigger workflows once per pass.
	triggers, err := loadEventTriggerWorkflows(ctx, db)
	if err != nil {
		if logger != nil {
			logger.Warn("workflow_event_triggers: load triggers failed", zap.Error(err))
		}
		return
	}
	if len(triggers) == 0 {
		return
	}

	// Get the cursor we last processed.
	cursor, err := repository.GetWorkflowEventTriggerCursor(ctx, db)
	if err != nil {
		if logger != nil {
			logger.Warn("workflow_event_triggers: get cursor failed", zap.Error(err))
		}
		return
	}

	// Pull a batch of events.
	resp, err := repository.PullEvents(ctx, db, model.PullEventsRequest{
		Cursor: cursor,
		Limit:  100,
	})
	if err != nil {
		if logger != nil {
			logger.Warn("workflow_event_triggers: pull events failed", zap.Error(err))
		}
		return
	}
	if len(resp.Events) == 0 {
		return
	}

	// Match each event against each trigger; on hit, emit
	// workflow.event.matched (which doubles as the dedup key) and
	// dispatch the workflow asynchronously.
	for _, event := range resp.Events {
		for _, trigger := range triggers {
			if !eventMatchesTrigger(event, trigger) {
				continue
			}
			if err := processMatchedTrigger(ctx, db, conn, logger, dispatch, trigger, event); err != nil {
				if logger != nil {
					logger.Warn("workflow_event_triggers: process match failed",
						zap.String("workflow_manifest_id", trigger.manifestID),
						zap.String("event_id", event.EventID.String()),
						zap.Error(err))
				}
			}
		}
	}

	// Advance cursor even if no matches fired — prevents re-processing.
	if err := repository.SaveWorkflowEventTriggerCursor(ctx, db, resp.NextCursor); err != nil {
		if logger != nil {
			logger.Warn("workflow_event_triggers: save cursor failed", zap.Error(err))
		}
	}
}

// eventTriggerWorkflow carries everything the trigger loop needs to dispatch
// a run when a match fires: manifest identity (for the run selector + dedup
// key) plus the parsed trigger spec (for filters + default inputs).
type eventTriggerWorkflow struct {
	manifestID string
	namespace  string
	name       string
	trigger    *model.WorkflowEventTriggerSpec
}

func loadEventTriggerWorkflows(ctx context.Context, db *sql.DB) ([]eventTriggerWorkflow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, namespace, name, spec
		FROM public.manifests
		WHERE kind = 'workflow'
		  AND active = TRUE
		  AND spec->'trigger'->>'mode' = 'event'
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var triggers []eventTriggerWorkflow
	for rows.Next() {
		var (
			id        string
			namespace string
			name      string
			spec      []byte
		)
		if err := rows.Scan(&id, &namespace, &name, &spec); err != nil {
			return nil, err
		}

		var wfSpec model.WorkflowManifestSpec
		if err := json.Unmarshal(spec, &wfSpec); err != nil {
			continue
		}
		if wfSpec.Trigger.Event == nil {
			continue
		}
		enabled := true
		if wfSpec.Trigger.Enabled != nil {
			enabled = *wfSpec.Trigger.Enabled
		}
		if !enabled {
			continue
		}

		triggers = append(triggers, eventTriggerWorkflow{
			manifestID: id,
			namespace:  namespace,
			name:       name,
			trigger:    wfSpec.Trigger.Event,
		})
	}
	return triggers, rows.Err()
}

// eventMatchesTrigger returns true if the event satisfies all conditions of
// an event trigger: type pattern match + (optional) aggregate filter +
// (optional) payload filters.
func eventMatchesTrigger(event model.Event, trigger eventTriggerWorkflow) bool {
	// 1. Type pattern match (wildcards via path.Match)
	typeMatches := false
	for _, pattern := range trigger.trigger.Types {
		matched, err := path.Match(pattern, event.Type)
		if err == nil && matched {
			typeMatches = true
			break
		}
	}
	if !typeMatches {
		return false
	}

	// 2. Aggregate filter
	if trigger.trigger.AggregateFilter != nil {
		if aggType := trigger.trigger.AggregateFilter.AggregateType; aggType != "" && event.AggregateType != aggType {
			return false
		}
		if namePattern := trigger.trigger.AggregateFilter.NamePattern; namePattern != "" {
			// Try to match against aggregate_id; future: also try payload.name
			matched, _ := path.Match(namePattern, event.AggregateID)
			if !matched {
				return false
			}
		}
	}

	// 3. Payload filters
	if len(trigger.trigger.PayloadFilters) > 0 {
		var payload map[string]interface{}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return false
		}
		for _, filter := range trigger.trigger.PayloadFilters {
			if !applyPayloadFilter(payload, filter) {
				return false
			}
		}
	}

	return true
}

// applyPayloadFilter evaluates a single payload filter against the parsed
// payload map. Uses dotted path lookup.
func applyPayloadFilter(payload map[string]interface{}, filter model.WorkflowEventPayloadFilter) bool {
	value := dottedPathLookup(payload, filter.Path)
	op := strings.ToLower(strings.TrimSpace(filter.Operator))

	switch op {
	case "eq":
		return fmt.Sprintf("%v", value) == fmt.Sprintf("%v", filter.Value)
	case "neq":
		return fmt.Sprintf("%v", value) != fmt.Sprintf("%v", filter.Value)
	case "in":
		return sliceContainsValue(filter.Value, value)
	case "not_in":
		return !sliceContainsValue(filter.Value, value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", value), fmt.Sprintf("%v", filter.Value))
	case "matches":
		pattern, ok := filter.Value.(string)
		if !ok {
			return false
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", value))
	}
	return false
}

// dottedPathLookup returns the value at a dotted path in a nested map.
// Returns nil if any intermediate key is missing.
func dottedPathLookup(obj map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = obj
	for _, part := range parts {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = m[part]
	}
	return current
}

// sliceContainsValue reports whether a slice-typed filter value contains
// the given item. The slice can be []interface{} or already a typed slice.
func sliceContainsValue(slice interface{}, item interface{}) bool {
	items, ok := slice.([]interface{})
	if !ok {
		return false
	}
	itemStr := fmt.Sprintf("%v", item)
	for _, i := range items {
		if fmt.Sprintf("%v", i) == itemStr {
			return true
		}
	}
	return false
}

// processMatchedTrigger closes the reactive loop for a single
// (event, trigger) pair: dedup, emit workflow.event.matched, then dispatch
// the workflow run asynchronously.
//
// Idempotency: the workflow.event.matched event itself is the dedup signal.
// Before doing anything, query event_log for an existing matched record
// keyed by (workflow_manifest_id=trigger.manifestID, payload.matched_event_id
// =event.EventID). If one exists this pair was already handled (probably by
// a previous leader-pass aborted between commit and cursor advance) and we
// skip both the emit and the dispatch.
//
// The matched event commits before the dispatch starts, so a crash between
// the two will dedup correctly the next time the loop comes around: we'll
// see the matched record exists and bail.
func processMatchedTrigger(
	ctx context.Context,
	db *sql.DB,
	conn *amqp.Connection,
	logger *zap.Logger,
	dispatch workflowDispatcher,
	trigger eventTriggerWorkflow,
	event model.Event,
) error {
	already, err := repository.HasWorkflowEventMatched(ctx, db, trigger.manifestID, event.EventID.String())
	if err != nil {
		return fmt.Errorf("dedup check: %w", err)
	}
	if already {
		if logger != nil {
			logger.Debug("workflow_event_triggers: skip duplicate match",
				zap.String("workflow_manifest_id", trigger.manifestID),
				zap.String("event_id", event.EventID.String()))
		}
		return nil
	}

	if err := emitWorkflowEventMatched(ctx, db, trigger, event); err != nil {
		return fmt.Errorf("emit workflow.event.matched: %w", err)
	}

	// RabbitMQ is required for actual dispatch (RunWorkflow publishes step
	// messages). When the broker is unavailable we still record the match
	// (workflow.event.matched committed above) so an operator can replay
	// later, but we do NOT dispatch — and we do NOT mark anything failed.
	//
	// brokerLive guards nil (boot-degraded typed-nil conn) AND closed
	// (runtime drop) in one check, so the dispatcher's bare goroutine never
	// receives a dead connection and never panics on conn.Channel(). This is
	// the canonical degrade-not-die gate for this loop.
	if !brokerLive(conn) {
		if logger != nil {
			logger.Warn("workflow_event_triggers: skip dispatch — rabbitmq connection unavailable",
				zap.String("workflow_manifest_id", trigger.manifestID),
				zap.String("event_id", event.EventID.String()))
		}
		return nil
	}

	runID := uuid.New()
	req := buildEventTriggerRunRequest(trigger, event)
	preparedReq, err := messagecontroller.PrepareAndInsertWorkflowRun(ctx, db, runID, req)
	if err != nil {
		return fmt.Errorf("prepare and insert workflow_run: %w", err)
	}
	req = preparedReq

	dispatch(ctx, db, conn, runID, req)
	return nil
}

// buildEventTriggerRunRequest produces the RunWorkflowRequest the dispatcher
// will execute. inputs.event exposes the raw event payload so workflow steps
// can reference {{ inputs.event.<field> }}; trigger.DefaultInputs are merged
// on top, deliberately winning on key conflicts so operators can override
// any payload-derived input by listing the same key in default_inputs.
func buildEventTriggerRunRequest(trigger eventTriggerWorkflow, event model.Event) model.RunWorkflowRequest {
	inputs := map[string]any{}

	// 1. Payload-derived input. Empty/non-object payload still gets the
	// `event` key (set to nil) so workflows referencing it don't panic
	// on a missing key — the template engine resolves to "" in that
	// case.
	if len(event.Payload) > 0 {
		var payloadMap map[string]any
		if err := json.Unmarshal(event.Payload, &payloadMap); err == nil {
			inputs["event"] = payloadMap
		} else {
			inputs["event"] = nil
		}
	} else {
		inputs["event"] = nil
	}

	// 2. DefaultInputs override. Last-write wins so operators can pin
	// a known value over a payload-derived one.
	for k, v := range trigger.trigger.DefaultInputs {
		inputs[k] = v
	}

	return model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{
			Namespace: trigger.namespace,
			Name:      trigger.name,
		},
		Inputs: inputs,
		Metadata: map[string]any{
			"triggered_by":       "workflow_event_triggers",
			"matched_event_id":   event.EventID.String(),
			"matched_event_type": event.Type,
		},
	}
}

// emitWorkflowEventMatched persists the workflow.event.matched record.
// This row doubles as the dedup signal (HasWorkflowEventMatched looks for
// it) so it MUST commit before the dispatch starts. Schema is registered
// in docs/contracts/events_validator.go so this no longer silently fails.
func emitWorkflowEventMatched(
	ctx context.Context,
	db *sql.DB,
	trigger eventTriggerWorkflow,
	event model.Event,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]interface{}{
		"workflow_manifest_id": trigger.manifestID,
		"matched_event_id":     event.EventID.String(),
		"matched_event_type":   event.Type,
		"matched_aggregate_id": event.AggregateID,
	}
	if len(trigger.trigger.DefaultInputs) > 0 {
		payload["default_inputs"] = trigger.trigger.DefaultInputs
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "workflow.event.matched",
		SchemaVersion: "v1",
		AggregateType: "workflow",
		AggregateID:   trigger.manifestID,
		Actor: &model.EventActor{
			Type: "system",
			ID:   "workflow_event_triggers",
		},
		Payload: payload,
	}); err != nil {
		return err
	}

	return tx.Commit()
}

// dispatchAsyncWorkflowRunBackground runs the workflow in a detached
// goroutine, mirroring controllers/httpapi.dispatchAsyncWorkflowRun. We
// can't call the httpapi version directly because that would cycle the
// controllers/httpapi → addons import, so the small body is duplicated
// here instead.
func dispatchAsyncWorkflowRunBackground(
	_ context.Context,
	db *sql.DB,
	conn *amqp.Connection,
	runID uuid.UUID,
	req model.RunWorkflowRequest,
) {
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		startedAt := time.Now().UTC()
		_ = repository.MarkWorkflowRunRunning(bg, db, runID, startedAt)

		response, runErr := messagecontroller.RunWorkflow(bg, conn, db, req)

		status := "succeeded"
		errMsg := ""
		var resultPayload any
		if runErr != nil {
			status = "failed"
			errMsg = runErr.Error()
		} else {
			resultPayload = response
			if strings.EqualFold(response.Status, "failed") {
				status = "failed"
				if response.Metadata != nil {
					if v, ok := response.Metadata["failed_step"].(string); ok && v != "" {
						errMsg = "step " + v + " failed"
					}
				}
			}
		}
		_ = repository.FinalizeWorkflowRun(bg, db, runID, status, resultPayload, errMsg, time.Now().UTC())
	}()
}

func workflowEventTriggersInterval() time.Duration {
	raw := os.Getenv("WORKFLOW_EVENT_TRIGGERS_INTERVAL_SECONDS")
	if raw == "" {
		return 5 * time.Second
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
