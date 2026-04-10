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

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() {
	Register("workflow_event_triggers", bootstrapWorkflowEventTriggers, 80)
}

// bootstrapWorkflowEventTriggers starts a background loop that watches the
// event stream (Gap 1) for events matching event-trigger workflows and
// emits workflow.event.matched events when a match occurs.
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

	logger, _ := Logger(app)
	interval := workflowEventTriggersInterval()

	stop := make(chan struct{})
	go runWorkflowEventTriggersLoop(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runWorkflowEventTriggersLoop(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
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
			runWorkflowEventTriggersPass(ctx, db, logger)
		}
	}
}

// runWorkflowEventTriggersPass executes one pass. Acquires leadership lock,
// pulls a batch of events from the event stream, matches them against
// active event-trigger workflows, and emits workflow.event.matched for
// each match.
func runWorkflowEventTriggersPass(ctx context.Context, db *sql.DB, logger *zap.Logger) {
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

	// Match each event against each trigger and emit workflow.event.matched
	// events for hits.
	for _, event := range resp.Events {
		for _, trigger := range triggers {
			if !eventMatchesTrigger(event, trigger) {
				continue
			}
			if err := emitWorkflowEventMatched(ctx, db, logger, trigger, event); err != nil {
				if logger != nil {
					logger.Warn("workflow_event_triggers: emit match failed",
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

type eventTriggerWorkflow struct {
	manifestID string
	trigger    *model.WorkflowEventTriggerSpec
}

func loadEventTriggerWorkflows(ctx context.Context, db *sql.DB) ([]eventTriggerWorkflow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, spec
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
			id   string
			spec []byte
		)
		if err := rows.Scan(&id, &spec); err != nil {
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

// emitWorkflowEventMatched records a match in the event stream so the
// workflow run pipeline can consume it and actually dispatch the workflow.
func emitWorkflowEventMatched(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	trigger eventTriggerWorkflow,
	event model.Event,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

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
		// Schema for workflow.event.matched may not be registered yet.
		// Log and continue — the dispatch won't happen, but the loop
		// keeps advancing its cursor.
		if logger != nil {
			logger.Warn("workflow_event_triggers: emit failed",
				zap.String("manifest_id", trigger.manifestID),
				zap.Error(err))
		}
		return nil
	}

	return tx.Commit()
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
