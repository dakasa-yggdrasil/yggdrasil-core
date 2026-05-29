package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

func init() {
	Register("workflow_scheduler", bootstrapWorkflowScheduler, 70)
}

// bootstrapWorkflowScheduler starts a background loop that finds workflows
// with trigger.mode = "schedule", computes their next fire time from the
// cron expression, and — when the fire time has arrived — atomically records
// the fire event and emits a workflow dispatch event on the event stream.
//
// The actual dispatch is emitted as a "workflow.schedule.fired" event that
// the workflow run pipeline can subscribe to. This keeps the scheduler
// decoupled from the dispatch mechanics.
func bootstrapWorkflowScheduler(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	logger, _ := Logger(app)
	interval := workflowSchedulerInterval()

	// AMQP optional. When unset (slim/dev mode) the scheduler still records
	// fires and emits the event into event_log, but skips run dispatch —
	// runs in a slim core are operator-driven via POST /api/v1/workflow-runs.
	conn, _ := RabbitMQ(app)

	stop := make(chan struct{})
	go runWorkflowSchedulerLoop(ctx, db, conn, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runWorkflowSchedulerLoop(
	ctx context.Context,
	db *sql.DB,
	conn *amqp.Connection,
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
			runWorkflowSchedulerPass(ctx, db, conn, logger)
		}
	}
}

// runWorkflowSchedulerPass executes one pass of the scheduler. Exposed for
// deterministic testing.
func runWorkflowSchedulerPass(ctx context.Context, db *sql.DB, conn *amqp.Connection, logger *zap.Logger) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, spec
		FROM public.manifests
		WHERE kind = 'workflow'
		  AND active = TRUE
		  AND spec->'trigger'->>'mode' = 'schedule'
	`)
	if err != nil {
		if logger != nil {
			logger.Warn("workflow_scheduler: query active scheduled workflows failed", zap.Error(err))
		}
		return
	}
	defer rows.Close()

	type scheduledWorkflow struct {
		manifestID string
		schedule   *model.WorkflowScheduleTriggerSpec
		enabled    bool
	}

	var candidates []scheduledWorkflow
	for rows.Next() {
		var (
			id   string
			spec []byte
		)
		if err := rows.Scan(&id, &spec); err != nil {
			if logger != nil {
				logger.Warn("workflow_scheduler: scan failed", zap.Error(err))
			}
			continue
		}

		var wfSpec model.WorkflowManifestSpec
		if err := json.Unmarshal(spec, &wfSpec); err != nil {
			if logger != nil {
				logger.Warn("workflow_scheduler: parse spec failed",
					zap.String("manifest_id", id),
					zap.Error(err))
			}
			continue
		}

		if wfSpec.Trigger.Schedule == nil {
			continue
		}

		enabled := true
		if wfSpec.Trigger.Enabled != nil {
			enabled = *wfSpec.Trigger.Enabled
		}
		if !enabled {
			continue
		}

		candidates = append(candidates, scheduledWorkflow{
			manifestID: id,
			schedule:   wfSpec.Trigger.Schedule,
			enabled:    enabled,
		})
	}
	if err := rows.Err(); err != nil {
		if logger != nil {
			logger.Warn("workflow_scheduler: iterate failed", zap.Error(err))
		}
		return
	}

	now := time.Now().UTC()
	for _, wf := range candidates {
		if err := processScheduledWorkflow(ctx, db, conn, logger, wf.manifestID, wf.schedule, now); err != nil {
			if logger != nil {
				logger.Warn("workflow_scheduler: process failed",
					zap.String("manifest_id", wf.manifestID),
					zap.Error(err))
			}
		}
	}
}

// processScheduledWorkflow computes the next fire time for a scheduled
// workflow based on its cron expression and current state. If the next
// fire is due (<= now), records the fire and emits a workflow.schedule.fired
// event atomically.
func processScheduledWorkflow(
	ctx context.Context,
	db *sql.DB,
	conn *amqp.Connection,
	logger *zap.Logger,
	manifestID string,
	schedule *model.WorkflowScheduleTriggerSpec,
	now time.Time,
) error {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(schedule.CronExpression)
	if err != nil {
		return err
	}

	loc := time.UTC
	if tz := strings.TrimSpace(schedule.Timezone); tz != "" {
		if parsed, err := time.LoadLocation(tz); err == nil {
			loc = parsed
		}
	}

	// Load existing state to find last_fired_at
	state, err := repository.GetWorkflowScheduleState(ctx, db, manifestID)
	if err != nil {
		return err
	}

	// If never fired, use start_at (or a past baseline) so the very first
	// fire happens on the next pass instead of being indefinitely deferred.
	//
	// Previous logic used `now.Add(-1 * time.Second)` as the baseline, which
	// makes sched.Next() return a future tick (e.g. cron */5 at 14:23:01 →
	// next tick 14:25), and the `if nextFire.After(now) return nil` branch
	// then defers forever — every pass observes the same future tick. Result:
	// new scheduled workflows registered while the scheduler is already
	// running NEVER fire on their own; only those bootstrap'd with a state
	// row pre-populated (e.g. the legacy dakasa-health-probe) tick correctly.
	//
	// Walking the baseline back ~1h ensures sched.Next() finds a past tick
	// for any reasonable cron expression (sub-hourly: */5, */10, */15 — all
	// have at least one tick within an hour). The fire loop then catches up
	// one tick per scheduler pass; catchup_policy="skip" callers can rely on
	// the existing skip handling at the run-dispatch layer.
	lastFired := state.LastFiredAt
	if lastFired.IsZero() {
		if schedule.StartAt != "" {
			if t, err := time.Parse(time.RFC3339, schedule.StartAt); err == nil {
				lastFired = t
			}
		}
		if lastFired.IsZero() {
			lastFired = now.Add(-1 * time.Hour)
		}
	}

	nextFire := sched.Next(lastFired.In(loc))
	if nextFire.After(now) {
		// Not yet time
		return nil
	}

	// Respect end_at
	if schedule.EndAt != "" {
		if endAt, err := time.Parse(time.RFC3339, schedule.EndAt); err == nil && now.After(endAt) {
			return nil
		}
	}

	// Compute the fire time AFTER this one for the next state row.
	nextAfterFire := sched.Next(nextFire.In(loc))

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	won, err := repository.UpsertWorkflowScheduleState(ctx, tx, manifestID, nextFire, nextAfterFire)
	if err != nil {
		return err
	}
	if !won {
		// Another worker already fired this tick
		return nil
	}

	// Emit event that the workflow run machinery can subscribe to.
	payload := map[string]interface{}{
		"workflow_manifest_id": manifestID,
		"scheduled_for":        nextFire.Format(time.RFC3339),
		"cron_expression":      schedule.CronExpression,
	}
	if schedule.Timezone != "" {
		payload["timezone"] = schedule.Timezone
	}
	if len(schedule.DefaultInputs) > 0 {
		payload["default_inputs"] = schedule.DefaultInputs
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "workflow.schedule.fired",
		SchemaVersion: "v1",
		AggregateType: "workflow",
		AggregateID:   manifestID,
		Actor: &model.EventActor{
			Type: "system",
			ID:   "workflow_scheduler",
		},
		Payload: payload,
	}); err != nil {
		// Event emit failure (schema not registered, etc.) should not prevent
		// the state transition — the state record is the business record.
		if logger != nil {
			logger.Warn("workflow_scheduler: emit event failed",
				zap.String("manifest_id", manifestID),
				zap.Error(err))
		}
	}

	if logger != nil {
		logger.Info("workflow_scheduler: fired",
			zap.String("manifest_id", manifestID),
			zap.Time("scheduled_for", nextFire))
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Dispatch the workflow run asynchronously after the schedule_state
	// commit so the audit trail captures the fire even if dispatch fails.
	// Without this step the scheduler is purely passive — it records "this
	// cron tick elapsed" and emits an event into the log, but no consumer
	// materialises a workflow_run, leaving every scheduled workflow armed
	// but never triggered. Conn nil means slim/dev mode (no AMQP) — skip
	// dispatch silently; the operator can still POST runs explicitly.
	if conn == nil {
		return nil
	}
	if err := dispatchScheduledRun(ctx, db, conn, logger, manifestID, schedule, nextFire); err != nil {
		if logger != nil {
			logger.Warn("workflow_scheduler: dispatch failed",
				zap.String("manifest_id", manifestID),
				zap.Error(err))
		}
		// Don't return the error — the schedule_state row is committed,
		// the audit event is in event_log, the next pass will skip this
		// tick (won=false) and try the following one. Failing the entire
		// scheduler pass for a single bad workflow would cascade.
	}
	return nil
}

// dispatchScheduledRun resolves the workflow's namespace+name from the
// manifests table, materialises a workflow_runs row in pending status,
// then kicks the goroutine that owns the actual execution. Mirrors the
// dispatchAsyncWorkflowRun handler in controllers/httpapi/workflow_runs.go
// — same Insert + MarkRunning + RunWorkflow + FinalizeWorkflowRun flow,
// just without the HTTP wrapper. Inputs come from the schedule's
// default_inputs (always a map, may be empty); metadata captures the
// scheduled_for timestamp + manifest_id so a later GET /workflow-runs/<id>
// can show the operator which cron tick produced the run.
func dispatchScheduledRun(
	ctx context.Context,
	db *sql.DB,
	conn *amqp.Connection,
	logger *zap.Logger,
	manifestID string,
	schedule *model.WorkflowScheduleTriggerSpec,
	scheduledFor time.Time,
) error {
	var namespace, name string
	// namespace + name live as their own columns on public.manifests (the
	// POST /api/v1/manifests handler validates and projects the flat
	// {name,namespace,...} body into them); the spec JSON column does not
	// re-encode them in metadata. Reading from spec->metadata returns NULL
	// for every row and Scan fails on NULL→string.
	//
	// Retry on ErrNoRows: a previous scheduler pass picked the workflow
	// out of the candidates list (manifest was active=TRUE then). If we
	// hit "no rows" here it usually means an Upsert was mid-transaction
	// on the same id when we ran — the row vanishes from the snapshot
	// for a few ms. One short retry handles the common race without
	// masking genuine deletions; a second miss is treated as
	// "manifest not found" the same way as before.
	lookup := func() error {
		return db.QueryRowContext(ctx, `
			SELECT namespace, name
			FROM public.manifests
			WHERE id = $1 AND kind = 'workflow' AND active = TRUE
		`, manifestID).Scan(&namespace, &name)
	}
	if err := lookup(); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(150 * time.Millisecond):
			}
			if err2 := lookup(); err2 != nil {
				return err2
			}
		} else {
			return err
		}
	}

	inputs := map[string]any{}
	for k, v := range schedule.DefaultInputs {
		inputs[k] = v
	}
	metadata := map[string]any{
		"triggered_by":  "workflow_scheduler",
		"manifest_id":   manifestID,
		"scheduled_for": scheduledFor.Format(time.RFC3339),
	}

	runID := uuid.New()
	selector := model.ManifestSelector{Namespace: namespace, Name: name}
	if err := repository.InsertWorkflowRun(ctx, db, runID, selector, inputs, metadata); err != nil {
		return err
	}

	req := model.RunWorkflowRequest{
		Workflow: selector,
		Inputs:   inputs,
		Metadata: metadata,
	}

	go func() {
		bg := context.Background()
		startedAt := time.Now().UTC()
		_ = repository.MarkWorkflowRunRunning(bg, db, runID, startedAt)
		response, runErr := messagecontroller.RunWorkflow(bg, conn, db, req)
		status := "succeeded"
		errMsg := ""
		var resultPayload []byte
		if runErr != nil {
			status = "failed"
			errMsg = runErr.Error()
		} else {
			if buf, err := json.Marshal(response); err == nil {
				resultPayload = buf
			}
		}
		_ = repository.FinalizeWorkflowRun(bg, db, runID, status, resultPayload, errMsg, time.Now().UTC())
	}()

	if logger != nil {
		logger.Info("workflow_scheduler: dispatched",
			zap.String("manifest_id", manifestID),
			zap.String("namespace", namespace),
			zap.String("name", name),
			zap.String("run_id", runID.String()))
	}
	return nil
}

func workflowSchedulerInterval() time.Duration {
	raw := os.Getenv("WORKFLOW_SCHEDULER_INTERVAL_SECONDS")
	if raw == "" {
		return 10 * time.Second
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
