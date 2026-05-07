package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
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

	stop := make(chan struct{})
	go runWorkflowSchedulerLoop(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runWorkflowSchedulerLoop(
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
			runWorkflowSchedulerPass(ctx, db, logger)
		}
	}
}

// runWorkflowSchedulerPass executes one pass of the scheduler. Exposed for
// deterministic testing.
func runWorkflowSchedulerPass(ctx context.Context, db *sql.DB, logger *zap.Logger) {
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
		if err := processScheduledWorkflow(ctx, db, logger, wf.manifestID, wf.schedule, now); err != nil {
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

	return tx.Commit()
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
