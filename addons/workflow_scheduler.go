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

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"
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
	ctx = withBrokerConnection(ctx, app)
	if raw, ok := app.Resource(capacityDispatchServiceResource); ok {
		if service, valid := raw.(*httpapi.CapacityDispatchService); valid {
			ctx = withCapacitySchedulerService(ctx, service)
		}
	}
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
	conn = brokerConnectionFor(ctx, conn)
	rows, err := db.QueryContext(ctx, `
		SELECT id, namespace, name, spec
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
		namespace  string
		name       string
		schedule   *model.WorkflowScheduleTriggerSpec
		enabled    bool
	}

	var candidates []scheduledWorkflow
	for rows.Next() {
		var (
			id        string
			namespace string
			name      string
			spec      []byte
		)
		if err := rows.Scan(&id, &namespace, &name, &spec); err != nil {
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
			namespace:  namespace,
			name:       name,
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
		if err := processScheduledWorkflow(ctx, db, conn, logger, wf.manifestID, wf.namespace, wf.name, wf.schedule, now); err != nil {
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
	namespace string,
	name string,
	schedule *model.WorkflowScheduleTriggerSpec,
	now time.Time,
) error {
	// Refuse before reading or advancing schedule_state. The same due tick is
	// therefore available for replay after the emergency lock is disabled.
	if err := workflowdispatchlock.CheckEnvironment(namespace, name); err != nil {
		if logger != nil {
			logger.Info("workflow_scheduler: dispatch held by emergency lock",
				zap.String("manifest_id", manifestID),
				zap.String("workflow", namespace+"/"+name))
		}
		return nil
	}

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
	// one tick per scheduler pass only for explicit catch_up. The shared
	// selector below coalesces skip/default backlog to its latest real due tick.
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

	nextFire, nextAfterFire, due, err := selectWorkflowScheduleTick(sched, loc, lastFired, now, schedule.CatchupPolicy)
	if err != nil {
		return err
	}
	if !due {
		// Not yet time
		return nil
	}

	// Respect end_at
	if schedule.EndAt != "" {
		if endAt, err := time.Parse(time.RFC3339, schedule.EndAt); err == nil && now.After(endAt) {
			return nil
		}
	}

	// Broker gate — CRITICAL: this check happens BEFORE schedule_state is
	// advanced. The state advance (UpsertWorkflowScheduleState below) is what
	// "consumes" this cron tick; if we advanced it while the broker is down,
	// the run would never dispatch and the tick would be lost forever (next
	// pass observes a later nextFire). By skipping here — leaving lastFired
	// untouched — the SAME tick re-fires on the next pass once the broker is
	// back. Explicit catch_up retains its oldest due tick; skip/default may
	// select a later actual due tick on recovery, without acknowledging missed
	// ticks or advancing this persisted cursor on refusal. nil conn =
	// boot-degraded; closed conn = runtime drop; both leave state untouched.
	var prepared *httpapi.CapacityDispatchPrepared
	if service := capacitySchedulerService(ctx); service != nil {
		id, parseErr := uuid.Parse(manifestID)
		if parseErr != nil {
			return parseErr
		}
		prepared, err = service.PrepareScheduledTick(ctx, id, nextFire)
		if err != nil {
			// An opted-in but disabled/refused binding NEVER falls back to
			// the legacy goroutine or consumes its original due tick.
			return err
		}

	} else {
		requiresOwner, ownerErr := capacityScheduleRequiresOwner(ctx, db, manifestID)
		if ownerErr != nil {
			return ownerErr
		}
		if requiresOwner {
			return errors.New("protected capacity schedule owner unavailable")
		}
	}
	if prepared == nil && !brokerLive(conn) {
		if logger != nil {
			logger.Warn("workflow_scheduler: broker unavailable — skipping tick, schedule_state left for replay",
				zap.String("manifest_id", manifestID),
				zap.Time("due_for", nextFire))
		}
		return nil
	}

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
	if prepared != nil {
		if _, _, err := prepared.Enqueue(ctx, tx); err != nil {
			return err
		}
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
	if prepared != nil {
		// Original tick, pending workflow run and new protocol job committed
		// together. Only the owned pre-start worker may invoke this run.
		return nil
	}

	// Dispatch the workflow run asynchronously after the schedule_state
	// commit so the audit trail captures the fire even if dispatch fails.
	// Without this step the scheduler is purely passive — it records "this
	// cron tick elapsed" and emits an event into the log, but no consumer
	// materialises a workflow_run, leaving every scheduled workflow armed
	// but never triggered.
	//
	// We re-check brokerLive here (not just the gate above) to close the
	// narrow window where the broker drops between the gate and this commit:
	// the schedule_state row is already committed (the tick legitimately
	// fired), but the connection may now be nil/closed, so dispatching would
	// deref a dead conn in the bare goroutine below and panic. Skip dispatch
	// in that case — the audit event records the fire and an operator can
	// replay via POST /api/v1/workflow-runs. Also covers slim/dev mode
	// (no AMQP), where conn is the boot-degraded typed-nil.
	if !brokerLive(conn) {
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

// selectWorkflowScheduleTick selects one real cron occurrence for both the
// protected capacity owner and the legacy dispatcher. Explicit catch_up keeps
// the original oldest-next behavior. Skip (also the declared default) chooses
// the latest occurrence <= now, rather than draining historical ticks at the
// scheduler's polling interval. Only the existing admission transaction may
// subsequently persist that selected tick; this pure selection consumes none.
//
// Cron Next is non-decreasing in its input instant, with plateaus between
// occurrences. Bisection over seconds finds the last plateau ending at
// now in at most 64 probes, regardless of backlog length or rare cron periods.
// The five-field parser has minute resolution; converting each probe into the
// configured location preserves actual instants through DST gaps and repeats.
func selectWorkflowScheduleTick(schedule cron.Schedule, loc *time.Location, lastFired, now time.Time, catchupPolicy string) (time.Time, time.Time, bool, error) {
	invalid := func() (time.Time, time.Time, bool, error) {
		return time.Time{}, time.Time{}, false, errors.New("workflow schedule tick selection invalid")
	}
	if schedule == nil || loc == nil || lastFired.IsZero() || now.IsZero() {
		return invalid()
	}
	policy := strings.ToLower(strings.TrimSpace(catchupPolicy))
	if policy != "" && policy != "skip" && policy != "catch_up" {
		return invalid()
	}
	next := func(after time.Time) (time.Time, bool) {
		value := schedule.Next(after.In(loc))
		return value, !value.IsZero() && value.After(after)
	}
	first, valid := next(lastFired)
	if !valid {
		return invalid()
	}
	if first.After(now) {
		return first, time.Time{}, false, nil
	}
	following, valid := next(first)
	if !valid {
		return invalid()
	}
	if policy == "catch_up" || following.After(now) {
		return first, following, true, nil
	}

	// Next(first) is already due, while Next(floor(now)) must be future.
	// Use unsigned distance so a valid interval crossing the Unix epoch does
	// not overflow signed subtraction. Every update shrinks that interval.
	low, high := first.Unix(), now.Unix()
	if low >= high {
		return invalid()
	}
	selected := following
	for uint64(high)-uint64(low) > 1 {
		middle := low + int64((uint64(high)-uint64(low))/2)
		candidate, valid := next(time.Unix(middle, 0))
		if !valid {
			return invalid()
		}
		if candidate.After(now) {
			high = middle
		} else {
			low, selected = middle, candidate
		}
	}
	after, valid := next(selected)
	if !valid || selected.Before(first) || selected.After(now) || !after.After(now) {
		return invalid()
	}
	return selected, after, true, nil
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
	req := model.RunWorkflowRequest{
		Workflow: selector,
		Inputs:   inputs,
		Metadata: metadata,
	}
	preparedReq, err := messagecontroller.PrepareAndInsertWorkflowRun(ctx, db, runID, req)
	if err != nil {
		return err
	}
	req = preparedReq

	go func() {
		bg := context.Background()
		startedAt := time.Now().UTC()
		_ = repository.MarkWorkflowRunRunning(bg, db, runID, startedAt)
		response, runErr := messagecontroller.RunWorkflow(bg, conn, db, req)
		if err := finishScheduledWorkflowRun(bg, db, logger, runID, response, runErr); err != nil && logger != nil {
			logger.Warn("workflow_scheduler: finalize run failed",
				zap.String("run_id", runID.String()), zap.Error(err))
		}
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

// A failed workflow step returns a typed response with a nil Go error. Keep
// the durable row's status in sync with that response, then publish a
// completion event only after the row has reached its terminal state.
func finishScheduledWorkflowRun(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	runID uuid.UUID,
	response model.RunWorkflowResponse,
	runErr error,
) error {
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
			if failedStep, ok := response.Metadata["failed_step"].(string); ok && failedStep != "" {
				errMsg = "step " + failedStep + " failed"
			}
		}
	}
	if err := repository.FinalizeWorkflowRun(ctx, db, runID, status, resultPayload, errMsg, time.Now().UTC()); err != nil {
		return err
	}
	if runErr == nil {
		messagecontroller.EmitScheduledWorkflowRunCompletedEvent(ctx, db, logger, response, runID)
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
