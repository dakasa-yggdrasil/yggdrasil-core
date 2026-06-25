package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

// heimdall_inbox_dispatcher pulls oldest pending row from heimdall_inbox,
// dispatches the heimdall-react-on-infra-alert workflow async, and marks
// the inbox row processed/failed. Failure paths bump failure_count for
// poison-pill detection: an operator can query rows where failure_count
// > N to find alerts that consistently break Heimdall (bug in react
// workflow, missing capability, etc.) and act on the bug rather than
// losing the alert silently.
//
// Backoff: failed rows are NOT immediately retried in the same pass —
// we wait at least heimdallInboxBackoff(failure_count) before the next
// attempt. Linear backoff (10s × failure_count, cap 5min) is enough
// for the common case (transient AMQP flap during dispatch); operator
// review takes over after maxFailures.

const (
	heimdallInboxMaxFailures      = 10
	heimdallInboxReactWorkflow    = "heimdall-react-on-infra-alert"
	heimdallInboxReactNamespace   = "dakasa"
	heimdallInboxBackoffStepSec   = 10
	heimdallInboxBackoffMaxSec    = 300
	heimdallInboxDispatcherSource = "heimdall_inbox_dispatcher"
)

func init() {
	Register("heimdall_inbox_dispatcher", bootstrapHeimdallInboxDispatcher, 76)
}

func bootstrapHeimdallInboxDispatcher(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	conn, _ := RabbitMQ(app)
	logger, _ := Logger(app)
	interval := heimdallInboxDispatcherInterval()

	stop := make(chan struct{})
	go runHeimdallInboxDispatcherLoop(ctx, db, conn, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runHeimdallInboxDispatcherLoop(
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
			runHeimdallInboxDispatcherPass(ctx, db, conn, logger)
		}
	}
}

// runHeimdallInboxDispatcherPass picks the oldest pending row whose
// last_attempt_at is past the backoff window for its failure_count and
// dispatches the react workflow. Single-row-per-pass is intentional —
// keeps the dispatcher quiet under load and lets the loop interval govern
// the throughput; bursts that exceed it land in the inbox and drain at
// the dispatcher's pace without overwhelming downstream goroutines.
func runHeimdallInboxDispatcherPass(ctx context.Context, db *sql.DB, conn *amqp.Connection, logger *zap.Logger) {
	// Broker gate — skip the ENTIRE pass when the broker is unavailable.
	// The pass marks the inbox row processed_at = NOW() (committing the tx)
	// BEFORE it would dispatch; if we ran it with a dead broker the row would
	// be consumed (no longer "pending") yet never executed, losing the alert.
	// Bailing here leaves processed_at IS NULL so the row is re-picked on the
	// next live pass — replay, not loss. nil conn = boot-degraded; closed =
	// runtime drop. (The post-commit conn==nil branch below is now only the
	// slim/dev fallback for the unreachable mid-pass-drop race.)
	if !brokerLive(conn) {
		if logger != nil {
			logger.Warn("heimdall_inbox_dispatcher: broker unavailable — skipping pass, inbox row left pending for replay")
		}
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall_inbox_dispatcher: begin tx failed", zap.Error(err))
		}
		return
	}
	defer tx.Rollback()

	// SELECT FOR UPDATE SKIP LOCKED: lets multiple cores claim distinct
	// rows safely. The partial index on processed_at IS NULL keeps the
	// scan cheap even with a long inbox history.
	row := tx.QueryRowContext(ctx, `
		SELECT id, source_event_id, aggregate_id, payload, failure_count, last_attempt_at
		FROM public.heimdall_inbox
		WHERE processed_at IS NULL
		  AND failure_count < $1
		  AND (last_attempt_at IS NULL OR last_attempt_at < NOW() - (LEAST($2 * GREATEST(failure_count, 1), $3) * INTERVAL '1 second'))
		ORDER BY received_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, heimdallInboxMaxFailures, heimdallInboxBackoffStepSec, heimdallInboxBackoffMaxSec)

	var (
		inboxID, sourceEventID, aggID string
		payload                       []byte
		failureCount                  int
		lastAttempt                   sql.NullTime
	)
	if err := row.Scan(&inboxID, &sourceEventID, &aggID, &payload, &failureCount, &lastAttempt); err != nil {
		if err == sql.ErrNoRows {
			return // nothing to do
		}
		if logger != nil {
			logger.Warn("heimdall_inbox_dispatcher: select pending failed", zap.Error(err))
		}
		return
	}

	// Build the same RunWorkflowRequest that workflow_event_triggers.
	// buildEventTriggerRunRequest produced — keeps the react workflow's
	// templates ({{ inputs.event.alerts.0... }}) compatible.
	var payloadMap map[string]any
	_ = json.Unmarshal(payload, &payloadMap)

	runID := uuid.New()
	selector := model.ManifestSelector{
		Namespace: heimdallInboxReactNamespace,
		Name:      heimdallInboxReactWorkflow,
	}
	inputs := map[string]any{"event": payloadMap}
	metadata := map[string]any{
		"triggered_by":      heimdallInboxDispatcherSource,
		"inbox_id":          inboxID,
		"source_event_id":   sourceEventID,
		"matched_event_id":  sourceEventID,
		"matched_event_type": "infra.alert.firing",
	}

	if err := repository.InsertWorkflowRun(ctx, db, runID, selector, inputs, metadata); err != nil {
		// Couldn't even register the pending row — bump failure and back off.
		_, _ = tx.ExecContext(ctx, `
			UPDATE public.heimdall_inbox
			SET failure_count = failure_count + 1,
			    last_attempt_at = NOW(),
			    last_failure_reason = $2
			WHERE id = $1
		`, inboxID, err.Error())
		_ = tx.Commit()
		if logger != nil {
			logger.Warn("heimdall_inbox_dispatcher: insert workflow_run failed",
				zap.String("inbox_id", inboxID), zap.Error(err))
		}
		return
	}

	// Mark inbox row processed in the SAME tx as InsertWorkflowRun (well,
	// InsertWorkflowRun ran on the outer db; we update inbox via tx here).
	// Goroutine below carries the actual workflow execution; if it fails
	// the run row records that, the inbox row stays "processed" (we
	// honored the dispatch contract — failure to execute is a separate
	// concern visible via workflow_runs status).
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.heimdall_inbox
		SET processed_at = NOW(),
		    last_attempt_at = NOW(),
		    dispatched_run_id = $2
		WHERE id = $1
	`, inboxID, runID); err != nil {
		if logger != nil {
			logger.Warn("heimdall_inbox_dispatcher: mark processed failed",
				zap.String("inbox_id", inboxID), zap.Error(err))
		}
		return
	}

	if err := tx.Commit(); err != nil {
		if logger != nil {
			logger.Warn("heimdall_inbox_dispatcher: commit failed", zap.Error(err))
		}
		return
	}

	if !brokerLive(conn) {
		// Slim mode (no AMQP) or a broker drop between the top gate and this
		// point — the run row is in the table for inspection but no goroutine
		// will execute it. Matches dispatchAsync behavior in slim/dev mode.
		// Re-checking brokerLive (nil OR closed) keeps the bare goroutine
		// below from calling conn.Channel() on a dead connection.
		if logger != nil {
			logger.Info("heimdall_inbox_dispatcher: marked processed (broker unavailable, no dispatch)",
				zap.String("inbox_id", inboxID), zap.String("run_id", runID.String()))
		}
		return
	}

	go func() {
		bg := context.Background()
		startedAt := time.Now().UTC()
		_ = repository.MarkWorkflowRunRunning(bg, db, runID, startedAt)
		response, runErr := messagecontroller.RunWorkflow(bg, conn, db, model.RunWorkflowRequest{
			Workflow: selector,
			Inputs:   inputs,
			Metadata: metadata,
		})
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
		logger.Info("heimdall_inbox_dispatcher: dispatched",
			zap.String("inbox_id", inboxID),
			zap.String("source_event_id", sourceEventID),
			zap.String("run_id", runID.String()))
	}
}

func heimdallInboxDispatcherInterval() time.Duration {
	raw := os.Getenv("HEIMDALL_INBOX_DISPATCHER_INTERVAL_SECONDS")
	if raw == "" {
		return 5 * time.Second
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
