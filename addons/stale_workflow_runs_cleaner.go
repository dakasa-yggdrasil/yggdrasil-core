package addons

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

// stale_workflow_runs_cleaner periodically transitions workflow_runs rows
// stuck in status='running' or 'pending' beyond a configurable timeout
// to status='cancelled'. Mirrors the manual /ops/workflows/{id}/abort
// flow and matches the same DB CHECK ('cancelled' is the canonical
// terminal state; the ops surface renders it as "aborted").
//
// Why this addon exists
// =====================
// Async workflow runs execute inside a goroutine owned by a pod-scoped
// context.Background() (see addons/workflow_scheduler.go dispatchScheduledRun
// and controllers/httpapi/workflow_runs.go). If the pod restarts mid-run,
// the goroutine dies, the FinalizeWorkflowRun call never fires, and the
// row sits in status='running' forever. The ops surface counts those
// rows in "Active workflows" and the scheduler's accounting drifts.
//
// Audit 2026-05-28 found 25 such orphaned rows on yggdrasil.dakasa.me,
// the oldest stuck since 2026-05-08 (20 days). All were manually aborted
// via the abort endpoint; this addon prevents the recurrence.
//
// Behavior
// ========
// Every YGGDRASIL_WORKFLOW_RUNS_CLEANER_INTERVAL_SECONDS (default 600 =
// 10 min) the cleaner runs ONE UPDATE that flips any row where
//
//	status IN ('running','pending')
//	AND COALESCE(started_at, created_at) < NOW() - INTERVAL
//
// to status='cancelled' with finished_at=NOW(), error='stale: addon
// stale_workflow_runs_cleaner (no heartbeat after <timeout>)'.
//
// Threshold defaults to 3600s (1 hour) — comfortably above the longest
// legit run we have (deploy-via-kustomize-source ~3.5 min). Override via
// YGGDRASIL_WORKFLOW_RUNS_STALE_TIMEOUT_SECONDS.
//
// We deliberately do NOT delete rows here — they stay as durable audit
// evidence. The engine does not resume execution from workflow_runs.inputs;
// replay of a sensitive run requires freshly supplied values. The existing
// manifest_purge / event_log_cleaner addons handle retention separately.

func init() {
	Register("stale_workflow_runs_cleaner", bootstrapStaleWorkflowRunsCleaner, 50)
}

func bootstrapStaleWorkflowRunsCleaner(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	logger, _ := Logger(app)
	interval := staleWorkflowRunsCleanerInterval()
	timeout := staleWorkflowRunsTimeout()

	stop := make(chan struct{})
	go runStaleWorkflowRunsCleaner(ctx, db, logger, interval, timeout, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runStaleWorkflowRunsCleaner(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	interval time.Duration,
	timeout time.Duration,
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
			n, err := cleanupStaleWorkflowRuns(ctx, db, timeout)
			if err != nil {
				if logger != nil {
					logger.Warn("stale_workflow_runs cleanup failed", zap.Error(err))
				}
				continue
			}
			if logger != nil && n > 0 {
				logger.Info("stale_workflow_runs cleanup",
					zap.Int64("cancelled", n),
					zap.Duration("stale_threshold", timeout))
			}
		}
	}
}

// cleanupStaleWorkflowRuns flips runs older than timeout from
// pending/running to cancelled. Returns the number of rows updated.
//
// The error field carries an explicit "stale: addon …" prefix so
// operators querying GET /api/v1/ops/workflows/<id> can distinguish
// addon-driven aborts from operator-driven aborts and engine failures.
func cleanupStaleWorkflowRuns(ctx context.Context, db *sql.DB, timeout time.Duration) (int64, error) {
	if db == nil {
		return 0, nil
	}
	if timeout <= 0 {
		return 0, nil
	}
	// Cast the duration to seconds to build a stable error message that
	// includes the threshold operators actually saw at cleanup time.
	errMsg := fmt.Sprintf(
		"stale: addon stale_workflow_runs_cleaner (no heartbeat after %.0fs)",
		timeout.Seconds(),
	)
	res, err := db.ExecContext(ctx, `
		UPDATE public.workflow_runs
		SET status = 'cancelled',
		    finished_at = NOW(),
		    error = $2,
		    updated_at = NOW()
		WHERE status IN ('pending', 'running')
		  AND COALESCE(started_at, created_at) < NOW() - ($1::text || ' seconds')::interval
	`, fmt.Sprintf("%.0f", timeout.Seconds()), errMsg)
	if err != nil {
		return 0, fmt.Errorf("stale_workflow_runs cleanup: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("stale_workflow_runs cleanup rows_affected: %w", err)
	}
	return n, nil
}

func staleWorkflowRunsCleanerInterval() time.Duration {
	raw := os.Getenv("YGGDRASIL_WORKFLOW_RUNS_CLEANER_INTERVAL_SECONDS")
	if raw == "" {
		return 10 * time.Minute
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(seconds) * time.Second
}

func staleWorkflowRunsTimeout() time.Duration {
	raw := os.Getenv("YGGDRASIL_WORKFLOW_RUNS_STALE_TIMEOUT_SECONDS")
	if raw == "" {
		return 1 * time.Hour
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 1 * time.Hour
	}
	return time.Duration(seconds) * time.Second
}
