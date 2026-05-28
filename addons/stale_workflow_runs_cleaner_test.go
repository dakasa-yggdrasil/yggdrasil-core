package addons

import (
	"context"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestCleanupStaleWorkflowRuns_CancelsRowsBeyondTimeout verifies the
// cleanup query flips pending/running rows older than the threshold to
// status='cancelled' with the explicit "stale: addon …" error message.
//
// Audit 2026-05-28: 25 orphan rows in production stuck on
// status='running' because the goroutine that owned them died with the
// pod (workflow_scheduler.go:378 dispatches with context.Background(),
// no FinalizeWorkflowRun fires after pod restart).
func TestCleanupStaleWorkflowRuns_CancelsRowsBeyondTimeout(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE public.workflow_runs
		SET status = 'cancelled',
		    finished_at = NOW(),
		    error = $2,
		    updated_at = NOW()
		WHERE status IN ('pending', 'running')
		  AND COALESCE(started_at, created_at) < NOW() - ($1::text || ' seconds')::interval
	`)).
		WithArgs("3600", "stale: addon stale_workflow_runs_cleaner (no heartbeat after 3600s)").
		WillReturnResult(sqlmock.NewResult(0, 25))

	n, err := cleanupStaleWorkflowRuns(context.Background(), db, time.Hour)
	if err != nil {
		t.Fatalf("cleanupStaleWorkflowRuns: %v", err)
	}
	if n != 25 {
		t.Fatalf("expected 25 rows cancelled, got %d", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestCleanupStaleWorkflowRuns_NilDBIsNoop ensures the cleaner is safe
// when bootstrap was a noop because Postgres was not available.
func TestCleanupStaleWorkflowRuns_NilDBIsNoop(t *testing.T) {
	t.Parallel()
	n, err := cleanupStaleWorkflowRuns(context.Background(), nil, time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows, got %d", n)
	}
}

// TestCleanupStaleWorkflowRuns_NonPositiveTimeoutIsNoop guards against
// misconfiguration that would otherwise abort every in-flight run.
func TestCleanupStaleWorkflowRuns_NonPositiveTimeoutIsNoop(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	n, err := cleanupStaleWorkflowRuns(context.Background(), db, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 rows for zero timeout, got %d", n)
	}
}

// TestStaleWorkflowRunsCleanerInterval_DefaultsTo10Min verifies the
// scan cadence default when the env knob is unset.
func TestStaleWorkflowRunsCleanerInterval_DefaultsTo10Min(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUNS_CLEANER_INTERVAL_SECONDS", "")
	if got := staleWorkflowRunsCleanerInterval(); got != 10*time.Minute {
		t.Fatalf("expected 10m default, got %v", got)
	}
}

// TestStaleWorkflowRunsCleanerInterval_HonorsEnv verifies the env
// override is parsed.
func TestStaleWorkflowRunsCleanerInterval_HonorsEnv(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUNS_CLEANER_INTERVAL_SECONDS", "120")
	if got := staleWorkflowRunsCleanerInterval(); got != 2*time.Minute {
		t.Fatalf("expected 2m, got %v", got)
	}
}

// TestStaleWorkflowRunsTimeout_DefaultsTo1Hour verifies the stale
// threshold default.
func TestStaleWorkflowRunsTimeout_DefaultsTo1Hour(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUNS_STALE_TIMEOUT_SECONDS", "")
	if got := staleWorkflowRunsTimeout(); got != time.Hour {
		t.Fatalf("expected 1h default, got %v", got)
	}
}

// TestStaleWorkflowRunsTimeout_HonorsEnv verifies the env override.
func TestStaleWorkflowRunsTimeout_HonorsEnv(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUNS_STALE_TIMEOUT_SECONDS", "1800")
	if got := staleWorkflowRunsTimeout(); got != 30*time.Minute {
		t.Fatalf("expected 30m, got %v", got)
	}
}
