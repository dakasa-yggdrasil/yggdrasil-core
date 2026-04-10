package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// WorkflowScheduleState captures the last and next fire times for a
// scheduled workflow trigger. The scheduler loop queries this table to find
// workflows that are due to run now.
type WorkflowScheduleState struct {
	WorkflowManifestID   string
	LastFiredAt          time.Time
	NextFireAt           time.Time
	ConsecutiveFailures  int
	UpdatedAt            time.Time
}

// UpsertWorkflowScheduleState records the last fire time + computed next
// fire time for a scheduled workflow. Uses an atomic UPDATE + INSERT so
// concurrent workers don't lose state.
//
// The ON CONFLICT WHERE clause uses the condition
// workflow_schedule_state.last_fired_at < EXCLUDED.last_fired_at so that
// two workers racing on the same workflow only update the state once.
// Returns true if this call won the update, false if another worker
// already fired that tick.
func UpsertWorkflowScheduleState(
	ctx context.Context,
	tx *sql.Tx,
	workflowManifestID string,
	lastFiredAt, nextFireAt time.Time,
) (bool, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO public.workflow_schedule_state (
			workflow_manifest_id, last_fired_at, next_fire_at, updated_at
		) VALUES ($1, $2, $3, NOW())
		ON CONFLICT (workflow_manifest_id) DO UPDATE SET
			last_fired_at = EXCLUDED.last_fired_at,
			next_fire_at = EXCLUDED.next_fire_at,
			updated_at = NOW()
		WHERE workflow_schedule_state.last_fired_at < EXCLUDED.last_fired_at
	`, workflowManifestID, lastFiredAt, nextFireAt)
	if err != nil {
		return false, fmt.Errorf("upsert workflow_schedule_state: %w", err)
	}
	affected, _ := result.RowsAffected()
	return affected > 0, nil
}

// GetWorkflowScheduleState returns the state row for a workflow, or a zero
// value if no row exists yet (first run).
func GetWorkflowScheduleState(ctx context.Context, db *sql.DB, workflowManifestID string) (WorkflowScheduleState, error) {
	var state WorkflowScheduleState
	err := db.QueryRowContext(ctx, `
		SELECT workflow_manifest_id, last_fired_at, next_fire_at, consecutive_failures, updated_at
		FROM public.workflow_schedule_state
		WHERE workflow_manifest_id = $1
	`, workflowManifestID).Scan(
		&state.WorkflowManifestID,
		&state.LastFiredAt,
		&state.NextFireAt,
		&state.ConsecutiveFailures,
		&state.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return WorkflowScheduleState{WorkflowManifestID: workflowManifestID}, nil
	}
	if err != nil {
		return WorkflowScheduleState{}, fmt.Errorf("get workflow_schedule_state: %w", err)
	}
	return state, nil
}

// GetWorkflowEventTriggerCursor returns the cursor the event-trigger loop
// last processed to. Creates the row with empty cursor if missing.
func GetWorkflowEventTriggerCursor(ctx context.Context, db *sql.DB) (string, error) {
	var cursor string
	err := db.QueryRowContext(ctx, `
		SELECT last_cursor FROM public.workflow_event_trigger_state
		WHERE id = 'workflow_event_trigger_loop'
	`).Scan(&cursor)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get workflow_event_trigger_cursor: %w", err)
	}
	return cursor, nil
}

// SaveWorkflowEventTriggerCursor persists the cursor after the loop
// processes a batch.
func SaveWorkflowEventTriggerCursor(ctx context.Context, db *sql.DB, cursor string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE public.workflow_event_trigger_state
		SET last_cursor = $1,
		    updated_at = NOW()
		WHERE id = 'workflow_event_trigger_loop'
	`, cursor)
	if err != nil {
		return fmt.Errorf("save workflow_event_trigger_cursor: %w", err)
	}
	return nil
}

// TryAcquireWorkflowEventTriggerLeadership attempts a session-level advisory
// lock. Only one worker holds the lock at a time; others should skip the
// event trigger pass and try again next tick. The lock is released when
// the session ends or ReleaseWorkflowEventTriggerLeadership is called.
const workflowEventTriggerLeaderLockID = 42 // arbitrary int for pg_try_advisory_lock

func TryAcquireWorkflowEventTriggerLeadership(ctx context.Context, db *sql.DB) (bool, error) {
	var acquired bool
	err := db.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, workflowEventTriggerLeaderLockID).Scan(&acquired)
	if err != nil {
		return false, fmt.Errorf("try advisory lock: %w", err)
	}
	return acquired, nil
}

// ReleaseWorkflowEventTriggerLeadership releases the advisory lock held by
// TryAcquireWorkflowEventTriggerLeadership.
func ReleaseWorkflowEventTriggerLeadership(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, workflowEventTriggerLeaderLockID)
	if err != nil {
		return fmt.Errorf("release advisory lock: %w", err)
	}
	return nil
}
