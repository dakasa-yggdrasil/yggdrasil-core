package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"
)

// WorkflowScheduleState captures the last and next fire times for a
// scheduled workflow trigger. The scheduler loop queries this table to find
// workflows that are due to run now.
type WorkflowScheduleState struct {
	WorkflowManifestID  string
	LastFiredAt         time.Time
	NextFireAt          time.Time
	ConsecutiveFailures int
	UpdatedAt           time.Time
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
// event trigger pass and try again next tick.
//
// A session-level advisory lock belongs to one PostgreSQL session. The lock
// and its unlock therefore run on the same pinned *sql.Conn: through the
// *sql.DB pool they could land on different connections, the unlock would
// warn "you don't own a lock of type ExclusiveLock", and the lock would leak
// on an idle pooled connection.
const workflowEventTriggerLeaderLockID = 42 // arbitrary int for pg_try_advisory_lock

// WorkflowEventTriggerLeadership is the pinned session that holds the leader
// lock. Release must be called exactly once.
type WorkflowEventTriggerLeadership struct {
	conn *sql.Conn
}

// TryAcquireWorkflowEventTriggerLeadership returns a held leadership when the
// lock was acquired, and nil (no session kept) otherwise.
func TryAcquireWorkflowEventTriggerLeadership(ctx context.Context, db *sql.DB) (*WorkflowEventTriggerLeadership, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("try advisory lock: %w", err)
	}
	var acquired bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, workflowEventTriggerLeaderLockID).Scan(&acquired); err != nil {
		// The lock outcome is unknown: discard the session rather than pool it.
		discardWorkflowEventTriggerConn(conn)
		return nil, fmt.Errorf("try advisory lock: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		return nil, nil
	}
	return &WorkflowEventTriggerLeadership{conn: conn}, nil
}

// Release unlocks on the same session that took the lock. A cancelled caller
// context does not skip the unlock. If the unlock cannot be confirmed, the
// session is discarded instead of being returned to the pool still holding it.
func (l *WorkflowEventTriggerLeadership) Release(ctx context.Context) error {
	if l == nil || l.conn == nil {
		return nil
	}
	conn := l.conn
	l.conn = nil
	unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var released bool
	if err := conn.QueryRowContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, workflowEventTriggerLeaderLockID).Scan(&released); err != nil || !released {
		discardWorkflowEventTriggerConn(conn)
		if err == nil {
			err = errors.New("leader lock was not held by this session")
		}
		return fmt.Errorf("release advisory lock: %w", err)
	}
	return conn.Close()
}

// A driver.ErrBadConn from Raw marks the connection bad, so Close discards
// it (ending its PostgreSQL session and any session lock) instead of pooling.
func discardWorkflowEventTriggerConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}

// HasWorkflowEventMatched reports whether a workflow.event.matched record
// already exists for the (workflow_manifest_id, source_event_id) pair. The
// dispatcher uses this as the dedup signal: the matched event itself is the
// dedup key, so re-running the leader pass over the same window cannot
// dispatch the same workflow twice for the same source event.
//
// We pin the lookup against the same fields the trigger emits — aggregate_id
// holds the workflow manifest id and payload->>'matched_event_id' holds the
// source event id. No new schema is needed; this is a query over an existing
// emitted event row.
func HasWorkflowEventMatched(ctx context.Context, db *sql.DB, workflowManifestID, sourceEventID string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.event_log
			WHERE type = 'workflow.event.matched'
			  AND aggregate_id = $1
			  AND payload->>'matched_event_id' = $2
		)
	`, workflowManifestID, sourceEventID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check workflow.event.matched dedup: %w", err)
	}
	return exists, nil
}
