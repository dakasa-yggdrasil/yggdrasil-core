package password

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// SelectRotationBatch returns up to `limit` collaborator IDs whose passwords
// have expired and have not yet been marked must_change.
//
// Eligibility rule (user-tunable — see spec §11):
//   - status IN ('active', 'on_leave')
//   - password_expires_at < NOW()
//   - password_must_change = false
//   - password_hash IS NOT NULL  (no SSO-only rows)
//
// Ordering: oldest expiry first so the backlog drains predictably.
func SelectRotationBatch(ctx context.Context, db *sql.DB, limit int) ([]uuid.UUID, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := db.QueryContext(ctx, `
        SELECT ai.collaborator_id
        FROM auth_identities ai
        JOIN collaborators c ON c.id = ai.collaborator_id
        WHERE ai.password_expires_at IS NOT NULL
          AND ai.password_expires_at < NOW()
          AND ai.password_must_change = false
          AND ai.password_hash IS NOT NULL
          AND c.status IN ('active','on_leave')
        ORDER BY ai.password_expires_at ASC
        LIMIT $1
    `, limit)
	if err != nil {
		return nil, fmt.Errorf("select rotation batch: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// MarkForRotation flips password_must_change=true for the given collaborator IDs.
// Caller is responsible for emitting credential.password_rotation_required events
// per ID (see repository.MarkPasswordsRequiringRotation for the event-emitting
// counterpart that uses this primitive).
func MarkForRotation(ctx context.Context, db *sql.DB, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	uuidStrings := make([]string, len(ids))
	for i, id := range ids {
		uuidStrings[i] = id.String()
	}
	res, err := db.ExecContext(ctx, `
        UPDATE auth_identities
        SET password_must_change = true
        WHERE collaborator_id = ANY($1::uuid[])
          AND password_must_change = false
    `, pq.Array(uuidStrings))
	if err != nil {
		return fmt.Errorf("mark rotation: %w", err)
	}
	_, _ = res.RowsAffected()
	return nil
}

// Runner is a periodic worker that scans expired passwords and marks them.
type Runner struct {
	DB       *sql.DB
	Interval time.Duration
	Batch    int
	Logger   Logger
	// EmitMark is called per marked collaborator_id; the controller wires this
	// to repository event emission. Leave nil to skip emission (tests).
	EmitMark func(ctx context.Context, id uuid.UUID) error
}

// Logger is the minimal logging interface required by Runner.
type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// Run blocks until ctx is cancelled, running a rotation pass immediately and
// then on each tick. Mirrors the ticker pattern in internal/operator/reconciler.go.
func (r *Runner) Run(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.runOnce(ctx); err != nil && r.Logger != nil {
			r.Logger.Error("rotation runner failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (r *Runner) runOnce(ctx context.Context) error {
	ids, err := SelectRotationBatch(ctx, r.DB, r.Batch)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if err := MarkForRotation(ctx, r.DB, ids); err != nil {
		return err
	}
	if r.EmitMark == nil {
		return nil
	}
	for _, id := range ids {
		if err := r.EmitMark(ctx, id); err != nil && r.Logger != nil {
			r.Logger.Error("emit rotation event", "id", id.String(), "err", err)
		}
	}
	return nil
}
