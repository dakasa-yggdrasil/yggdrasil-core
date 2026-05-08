package addons

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() {
	Register("collaborator_status_clock", bootstrapCollaboratorStatusClock, 60)
}

// bootstrapCollaboratorStatusClock starts a daily ticker that promotes
// pending_start collaborators to active when their start_date has been
// reached, and offboards collaborators whose end_date has passed.
//
// Status flips emit lifecycle events with actor_type=system so the
// audit log distinguishes automatic transitions from manual ones.
func bootstrapCollaboratorStatusClock(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)
	interval := collaboratorStatusClockInterval()

	stop := make(chan struct{})
	go runCollaboratorStatusClock(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})
	return nil
}

func runCollaboratorStatusClock(ctx context.Context, db *sql.DB, logger *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := RunCollaboratorStatusClockTick(ctx, db); err != nil {
		if logger != nil {
			logger.Warn("collaborator_status_clock initial tick failed", zap.Error(err))
		}
	}

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := RunCollaboratorStatusClockTick(ctx, db); err != nil {
				if logger != nil {
					logger.Warn("collaborator_status_clock tick failed", zap.Error(err))
				}
			}
		}
	}
}

// RunCollaboratorStatusClockTick runs ONE pass of the clock — promote
// pending_starts that have reached their start_date and offboard any
// collaborator past their end_date. Date math runs in local time so it
// agrees with the calendar semantics of HR/employment data.
func RunCollaboratorStatusClockTick(ctx context.Context, db *sql.DB) error {
	today := time.Now().Format("2006-01-02")

	pendingIDs, err := queryCollabIDs(ctx, db, `
		SELECT id::text FROM public.collaborators
		WHERE status = 'pending_start'
		  AND employment_data ? 'start_date'
		  AND (employment_data->>'start_date') <= $1
	`, today)
	if err != nil {
		return fmt.Errorf("query pending_start: %w", err)
	}
	for _, id := range pendingIDs {
		statusActive := "active"
		if _, err := repository.UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{
			ID:     id,
			Status: &statusActive,
		}); err != nil {
			return fmt.Errorf("promote %s: %w", id, err)
		}
		collab, err := repository.GetCollaborator(ctx, db, id)
		if err != nil {
			return err
		}
		if _, err := repository.AppendLifecycleEvent(ctx, db, model.AppendLifecycleEventRequest{
			CollaboratorID: collab.ID,
			EventType:      model.LifecycleEventHired,
			Payload:        map[string]any{"start_date": collab.EmploymentData["start_date"], "auto_promoted": true},
			ActorType:      model.ActorTypeSystem,
			ActorID:        "collaborator_status_clock",
		}); err != nil {
			return err
		}
	}

	endIDs, err := queryCollabIDs(ctx, db, `
		SELECT id::text FROM public.collaborators
		WHERE status <> 'offboarded'
		  AND employment_data ? 'end_date'
		  AND (employment_data->>'end_date') <= $1
	`, today)
	if err != nil {
		return fmt.Errorf("query end_date: %w", err)
	}
	for _, id := range endIDs {
		statusOffboarded := "offboarded"
		if _, err := repository.UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{
			ID:     id,
			Status: &statusOffboarded,
		}); err != nil {
			return fmt.Errorf("offboard %s: %w", id, err)
		}
		collab, err := repository.GetCollaborator(ctx, db, id)
		if err != nil {
			return err
		}
		if _, err := repository.AppendLifecycleEvent(ctx, db, model.AppendLifecycleEventRequest{
			CollaboratorID: collab.ID,
			EventType:      model.LifecycleEventOffboarded,
			Payload: map[string]any{
				"reason":   "contract-end",
				"end_date": collab.EmploymentData["end_date"],
			},
			ActorType: model.ActorTypeSystem,
			ActorID:   "collaborator_status_clock",
		}); err != nil {
			return err
		}
	}

	return nil
}

func queryCollabIDs(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// collaboratorStatusClockInterval returns the cadence of the daily
// tick, configurable via env for ops/tests.
func collaboratorStatusClockInterval() time.Duration {
	if v := os.Getenv("COLLAB_STATUS_CLOCK_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 24 * time.Hour
}
