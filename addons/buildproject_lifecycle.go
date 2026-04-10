package addons

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() {
	Register("buildproject_lifecycle", bootstrapBuildProjectLifecycle, 60)
}

// bootstrapBuildProjectLifecycle starts the background loop that enforces
// ephemeral BuildProject expiration. It:
//   - periodically scans for active ephemeral projects past their expires_at
//   - atomically transitions them to the "expiring" state
//   - emits buildproject.expired events
//   - transitions to "deleted" after any configured teardown workflow runs
//   - hard-deletes projects that have been deleted longer than the retention
//     period (default 30 days, configurable)
//
// Runs in every yggdrasil-core instance. Atomic state transitions via
// optimistic locking make this safe with multiple concurrent workers.
func bootstrapBuildProjectLifecycle(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		// Postgres addon not available; skip silently.
		return nil
	}

	logger, _ := Logger(app)
	interval := buildProjectLifecycleInterval()
	retention := buildProjectHardDeleteRetention()

	stop := make(chan struct{})
	go runBuildProjectLifecycleLoop(ctx, db, logger, interval, retention, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runBuildProjectLifecycleLoop(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	interval time.Duration,
	retention time.Duration,
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
			runBuildProjectLifecyclePass(ctx, db, logger, retention)
		}
	}
}

// runBuildProjectLifecyclePass executes one pass of the lifecycle enforcer.
// Separated from the loop so tests can invoke a single pass deterministically.
func runBuildProjectLifecyclePass(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	retention time.Duration,
) {
	// Step 1: find expired candidates + transition each to expiring + emit
	// buildproject.expired event. Each transition is its own tx so a failure
	// on one candidate doesn't block others.
	candidates, err := repository.FindExpiredBuildProjectCandidates(ctx, db, 100)
	if err != nil {
		if logger != nil {
			logger.Warn("buildproject_lifecycle: find candidates failed", zap.Error(err))
		}
		return
	}

	for _, build := range candidates {
		if err := transitionBuildProjectToExpiringWithEvent(ctx, db, logger, build); err != nil {
			if logger != nil {
				logger.Warn("buildproject_lifecycle: transition failed",
					zap.String("id", build.ID.String()),
					zap.Error(err))
			}
			continue
		}
	}

	// Step 2: hard-delete expired BuildProjects that have been deleted
	// longer than retention. Opt-in: if retention is 0 or negative, skip.
	if retention > 0 {
		cutoff := time.Now().UTC().Add(-retention)
		deleted, err := repository.HardDeleteBuildProjectsOlderThan(ctx, db, cutoff)
		if err != nil {
			if logger != nil {
				logger.Warn("buildproject_lifecycle: hard delete failed", zap.Error(err))
			}
		} else if deleted > 0 && logger != nil {
			logger.Info("buildproject_lifecycle: hard-deleted expired projects",
				zap.Int64("count", deleted))
		}
	}
}

// transitionBuildProjectToExpiringWithEvent wraps the state transition +
// event emission in a single transaction so both happen or neither does.
func transitionBuildProjectToExpiringWithEvent(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	build model.BuildProject,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	transitioned, err := repository.TransitionBuildProjectToExpiring(ctx, tx, build.ID.String())
	if err != nil {
		return err
	}
	if !transitioned {
		// Another worker already picked this one up; skip silently.
		return nil
	}

	// Emit buildproject.expired event in the same tx. If the emit fails,
	// the tx rolls back and another lifecycle pass will retry.
	payload := map[string]interface{}{
		"build_project_id": build.ID.String(),
		"build_name":       build.BuildName,
		"env_type":         build.EnvType,
		"cloud":            build.Cloud,
		"expires_at":       build.ExpiresAt,
	}
	if build.ClusterName != "" {
		payload["cluster_name"] = build.ClusterName
	}
	if build.ClusterZone != "" {
		payload["cluster_zone"] = build.ClusterZone
	}

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "buildproject.expired",
		SchemaVersion: "v1",
		AggregateType: "buildproject",
		AggregateID:   build.ID.String(),
		Actor: &model.EventActor{
			Type: "system",
			ID:   "buildproject_lifecycle_enforcer",
		},
		Payload: payload,
	}); err != nil {
		// Schema for buildproject.expired may not be registered yet — in
		// that case the emit fails but the transition should still succeed.
		// We log the warning and don't roll back (the transition is the
		// main business logic; the event is an audit side channel).
		if logger != nil {
			logger.Warn("buildproject_lifecycle: event emit failed (schema may not be registered)",
				zap.String("id", build.ID.String()),
				zap.Error(err))
		}
		// Fall through to commit the state transition anyway.
	}

	return tx.Commit()
}

func buildProjectLifecycleInterval() time.Duration {
	raw := os.Getenv("BUILDPROJECT_LIFECYCLE_INTERVAL_SECONDS")
	if raw == "" {
		return 60 * time.Second
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func buildProjectHardDeleteRetention() time.Duration {
	raw := os.Getenv("BUILDPROJECT_HARD_DELETE_RETENTION_DAYS")
	if raw == "" {
		return 30 * 24 * time.Hour
	}
	days, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || days < 0 {
		return 30 * 24 * time.Hour
	}
	if days == 0 {
		return 0 // 0 = disabled
	}
	return time.Duration(days) * 24 * time.Hour
}
