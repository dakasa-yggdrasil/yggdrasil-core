package addons

import (
	"context"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/teamreconcile"
	"go.uber.org/zap"
)

func init() {
	Register("team-reconcile", bootstrapTeamReconcile, 76)
}

// bootstrapTeamReconcile starts the teamreconcile.Runner as a background
// goroutine alongside manifest-sync.
//
// Controlled by:
//
//	TEAM_RECONCILE_ENABLED  — "false" to disable (default enabled)
//	TEAM_RECONCILE_INTERVAL — cron cadence (e.g. "5m"). Default 5m
func bootstrapTeamReconcile(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)

	r := &teamreconcile.Runner{
		DB:       db,
		Interval: envDurOrDefault("TEAM_RECONCILE_INTERVAL", 5*time.Minute),
		Logger:   logger,
	}

	go func() {
		if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("team reconcile runner exited unexpectedly", zap.Error(err))
			}
		}
	}()

	if logger != nil {
		logger.Info("team reconcile addon started",
			zap.Duration("interval", r.Interval),
		)
	}
	return nil
}
