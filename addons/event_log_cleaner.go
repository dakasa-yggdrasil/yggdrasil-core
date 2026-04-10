package addons

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() {
	Register("event_log_cleaner", bootstrapEventLogCleaner, 50)
}

func bootstrapEventLogCleaner(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		// Postgres addon not available; skip silently (opt-in by dependency).
		return nil
	}

	logger, _ := Logger(app)
	interval := eventLogCleanerInterval()

	stop := make(chan struct{})
	go runEventLogCleaner(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runEventLogCleaner(ctx context.Context, db *sql.DB, logger *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := repository.CleanupExpiredEvents(ctx, db)
			if err != nil {
				if logger != nil {
					logger.Warn("event_log cleanup failed", zap.Error(err))
				}
				continue
			}
			if logger != nil && deleted > 0 {
				logger.Info("event_log cleanup", zap.Int64("deleted", deleted))
			}
		}
	}
}

func eventLogCleanerInterval() time.Duration {
	raw := os.Getenv("EVENT_LOG_CLEANER_INTERVAL_SECONDS")
	if raw == "" {
		return 3600 * time.Second // default 1 hour
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 3600 * time.Second
	}
	return time.Duration(seconds) * time.Second
}
