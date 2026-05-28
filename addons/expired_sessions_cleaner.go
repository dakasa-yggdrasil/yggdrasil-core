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

// expired_sessions_cleaner periodically transitions auth_sessions rows
// whose expires_at < NOW() AND status = 'active' to status = 'expired'.
//
// Audit ref: C5 (active-but-expired sessions never cleaned by any
// addon; verified 5 such rows in production). Without this cleaner the
// row count grows monotonically and the `auth_sessions.status='active'`
// dashboard count misleads operators.
//
// Distinct from manifest_purge / event_log_cleaner / collaborator_status
// _clock because none of them touch auth_sessions. The cleaner runs on
// a 30-min cadence by default; override via
// EXPIRED_SESSIONS_CLEANER_INTERVAL_SECONDS.

func init() {
	Register("expired_sessions_cleaner", bootstrapExpiredSessionsCleaner, 50)
}

func bootstrapExpiredSessionsCleaner(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	logger, _ := Logger(app)
	interval := expiredSessionsCleanerInterval()

	stop := make(chan struct{})
	go runExpiredSessionsCleaner(ctx, db, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

func runExpiredSessionsCleaner(ctx context.Context, db *sql.DB, logger *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := cleanupExpiredSessions(ctx, db)
			if err != nil {
				if logger != nil {
					logger.Warn("expired_sessions cleanup failed", zap.Error(err))
				}
				continue
			}
			if logger != nil && n > 0 {
				logger.Info("expired_sessions cleanup", zap.Int64("expired", n))
			}
		}
	}
}

// cleanupExpiredSessions transitions rows past their expires_at to
// status='expired'. Returns the number of rows updated.
//
// We do NOT delete the rows here — kept for audit/timeline forensics.
// A separate retention sweeper (out of scope for this addon) can hard-
// delete rows older than a configurable threshold.
func cleanupExpiredSessions(ctx context.Context, db *sql.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}
	res, err := db.ExecContext(ctx, `
		UPDATE public.auth_sessions
		SET status = 'expired', updated_at = NOW()
		WHERE status = 'active'
		  AND expires_at < NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("expired_sessions cleanup: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("expired_sessions cleanup rows_affected: %w", err)
	}
	return n, nil
}

func expiredSessionsCleanerInterval() time.Duration {
	raw := os.Getenv("EXPIRED_SESSIONS_CLEANER_INTERVAL_SECONDS")
	if raw == "" {
		return 30 * time.Minute
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(seconds) * time.Second
}
