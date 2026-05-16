package addons

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"go.uber.org/zap"
)

func init() {
	Register("external_identity_cleanup", bootstrapExternalIdentityCleanup, 86)
}

// bootstrapExternalIdentityCleanup runs a daily ticker that purges
// long-soft-deleted external identity rows (default retention: 30 days).
//
// Tunable env vars:
//
//	YGGDRASIL_EXTERNAL_IDENTITY_CLEANUP_INTERVAL — tick interval (default 24h)
//	YGGDRASIL_EXTERNAL_IDENTITY_RETENTION        — soft-delete retention (default 720h = 30d)
//
// Setting interval "0" disables the ticker.
func bootstrapExternalIdentityCleanup(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)
	interval := externalIdentityCleanupInterval()
	if interval == 0 {
		return nil
	}
	retention := externalIdentityRetention()

	stop := make(chan struct{})
	go runExternalIdentityCleanup(ctx, db, logger, interval, retention, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})
	return nil
}

func runExternalIdentityCleanup(ctx context.Context, db *sql.DB, logger *zap.Logger, interval, retention time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if n, err := externalidentity.CleanupTick(ctx, db, retention); err != nil && logger != nil {
		logger.Warn("external_identity_cleanup initial tick failed", zap.Error(err))
	} else if logger != nil && n > 0 {
		logger.Info("external_identity_cleanup purged", zap.Int("count", n))
	}

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := externalidentity.CleanupTick(ctx, db, retention)
			if err != nil && logger != nil {
				logger.Warn("external_identity_cleanup tick failed", zap.Error(err))
			} else if logger != nil && n > 0 {
				logger.Info("external_identity_cleanup purged", zap.Int("count", n))
			}
		}
	}
}

func externalIdentityCleanupInterval() time.Duration {
	raw := os.Getenv("YGGDRASIL_EXTERNAL_IDENTITY_CLEANUP_INTERVAL")
	if raw == "" {
		return 24 * time.Hour
	}
	if raw == "0" {
		return 0
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if n, err := strconv.Atoi(raw); err == nil {
		return time.Duration(n) * time.Second
	}
	return 24 * time.Hour
}

func externalIdentityRetention() time.Duration {
	raw := os.Getenv("YGGDRASIL_EXTERNAL_IDENTITY_RETENTION")
	if raw == "" {
		return 30 * 24 * time.Hour
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if n, err := strconv.Atoi(raw); err == nil {
		return time.Duration(n) * time.Second
	}
	return 30 * 24 * time.Hour
}
