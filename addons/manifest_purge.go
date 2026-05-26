package addons

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() {
	Register("manifest_purge", bootstrapManifestPurge, 60)
}

// bootstrapManifestPurge wires the periodic purge of soft-deleted
// manifests. Mirrors event_log_cleaner: one goroutine, ticker-driven,
// shuts down via app.RegisterCloser. Postgres-dependent — silently
// skipped when the postgres addon is absent (in-memory test runs).
//
// Default cadence is once every 24h with a 30-day retention. Both knobs
// are env-tunable: MANIFEST_PURGE_INTERVAL_SECONDS and
// MANIFEST_PURGE_RETENTION_DAYS. Setting the interval to 0 keeps the
// addon registered but inactive — useful for environments that prefer
// to drive purge via an out-of-band workflow.
func bootstrapManifestPurge(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}

	logger, _ := Logger(app)
	interval := manifestPurgeInterval()
	if interval == 0 {
		if logger != nil {
			logger.Info("manifest_purge disabled via MANIFEST_PURGE_INTERVAL_SECONDS=0")
		}
		return nil
	}

	retention := manifestPurgeRetention()

	stop := make(chan struct{})
	go runManifestPurge(ctx, db, logger, interval, retention, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})

	return nil
}

// runManifestPurge sweeps the manifests table on every tick, removing
// rows with active=FALSE older than the configured retention. Logs only
// non-zero deletions to keep the steady-state log volume bounded.
func runManifestPurge(ctx context.Context, db *sql.DB, logger *zap.Logger, interval, retention time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().UTC().Add(-retention)
			deleted, err := repository.PurgeInactiveManifestsOlderThan(ctx, db, cutoff)
			if err != nil {
				if logger != nil {
					logger.Warn("manifest purge failed",
						zap.Time("cutoff", cutoff),
						zap.Error(err),
					)
				}
				continue
			}
			httpapi.IncManifestPurged(deleted)
			if logger != nil && deleted > 0 {
				logger.Info("manifest purge",
					zap.Int64("deleted", deleted),
					zap.Time("cutoff", cutoff),
				)
			}
		}
	}
}

func manifestPurgeInterval() time.Duration {
	raw := os.Getenv("MANIFEST_PURGE_INTERVAL_SECONDS")
	if raw == "" {
		return 24 * time.Hour
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 24 * time.Hour
	}
	if seconds < 0 {
		return 24 * time.Hour
	}
	return time.Duration(seconds) * time.Second
}

func manifestPurgeRetention() time.Duration {
	raw := os.Getenv("MANIFEST_PURGE_RETENTION_DAYS")
	if raw == "" {
		return 30 * 24 * time.Hour
	}
	days, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || days <= 0 {
		return 30 * 24 * time.Hour
	}
	return time.Duration(days) * 24 * time.Hour
}
