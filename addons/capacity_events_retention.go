package addons

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() { Register("capacity_events_retention", bootstrapCapacityEventsRetention, 56) }

type capacityRetentionSettings struct {
	enabled     bool
	days, batch int
	interval    time.Duration
}

func capacityRetentionConfig(getenv func(string) string) (capacityRetentionSettings, error) {
	settings := capacityRetentionSettings{days: 90, batch: 1000, interval: 15 * time.Minute}
	switch getenv("YGGDRASIL_CAPACITY_EVENT_RETENTION_ENABLED") {
	case "", "false":
		return settings, nil
	case "true":
		settings.enabled = true
	default:
		return settings, fmt.Errorf("capacity event retention enabled must be true or false")
	}
	for _, field := range []struct {
		name     string
		min, max int
		value    *int
	}{
		{"YGGDRASIL_CAPACITY_EVENT_RETENTION_DAYS", 30, 3650, &settings.days},
		{"YGGDRASIL_CAPACITY_EVENT_RETENTION_BATCH", 1, 1000, &settings.batch},
	} {
		if raw := getenv(field.name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < field.min || value > field.max {
				return settings, fmt.Errorf("%s is outside its retention bounds", field.name)
			}
			*field.value = value
		}
	}
	if raw := getenv("YGGDRASIL_CAPACITY_EVENT_RETENTION_INTERVAL_SECONDS"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 60 || value > 86400 {
			return settings, fmt.Errorf("capacity event retention interval must be 60..86400 seconds")
		}
		settings.interval = time.Duration(value) * time.Second
	}
	return settings, nil
}

func bootstrapCapacityEventsRetention(ctx context.Context, app *runtime.ServiceApp) error {
	settings, err := capacityRetentionConfig(os.Getenv)
	if err != nil || !settings.enabled {
		return err
	}
	db, ok := Postgres(app)
	if !ok || db == nil {
		return fmt.Errorf("enabled capacity event retention requires PostgreSQL")
	}
	logger, _ := Logger(app)
	runCtx, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	goroutine.SafeGo("capacity_events_retention", func() { defer close(joined); runCapacityEventsRetention(runCtx, db, logger, settings) })
	app.RegisterCloser(func(closeCtx context.Context) error {
		cancel()
		select {
		case <-joined:
			return nil
		case <-closeCtx.Done():
			return closeCtx.Err()
		}
	})
	return nil
}

func runCapacityEventsRetention(ctx context.Context, db *sql.DB, logger *zap.Logger, settings capacityRetentionSettings) {
	// Avoid a startup cascade; there is no boot sweep or catch-up loop.
	ticker := time.NewTicker(settings.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			n, err := repository.PruneCapacityEvents(sweepCtx, db, settings.days, settings.batch)
			cancel()
			if logger == nil {
				continue
			}
			if err != nil {
				logger.Warn("capacity event retention failed", zap.Error(err))
				continue
			}
			if n > 0 {
				logger.Info("capacity event retention completed", zap.Int64("deleted", n), zap.Int("batch_size", settings.batch))
			}
		}
	}
}
