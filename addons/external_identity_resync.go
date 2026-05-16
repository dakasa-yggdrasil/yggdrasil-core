package addons

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("external_identity_resync", bootstrapExternalIdentityResync, 85)
}

// bootstrapExternalIdentityResync schedules a periodic re-sync that
// detects drift between yggdrasil-core's stored external identities and
// what each integration instance reports via list_identities. Drift is
// observed-only; nothing is auto-mutated.
//
// Tunable via YGGDRASIL_EXTERNAL_IDENTITY_RESYNC_INTERVAL (default 4h).
// Setting "0" disables the ticker (used in tests).
func bootstrapExternalIdentityResync(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		return nil
	}
	conn, ok := RabbitMQ(app)
	if !ok {
		return nil
	}
	logger, _ := Logger(app)
	interval := externalIdentityResyncInterval()
	if interval == 0 {
		return nil
	}

	stop := make(chan struct{})
	go runExternalIdentityResync(ctx, db, conn, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})
	return nil
}

func runExternalIdentityResync(ctx context.Context, db *sql.DB, conn *amqp.Connection, logger *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if _, err := externalidentity.ResyncTick(ctx, db, conn); err != nil && logger != nil {
		logger.Warn("external_identity_resync initial tick failed", zap.Error(err))
	}

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := externalidentity.ResyncTick(ctx, db, conn); err != nil && logger != nil {
				logger.Warn("external_identity_resync tick failed", zap.Error(err))
			}
		}
	}
}

func externalIdentityResyncInterval() time.Duration {
	raw := os.Getenv("YGGDRASIL_EXTERNAL_IDENTITY_RESYNC_INTERVAL")
	if raw == "" {
		return 4 * time.Hour
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
	return 4 * time.Hour
}
