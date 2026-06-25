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
	// RabbitMQ(app) returns (nil, true) when the broker was unreachable at
	// boot (typed-nil resource), so `ok` alone is NOT enough — guard the
	// nil conn explicitly. Without this the runner would call
	// ExecuteIntegration(ctx, nil, ...) → conn.Channel() on a nil
	// *amqp.Connection → panic, crashing the whole process.
	conn, ok := RabbitMQ(app)
	if !ok || conn == nil {
		return nil
	}
	logger, _ := Logger(app)
	interval := externalIdentityResyncInterval()
	if interval == 0 {
		return nil
	}

	// brokerLive is re-evaluated per tick so a runtime broker drop (the conn
	// closes after a healthy boot) also skips the tick instead of dispatching
	// through a dead connection. Mirrors the reactor Runner's BrokerAvailable.
	brokerAvailable := func() bool { return brokerLive(conn) }

	stop := make(chan struct{})
	go runExternalIdentityResync(ctx, db, conn, brokerAvailable, logger, interval, stop)

	app.RegisterCloser(func(context.Context) error {
		close(stop)
		return nil
	})
	return nil
}

func runExternalIdentityResync(ctx context.Context, db *sql.DB, conn *amqp.Connection, brokerAvailable func() bool, logger *zap.Logger, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// runTick gates every pass on broker liveness. ResyncTick fans out to
	// ExecuteIntegration (which calls conn.Channel()); dispatching through a
	// nil or closed connection panics. Skipping leaves nothing half-done —
	// drift is observed-only and re-detected on the next live tick.
	runTick := func(phase string) {
		if brokerAvailable != nil && !brokerAvailable() {
			if logger != nil {
				logger.Warn("external_identity_resync: broker unavailable — skipping tick",
					zap.String("phase", phase))
			}
			return
		}
		if _, err := externalidentity.ResyncTick(ctx, db, conn); err != nil && logger != nil {
			logger.Warn("external_identity_resync tick failed",
				zap.String("phase", phase), zap.Error(err))
		}
	}

	runTick("initial")

	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			runTick("ticker")
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
