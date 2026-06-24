package addons

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"

	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("rabbitmq", bootstrapRabbitMQ, 20)
}

func bootstrapRabbitMQ(ctx context.Context, app *runtime.ServiceApp) error {
	brokerURL := os.Getenv("BROKER_URL")
	if brokerURL == "" {
		logger, _ := Logger(app)
		if logger != nil {
			logger.Info("rabbitmq addon skipped because BROKER_URL is not set")
		}
		return nil
	}

	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		logger, _ := Logger(app)
		if logger != nil {
			logger.Warn("rabbitmq unreachable at boot; starting broker-degraded (IdP/auth + wake only, workflow dispatch disabled)",
				zap.String("broker_url", brokerURL), zap.Error(err))
		}
		app.SetResource("rabbitmq", (*amqp.Connection)(nil))
		app.SetResource("rpc_transport", nil)
		return nil
	}

	db, ok := Postgres(app)
	if !ok {
		_ = conn.Close()
		return fmt.Errorf("postgres addon is not available")
	}

	logger, _ := Logger(app)

	// Broker connectivity lost. We DO NOT exit: the IdP/auth and wake
	// paths do not need the broker, so the process stays up and serves
	// them. The workflow/event path degrades (returns 503) via
	// Server.isBrokerAvailable() until the connection is restored.
	connClose := conn.NotifyClose(make(chan *amqp.Error, 1))
	go func() {
		amqpErr, ok := <-connClose
		if logger != nil {
			if ok && amqpErr != nil {
				logger.Error(
					"rabbitmq connection lost; workflow dispatch degraded (process stays up)",
					zap.Int("code", amqpErr.Code),
					zap.String("reason", amqpErr.Reason),
					zap.Bool("recover", amqpErr.Recover),
					zap.Bool("server", amqpErr.Server),
				)
			} else {
				logger.Error("rabbitmq connection lost; workflow dispatch degraded (process stays up)")
			}
		}
	}()

	// Construct the generic rpc.Transport first. Consumers subscribe
	// through it; the raw amqp connection stays available so handlers
	// that still do direct outbound publishes (resolveIntegrationInstance,
	// dispatchWorkflowThroughIntegration, etc.) keep working during
	// the migration.
	rpcTransport := rpcamqp.New(conn)

	if err := message.RegisterAllConsumers(rpcTransport, conn, db, logger); err != nil {
		_ = conn.Close()
		return fmt.Errorf("register consumers: %w", err)
	}

	app.SetResource("rabbitmq", conn)
	app.SetResource("rpc_transport", rpcTransport)
	app.RegisterCloser(func(context.Context) error { return conn.Close() })

	monitorInterval := integrationRuntimeMonitorInterval()
	stopMonitor := message.StartIntegrationRuntimeMonitor(conn, db, logger, monitorInterval)
	app.RegisterCloser(func(context.Context) error {
		stopMonitor()
		return nil
	})

	// The Heimdall closed-loop guardian sweep used to live here. It
	// moved to the separate integration-heimdall repo (commercial
	// product). The core keeps the guardian_* / remediation_*
	// manifest kinds and their CRUD endpoints; any guardian
	// integration (Heimdall or a custom one) subscribes to the
	// event stream and runs its own sweep loop.

	return nil
}

// RabbitMQ returns the shared RabbitMQ connection when the addon is installed.
func RabbitMQ(app *runtime.ServiceApp) (*amqp.Connection, bool) {
	resource, ok := app.Resource("rabbitmq")
	if !ok {
		return nil, false
	}

	conn, ok := resource.(*amqp.Connection)
	return conn, ok
}

// RPCTransport returns the generic rpc.Transport when the addon is
// installed. Handlers that have migrated off the amqp-specific types
// call this; the raw RabbitMQ() accessor remains available for
// handlers mid-migration.
func RPCTransport(app *runtime.ServiceApp) (rpc.Transport, bool) {
	resource, ok := app.Resource("rpc_transport")
	if !ok {
		return nil, false
	}
	transport, ok := resource.(rpc.Transport)
	return transport, ok
}

func integrationRuntimeMonitorInterval() time.Duration {
	raw := os.Getenv("INTEGRATION_RUNTIME_MONITOR_INTERVAL_SECONDS")
	if raw == "" {
		return 60 * time.Second
	}

	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 60 * time.Second
	}

	return time.Duration(seconds) * time.Second
}

