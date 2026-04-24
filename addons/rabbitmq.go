package addons

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"

	amqp "github.com/rabbitmq/amqp091-go"
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

	db, ok := Postgres(app)
	if !ok {
		return fmt.Errorf("postgres addon is not available")
	}

	conn, err := amqp.Dial(brokerURL)
	if err != nil {
		return fmt.Errorf("connect rabbitmq: %w", err)
	}

	logger, _ := Logger(app)

	if err := message.RegisterAllConsumers(conn, db, logger); err != nil {
		_ = conn.Close()
		return fmt.Errorf("register consumers: %w", err)
	}

	app.SetResource("rabbitmq", conn)
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

