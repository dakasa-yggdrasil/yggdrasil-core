package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/reactors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("reactor-dispatcher", bootstrapReactorDispatcher, 70)
}

// bootstrapReactorDispatcher starts the reactor Runner that claims pending
// reactions and dispatches them to integration adapters via RabbitMQ.
//
// Controlled by:
//
//	REACTOR_RUNNER_INTERVAL     — poll cadence (e.g. "5s"). Default 5s.
//	REACTOR_RUNNER_BATCH_SIZE   — rows claimed per tick. Default 50.
//	REACTOR_RUNNER_PARALLELISM  — concurrent dispatches per tick. Default 10.
//	REACTOR_STUCK_THRESHOLD     — in-progress age before re-queuing. Default 10m.
func bootstrapReactorDispatcher(ctx context.Context, app *runtime.ServiceApp) error {
	db, ok := Postgres(app)
	if !ok {
		// Postgres addon not enabled — nothing to do.
		return nil
	}

	conn, ok := RabbitMQ(app)
	if !ok {
		// RabbitMQ addon not enabled — skip silently; the runner only makes
		// sense when there is a broker to dispatch through.
		return nil
	}

	logger, _ := Logger(app)

	runner := &reactors.Runner{
		DB:             db,
		Logger:         logger,
		Caller:         &rabbitmqReactorCaller{conn: conn, db: db},
		Interval:       envDurOrDefault("REACTOR_RUNNER_INTERVAL", 5*time.Second),
		BatchSize:      envIntOrDefault("REACTOR_RUNNER_BATCH_SIZE", 50),
		Parallelism:    envIntOrDefault("REACTOR_RUNNER_PARALLELISM", 10),
		StuckThreshold: envDurOrDefault("REACTOR_STUCK_THRESHOLD", 10*time.Minute),
	}

	go func() {
		if err := runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if logger != nil {
				logger.Error("reactor runner exited unexpectedly", zap.Error(err))
			}
		}
	}()

	if logger != nil {
		logger.Info("reactor dispatcher addon started",
			zap.Duration("interval", runner.Interval),
			zap.Int("batch_size", runner.BatchSize),
			zap.Int("parallelism", runner.Parallelism),
			zap.Duration("stuck_threshold", runner.StuckThreshold),
		)
	}
	return nil
}

// rabbitmqReactorCaller implements reactors.Caller by resolving the
// integration_instance manifest from DB and dispatching via the canonical
// message.ExecuteIntegration path (resolve → hydrate secrets → adapter RPC).
type rabbitmqReactorCaller struct {
	conn *amqp.Connection
	db   *sql.DB
}

// Call implements reactors.Caller.
//
// The payload produced by reactors.BuildReactorPayload is a JSON blob that the
// integration adapter expects as its execute "input".  We unmarshal it into a
// map so the existing AdapterExecuteIntegrationRequest.Input field carries it
// unmodified, then delegate to message.ExecuteIntegration which handles the
// full resolve → hydrate-secrets → transport-call chain.
func (c *rabbitmqReactorCaller) Call(
	ctx context.Context,
	integrationInstanceID string,
	capability string,
	payload []byte,
) error {
	var input map[string]any
	if err := json.Unmarshal(payload, &input); err != nil {
		return fmt.Errorf("decode reactor payload: %w", err)
	}

	req := model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{
			ManifestID: integrationInstanceID,
		},
		Operation:  capability,
		Capability: capability,
		Input:      input,
	}

	_, err := message.ExecuteIntegration(ctx, c.conn, c.db, req)
	return err
}

func envDurOrDefault(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func envIntOrDefault(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
