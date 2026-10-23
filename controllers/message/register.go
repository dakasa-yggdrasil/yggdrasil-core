package message

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/brokersession"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

// RegisterAllConsumers subscribes every core RPC endpoint on the
// provided transport. The handler lists still take a raw
// *amqp.Connection for outbound calls (resolveIntegrationInstance,
// dispatchWorkflowThroughIntegration, etc.) — those migrate in
// follow-up commits. The inbound path (consume + ack/nack + reply)
// is fully transport-agnostic as of this refactor.
func RegisterAllConsumers(transport rpc.Transport, conn *amqp.Connection, db *sql.DB, logger *zap.Logger) error {
	cleanup, err := RegisterAllConsumersWithContext(context.Background(), transport, conn, db, logger)
	if err != nil && cleanup != nil {
		cleanup()
	}
	return err
}

// RegisterAllConsumersWithContext binds the consumers to one broker session.
// stopDrain prevents new handler starts, cancels active handler contexts, closes
// subscriptions and waits for the handlers to finish. It is safe to call more
// than once. It does not retry or settle deliveries on the caller's behalf.
// The caller must invoke a non-nil stopDrain even when registration returns an
// error; partial-registration cleanup belongs to the session's drain owner.
func RegisterAllConsumersWithContext(ctx context.Context, transport rpc.Transport, conn *amqp.Connection, db *sql.DB, logger *zap.Logger) (stopDrain func(), err error) {
	consumers := append(manifestConsumers(conn, db, logger), identityConsumers(conn, db, logger)...)
	consumers = append(consumers, integrationConsumers(conn, db, logger)...)
	consumers = append(consumers, topologyConsumers(conn, db, logger)...)
	consumers = append(consumers, productConsumers(conn, db, logger)...)
	consumers = append(consumers, workflowConsumers(conn, db, logger)...)
	consumers = append(consumers, eventStreamConsumers(conn, db, logger)...)
	rpcConsumers := make([]rpc.ConsumerConfig, 0, len(consumers))
	for _, consumer := range consumers {
		rpcConsumers = append(rpcConsumers, consumer.toRPC())
	}
	return brokersession.RegisterConsumers(ctx, transport, rpcConsumers, func() {
		if conn != nil && !conn.IsClosed() {
			_ = conn.CloseDeadline(time.Now().Add(time.Second))
		}
	})
}
