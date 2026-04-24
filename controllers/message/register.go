package message

import (
	"database/sql"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/rpc"
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
	consumers := append(manifestConsumers(conn, db, logger), identityConsumers(conn, db, logger)...)
	consumers = append(consumers, integrationConsumers(conn, db, logger)...)
	consumers = append(consumers, topologyConsumers(conn, db, logger)...)
	consumers = append(consumers, productConsumers(conn, db, logger)...)
	consumers = append(consumers, workflowConsumers(conn, db, logger)...)
	consumers = append(consumers, eventStreamConsumers(conn, db, logger)...)

	for _, cfg := range consumers {
		if _, err := transport.Consume(cfg.toRPC()); err != nil {
			return fmt.Errorf("subscribe %s: %w", cfg.Queue, err)
		}
	}
	return nil
}
