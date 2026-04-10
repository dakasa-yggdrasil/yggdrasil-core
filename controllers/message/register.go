package message

import (
	"database/sql"

	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

// RegisterAllConsumers declares the core RPC queues and starts the consumers.
func RegisterAllConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) error {
	ch, err := conn.Channel()
	if err != nil {
		return err
	}

	consumers := append(manifestConsumers(conn, db, logger), identityConsumers(conn, db, logger)...)
	consumers = append(consumers, integrationConsumers(conn, db, logger)...)
	consumers = append(consumers, topologyConsumers(conn, db, logger)...)
	consumers = append(consumers, productConsumers(conn, db, logger)...)
	consumers = append(consumers, workflowConsumers(conn, db, logger)...)
	consumers = append(consumers, eventStreamConsumers(conn, db, logger)...)
	for _, cfg := range consumers {
		if _, err := ch.QueueDeclare(cfg.Queue, true, false, false, false, nil); err != nil {
			_ = ch.Close()
			return err
		}

		if err := consumeQueue(ch, cfg); err != nil {
			_ = ch.Close()
			return err
		}
	}

	return nil
}
