package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
)

const queueEventStreamPull = "yggdrasil-core.event_stream.pull"

func eventStreamConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueEventStreamPull,
			Timeout: 10 * time.Second,
			QoS:     20,
			Handler: eventStreamPullHandler(conn, db, logger),
		},
	}
}

func eventStreamPullHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.PullEventsRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		resp, err := repository.PullEvents(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, "pull_failed", err, logger)
		}

		return replySuccess(ctx, d, resp, logger)
	}
}
