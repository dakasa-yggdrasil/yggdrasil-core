package message

import (
	"context"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ConsumerHandler processes one delivery.
//
// NOTE — RPC abstraction migration in progress.
// The transport-level abstraction is in internal/rpc. Handlers in
// this package still accept amqp.Delivery directly so the 20+
// existing handler files (~14k LOC) can migrate incrementally
// without breaking the build. See addons/rabbitmq.go and
// internal/rpc/amqp/ for the transport wrapping the core exposes
// to adopters today.
type ConsumerHandler func(ctx context.Context, d amqp.Delivery) error

// ConsumerConfig declares a single queue consumer.
type ConsumerConfig struct {
	Queue   string
	Handler ConsumerHandler
	Timeout time.Duration
	QoS     int
}

func consumeQueue(ch *amqp.Channel, cfg ConsumerConfig) error {
	if cfg.QoS > 0 {
		if err := ch.Qos(cfg.QoS, 0, false); err != nil {
			return err
		}
	}

	deliveries, err := ch.Consume(cfg.Queue, "", false, false, false, false, nil)
	if err != nil {
		return err
	}

	go func() {
		for d := range deliveries {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
			err := cfg.Handler(ctx, d)
			cancel()

			if err != nil {
				_ = d.Nack(false, false)
				continue
			}
			_ = d.Ack(false)
		}
	}()

	return nil
}
