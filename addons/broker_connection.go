package addons

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	amqp "github.com/rabbitmq/amqp091-go"
)

type brokerConnectionContextKey struct{}

// Background loops retain their existing clocks and ownership. They resolve
// the live session for each new pass instead of retaining the boot connection.
func withBrokerConnection(ctx context.Context, app *runtime.ServiceApp) context.Context {
	return context.WithValue(ctx, brokerConnectionContextKey{}, func() *amqp.Connection {
		conn, _ := RabbitMQ(app)
		return conn
	})
}

func brokerConnectionFor(ctx context.Context, fallback *amqp.Connection) *amqp.Connection {
	if current, ok := ctx.Value(brokerConnectionContextKey{}).(func() *amqp.Connection); ok {
		return current()
	}
	return fallback
}
