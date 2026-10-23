package message

import (
	"context"

	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
	amqp "github.com/rabbitmq/amqp091-go"
)

// sessionAMQPTransport takes one connection snapshot without reconnecting. The
// SDK's legacy New(nil) path dereferences nil on Request/Publish; returning a
// closed transport preserves an ordinary unavailable result during session loss.
// HTTP adapters keep their separate transport and do not depend on this handle.
func sessionAMQPTransport(conn *amqp.Connection) rpc.Transport {
	if conn == nil || conn.IsClosed() {
		return closedSessionAMQPTransport{}
	}
	return rpcamqp.New(conn)
}

type closedSessionAMQPTransport struct{}

func (closedSessionAMQPTransport) Consume(rpc.ConsumerConfig) (rpc.Subscription, error) {
	return nil, rpc.ErrClosed
}
func (closedSessionAMQPTransport) Request(context.Context, rpc.Request) (rpc.Reply, error) {
	return rpc.Reply{}, rpc.ErrClosed
}
func (closedSessionAMQPTransport) Publish(context.Context, rpc.Request) error { return rpc.ErrClosed }
func (closedSessionAMQPTransport) Close() error                               { return nil }
