package message

import (
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/rpc"
)

// ConsumerHandler is the transport-agnostic handler signature. It is
// an alias of rpc.Handler so every handler in this package binds
// naturally regardless of which rpc.Transport implementation
// delivered the message (AMQP, HTTP, gRPC, Kafka, …).
type ConsumerHandler = rpc.Handler

// ConsumerConfig declares one consumer registration in the shape the
// existing handler lists use. "Queue" maps to the rpc endpoint,
// "QoS" maps to rpc concurrency. RegisterAllConsumers converts each
// entry to rpc.ConsumerConfig before subscribing through the active
// rpc.Transport.
type ConsumerConfig struct {
	Queue   string
	Handler ConsumerHandler
	Timeout time.Duration
	QoS     int
}

// toRPC returns the rpc.ConsumerConfig equivalent for use with a
// transport. Transports without native concurrency knobs simulate
// QoS via a worker pool of matching size.
func (c ConsumerConfig) toRPC() rpc.ConsumerConfig {
	return rpc.ConsumerConfig{
		Endpoint:    c.Queue,
		Handler:     c.Handler,
		Timeout:     c.Timeout,
		Concurrency: c.QoS,
	}
}
