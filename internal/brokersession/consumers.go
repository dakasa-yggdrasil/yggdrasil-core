package brokersession

import (
	"context"
	"fmt"
	"sync"

	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
)

// RegisterConsumers binds endpoints to one broker session. stopDrain closes the
// handler admission gate, closes the connection, cancels active handlers, closes
// subscriptions and waits for admitted handlers to finish. closeConnection must
// return only after the connection is closed: a handler error on an open socket
// can cause the transport to discard the delivery. External context cancellation
// is handled by the session owner through stopDrain, never ahead of socket close.
// The caller must invoke a non-nil stopDrain on success OR error. Cleanup is
// returned, rather than run here, so its owner can report a drain deadline while
// still waiting for the old session. This function never retries or settles
// deliveries.
func RegisterConsumers(ctx context.Context, transport rpc.Transport, consumers []rpc.ConsumerConfig, closeConnection func()) (func(), error) {
	if closeConnection == nil {
		return nil, fmt.Errorf("consumer session requires connection close callback")
	}
	sessionCtx, cancelSession := context.WithCancel(context.WithoutCancel(ctx))
	var gate sync.Mutex
	var stopped bool
	var active sync.WaitGroup
	var stopOnce sync.Once
	var subscriptions []rpc.Subscription
	stopDrain := func() {
		stopOnce.Do(func() {
			gate.Lock()
			stopped = true
			// A concurrent delivery must not even return ErrClosed until
			// socket close finishes, because the SDK settles handler errors.
			closeConnection()
			cancelSession()
			gate.Unlock()
			for _, subscription := range subscriptions {
				_ = subscription.Close()
			}
			active.Wait()
		})
	}
	for _, cfg := range consumers {
		rpcConfig := cfg
		handler := rpcConfig.Handler
		if handler == nil {
			return stopDrain, fmt.Errorf("subscribe %s: handler is required", cfg.Endpoint)
		}
		rpcConfig.Handler = func(ctx context.Context, delivery rpc.Delivery) error {
			gate.Lock()
			if stopped || sessionCtx.Err() != nil {
				gate.Unlock()
				return rpc.ErrClosed
			}
			active.Add(1)
			gate.Unlock()
			defer active.Done()

			// Keep the delivery's values and deadline while adding session
			// cancellation. The SDK creates its delivery contexts independently.
			handlerCtx, cancel := context.WithCancel(ctx)
			stopSessionCancel := context.AfterFunc(sessionCtx, cancel)
			defer stopSessionCancel()
			defer cancel()
			if sessionCtx.Err() != nil {
				cancel()
			}
			return handler(handlerCtx, delivery)
		}
		subscription, err := transport.Consume(rpcConfig)
		if subscription != nil {
			subscriptions = append(subscriptions, subscription)
		}
		if err != nil {
			return stopDrain, fmt.Errorf("subscribe %s: %w", cfg.Endpoint, err)
		}
	}
	return stopDrain, nil
}
