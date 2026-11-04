//go:build nativequalification

package capacityqualification

import (
	"context"
	"errors"
	"net"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// DedicatedBroker owns a separate fixture-only connection and its socket.
type DedicatedBroker struct {
	Connection *amqp.Connection
	socket     net.Conn
}

var errQualificationBrokerDeadline = errors.New("qualification broker close deadline exceeded")

// DialDedicated refuses every destination except the owning CI's fixed broker.
func DialDedicated(ctx context.Context, address string) (*DedicatedBroker, error) {
	if address != "amqp://native:native-ci-only@127.0.0.1:5672/" {
		return nil, errors.New("original qualification broker required")
	}
	return dialDedicated(ctx, address, nil)
}

func dialDedicated(ctx context.Context, address string, dial func(context.Context, string, string) (net.Conn, error)) (*DedicatedBroker, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("original qualification context required")
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	var socket net.Conn
	connection, err := amqp.DialConfig(address, amqp.Config{Dial: func(network, address string) (net.Conn, error) {
		var dialErr error
		socket, dialErr = dial(ctx, network, address)
		if dialErr == nil {
			deadline := time.Now().Add(5 * time.Second)
			if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
				deadline = parent
			}
			dialErr = socket.SetDeadline(deadline)
			if dialErr != nil {
				_ = socket.Close()
			}
		}
		return socket, dialErr
	}})
	if err != nil {
		if socket != nil {
			_ = socket.Close()
		}
		return nil, err
	}
	return &DedicatedBroker{Connection: connection, socket: socket}, nil
}

func (b *DedicatedBroker) guard(ctx context.Context, limit time.Duration) (func() error, error) {
	if b == nil || b.Connection == nil || b.socket == nil || ctx == nil || limit <= 0 {
		return nil, errors.New("qualification broker scope required")
	}
	stop, guardDone := make(chan struct{}), make(chan error, 1)
	go func() {
		timer := time.NewTimer(limit)
		defer timer.Stop()
		select {
		case <-stop:
			guardDone <- nil
		case <-ctx.Done():
			_ = b.socket.Close()
			guardDone <- errors.New("original qualification close context expired")
		case <-timer.C:
			_ = b.socket.Close()
			guardDone <- errQualificationBrokerDeadline
		}
	}()
	return func() error { close(stop); guardErr := <-guardDone; return errors.Join(guardErr, ctx.Err()) }, nil
}

// StartWith fences channel, QoS, consume and their cleanup with the same
// socket ownership; returning always joins the guard.
func (b *DedicatedBroker) StartWith(ctx context.Context, limit time.Duration, start func() (func() error, error)) (func() error, error) {
	if start == nil {
		return nil, errors.New("qualification startup required")
	}
	stop, err := b.guard(ctx, limit)
	if err != nil {
		return nil, err
	}
	closeConsumers, startErr := start()
	guardErr := stop()
	return closeConsumers, errors.Join(startErr, guardErr)
}

// CloseWith joins consumers, connection and deadline guard. Forced socket
// closure always reports failure; local handlers must still really return.
func (b *DedicatedBroker) CloseWith(ctx context.Context, limit time.Duration, closeConsumers func() error) error {
	stop, err := b.guard(ctx, limit)
	if err != nil {
		return err
	}
	var consumersErr error
	if closeConsumers != nil {
		consumersErr = closeConsumers()
	}
	closeErr := b.Connection.Close()
	socketErr := b.socket.Close()
	if errors.Is(socketErr, net.ErrClosed) {
		socketErr = nil
	}
	return errors.Join(consumersErr, closeErr, socketErr, stop())
}
