package addons

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/brokersession"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"

	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

func init() {
	Register("rabbitmq", bootstrapRabbitMQ, 20)
}

func bootstrapRabbitMQ(ctx context.Context, app *runtime.ServiceApp) error {
	brokerURL := os.Getenv("BROKER_URL")
	lockPaused := workflowDispatchLockPaused()
	if brokerURL == "" {
		if lockPaused {
			return fmt.Errorf("workflow dispatch lock requires BROKER_URL so paused queues can be verified")
		}
		return nil
	}
	logger, _ := Logger(app)
	report := func(err error) { reportBrokerSessionFailure(logger, err) }
	factory := func(parent context.Context) (*brokersession.Session, error) {
		attempt, cancel := context.WithTimeout(parent, 15*time.Second)
		defer cancel()
		conn, err := dialBrokerSession(attempt, brokerURL)
		if err != nil {
			return nil, brokerDialError{err}
		}
		// Cancellation also bounds queue/consumer setup after the handshake.
		interrupt := context.AfterFunc(attempt, func() { _ = conn.CloseDeadline(time.Now().Add(time.Second)) })
		defer interrupt()
		db, ok := Postgres(app)
		if !ok {
			_ = conn.CloseDeadline(time.Now().Add(time.Second))
			return nil, fmt.Errorf("postgres addon is not available")
		}
		if lockPaused {
			if err := requireDispatchLockQueues(conn, message.DispatchLockPausedQueues()); err != nil {
				_ = conn.CloseDeadline(time.Now().Add(time.Second))
				return nil, err
			}
		}
		// One owner reconnects the session. The SDK transport deliberately has
		// no second connection watchdog and never replays an outbound request.
		transport := rpcamqp.New(conn)
		closed := conn.NotifyClose(make(chan *amqp.Error, 1))
		// The owner closes the socket before cancelling delivery contexts. The
		// pinned SDK settles handler errors with Nack(false); parent shutdown
		// must not cause that settlement on a still-live socket.
		sessionCtx, cancelSession := context.WithCancel(context.WithoutCancel(parent))
		var stopConsumers func()
		stopMonitor := func() {}
		session := &brokersession.Session{Connection: conn, Transport: transport, Closed: closed,
			Live: func() bool { return !conn.IsClosed() },
			Close: func() {
				// Monitor cancellation is independent of delivery cancellation.
				// Stop consumers closes its gate and socket before cancelling
				// handlers, preventing SDK settlement on a still-live connection.
				monitorStopped := make(chan struct{})
				go func() { stopMonitor(); close(monitorStopped) }()
				if stopConsumers != nil {
					stopConsumers()
				} else {
					_ = conn.CloseDeadline(time.Now().Add(time.Second))
				}
				cancelSession()
				_ = transport.Close()
				<-monitorStopped
			}}
		stopConsumers, err = message.RegisterAllConsumersWithContext(sessionCtx, transport, conn, db, logger)
		if err != nil {
			// Return partial ownership so the same supervised drain deadline
			// covers handlers already running during failed registration.
			return session, fmt.Errorf("register consumers: %w", err)
		}
		if attempt.Err() != nil || conn.IsClosed() {
			return session, fmt.Errorf("broker session closed during consumer registration")
		}
		stopMonitor = message.StartIntegrationRuntimeMonitorWithContext(sessionCtx, conn, db, logger, integrationRuntimeMonitorInterval())
		return session, nil
	}
	initial, err := factory(ctx)
	if err != nil {
		if initial != nil {
			brokersession.Drain(initial, report)
		}
		var dialError brokerDialError
		if lockPaused || !errors.As(err, &dialError) {
			return err
		}
		report(err)
	}
	changed := func(session *brokersession.Session) {
		var conn *amqp.Connection
		var transport rpc.Transport
		if session != nil {
			conn, transport = session.Connection, session.Transport
		}
		app.SetResource("rabbitmq", conn)
		app.SetResource("rpc_transport", transport)
	}
	manager := brokersession.Start(ctx, initial, factory, changed, report)
	app.SetResource("rabbitmq_session", manager)
	if initial == nil {
		changed(nil)
	}
	app.RegisterCloser(manager.Shutdown)
	return nil
}

func reportBrokerSessionFailure(logger *zap.Logger, err error) {
	if logger != nil {
		// Do not log BROKER_URL or credential-bearing dial errors.
		fields := []zap.Field{zap.String("error_class", fmt.Sprintf("%T", err))}
		var brokerError *amqp.Error
		if errors.As(err, &brokerError) {
			fields = append(fields, zap.Int("amqp_code", brokerError.Code))
		}
		if errors.Is(err, brokersession.ErrDrainDeadline) {
			logger.Error("rabbitmq session drain exceeded deadline; replacement withheld", fields...)
			return
		}
		logger.Warn("rabbitmq session unavailable; reconnecting without replay", fields...)
	}
}

type brokerDialError struct{ error }

// dialBrokerSession bounds both TCP/TLS and the AMQP handshake and cancels
// an in-progress handshake on shutdown. The library clears its deadline once
// negotiation succeeds; the live connection continues with normal heartbeats.
func dialBrokerSession(ctx context.Context, brokerURL string) (*amqp.Connection, error) {
	return dialBrokerSessionUsing(ctx, brokerURL, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
}

func dialBrokerSessionUsing(ctx context.Context, brokerURL string, dial func(context.Context, string, string) (net.Conn, error)) (*amqp.Connection, error) {
	var stop func() bool
	var socket net.Conn
	conn, err := amqp.DialConfig(brokerURL, amqp.Config{Dial: func(network, address string) (net.Conn, error) {
		raw, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		socket = raw
		deadline := time.Now().Add(10 * time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err = raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, err
		}
		stop = context.AfterFunc(ctx, func() { _ = raw.Close() })
		return raw, nil
	}})
	if stop != nil {
		stop()
	}
	if err != nil {
		// Open can return a non-nil, incompletely negotiated connection with
		// an error (for example incompatible SASL). Retire its raw socket and
		// reader before another dial, without waiting for protocol shutdown.
		if socket != nil {
			_ = socket.Close()
		}
		if conn != nil {
			_ = conn.CloseDeadline(time.Now())
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if ctx.Err() != nil {
		if conn != nil {
			_ = conn.CloseDeadline(time.Now().Add(time.Second))
		}
		return nil, ctx.Err()
	}
	return conn, err
}

type passiveQueueDeclarer interface {
	QueueDeclarePassive(name string, durable, autoDelete, exclusive, noWait bool, args amqp.Table) (amqp.Queue, error)
}

func requireDispatchLockQueues(conn *amqp.Connection, queues []string) error {
	channel, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("verify dispatch-lock queues: open channel: %w", err)
	}
	defer channel.Close()

	return requireDispatchLockQueuesOnChannel(channel, queues)
}

func requireDispatchLockQueuesOnChannel(channel passiveQueueDeclarer, queues []string) error {
	for _, queue := range queues {
		if _, err := channel.QueueDeclarePassive(queue, true, false, false, false, nil); err != nil {
			return fmt.Errorf("verify dispatch-lock queue %q: %w", queue, err)
		}
	}
	return nil
}

// RabbitMQ returns the current fully registered session's connection. During
// boot degradation, recovery, drain or shutdown it returns (nil, true). Callers
// obtain one snapshot per operation and check brokerLive; they must not cache it
// across operations or retry an ambiguous operation after a session change.
func RabbitMQ(app *runtime.ServiceApp) (*amqp.Connection, bool) {
	if raw, ok := app.Resource("rabbitmq_session"); ok {
		if manager, ok := raw.(*brokersession.Manager); ok {
			return manager.Connection(), true
		}
	}
	resource, ok := app.Resource("rabbitmq")
	if !ok {
		return nil, false
	}

	conn, ok := resource.(*amqp.Connection)
	return conn, ok
}

// brokerLive reports whether the AMQP connection is usable right now: it must
// be non-nil AND not closed. This is the single canonical gate every addon
// background loop checks immediately before dispatching through the broker.
//
// It covers BOTH failure modes in one expression:
//   - boot-degraded: the broker was unreachable at boot, so the resource holds
//     a typed-nil *amqp.Connection (conn == nil).
//   - runtime-drop:  the broker was live at boot but the connection later
//     closed (conn != nil but conn.IsClosed()).
//
// The `conn != nil` guard short-circuits before conn.IsClosed(), which would
// itself panic on a nil receiver (it reads atomic state on the struct).
//
// Mirrors the reactor Runner's BrokerAvailable gate; when false the caller
// must SKIP — leaving DB rows / schedule state / events pending for replay
// after the broker recovers — never mark the work failed and never consume it.
func brokerLive(conn *amqp.Connection) bool {
	return conn != nil && !conn.IsClosed()
}

// RPCTransport returns the generic rpc.Transport when the addon is
// installed. Handlers that have migrated off the amqp-specific types
// call this; the raw RabbitMQ() accessor remains available for
// handlers mid-migration.
func RPCTransport(app *runtime.ServiceApp) (rpc.Transport, bool) {
	if raw, ok := app.Resource("rabbitmq_session"); ok {
		if manager, ok := raw.(*brokersession.Manager); ok {
			return manager.Transport(), true
		}
	}
	resource, ok := app.Resource("rpc_transport")
	if !ok {
		return nil, false
	}
	transport, ok := resource.(rpc.Transport)
	return transport, ok
}

func integrationRuntimeMonitorInterval() time.Duration {
	raw := os.Getenv("INTEGRATION_RUNTIME_MONITOR_INTERVAL_SECONDS")
	if raw == "" {
		return 60 * time.Second
	}

	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 {
		return 60 * time.Second
	}

	return time.Duration(seconds) * time.Second
}
