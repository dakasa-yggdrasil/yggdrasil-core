//go:build integration

package brokersession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
	amqp "github.com/rabbitmq/amqp091-go"
)

// This test is operated manually against an isolated local broker. It never
// defaults to BROKER_URL, resolves a hostname, invokes broker controls, or uses
// a business consumer/database. The operator closes the logged connection with
// code320 after the FORCE_CLOSE_320 marker; the test validates the replacement.
func TestLocalBrokerSessionRecovery320(t *testing.T) {
	brokerURL := os.Getenv("CORE_AMQP_INTEGRATION_URL")
	if err := loopbackBrokerURL(brokerURL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	name := "core-session-harness-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	endpoint := name + ".echo"
	var generations, active, ambiguous atomic.Int32
	ready := make(chan *Session, 4)
	received := make(chan string, 4)
	canceledHandler := make(chan struct{}, 1)
	releaseDrain := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseDrain) }) }
	defer release()
	errorsSeen := make(chan error, 8)
	factory := func(parent context.Context) (*Session, error) {
		generation := generations.Add(1)
		connectionName := fmt.Sprintf("%s-generation-%d", name, generation)
		conn, err := amqp.DialConfig(brokerURL, amqp.Config{
			Properties: amqp.Table{"connection_name": connectionName},
			Dial: func(network, address string) (net.Conn, error) {
				raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(parent, network, address)
				if err == nil {
					err = raw.SetDeadline(time.Now().Add(5 * time.Second))
					if err != nil {
						_ = raw.Close()
					}
				}
				return raw, err
			},
		})
		if err != nil {
			return nil, err
		}
		transport := rpcamqp.New(conn)
		sessionCtx, stop := context.WithCancel(context.WithoutCancel(parent))
		if !active.CompareAndSwap(0, 1) {
			stop()
			_ = conn.Close()
			_ = transport.Close()
			return nil, errors.New("overlapping consumer generations")
		}
		stopConsumers, err := RegisterConsumers(sessionCtx, transport, []rpc.ConsumerConfig{{
			Endpoint: endpoint, Concurrency: 1, Timeout: 90 * time.Second,
			Handler: func(handlerCtx context.Context, delivery rpc.Delivery) error {
				if string(delivery.Body) == "ambiguous-original" {
					ambiguous.Add(1)
					// This models an operation accepted exactly once whose reply is
					// lost. Ack first excludes broker redelivery from this test of
					// outbound replay; production delivery settlement is unchanged.
					if err := delivery.Ack(); err != nil {
						return err
					}
					received <- "ambiguous-original"
					<-handlerCtx.Done()
					canceledHandler <- struct{}{}
					<-releaseDrain
					return handlerCtx.Err()
				}
				if delivery.ReplyTo != "" {
					if err := delivery.Reply(handlerCtx, delivery.Body, "text/plain"); err != nil {
						return err
					}
				}
				if err := delivery.Ack(); err != nil {
					return err
				}
				received <- string(delivery.Body)
				return nil
			},
		}}, func() { _ = conn.CloseDeadline(time.Now().Add(time.Second)) })
		if err != nil {
			if stopConsumers != nil {
				stopConsumers()
			} else {
				_ = conn.CloseDeadline(time.Now().Add(time.Second))
			}
			stop()
			_ = transport.Close()
			active.Store(0)
			return nil, err
		}
		return &Session{Connection: conn, Transport: transport,
			Closed: conn.NotifyClose(make(chan *amqp.Error, 1)), Live: func() bool { return !conn.IsClosed() },
			Close: func() {
				stopConsumers()
				stop()
				_ = transport.Close()
				active.Store(0)
			}}, nil
	}
	initial, err := factory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := Start(ctx, initial, factory, func(s *Session) {
		if s != nil {
			ready <- s
		}
	}, func(err error) { errorsSeen <- err })
	defer func() {
		release()
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := m.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}()
	waitEvent := func(ch <-chan string, want string) {
		t.Helper()
		select {
		case got := <-ch:
			if got != want {
				t.Fatalf("delivery=%q want=%q", got, want)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	request := func(body string) {
		t.Helper()
		op, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		reply, err := m.Transport().Request(op, rpc.Request{Endpoint: endpoint, Body: []byte(body)})
		if err != nil || string(reply.Body) != body {
			t.Fatalf("request %s: reply=%q error=%v", body, reply.Body, err)
		}
		waitEvent(received, body)
	}
	<-ready
	request("before")
	if err := m.Transport().Publish(ctx, rpc.Request{Endpoint: endpoint, Body: []byte("publish-before")}); err != nil {
		t.Fatal(err)
	}
	waitEvent(received, "publish-before")
	unknown := make(chan error, 1)
	go func() {
		_, err := initial.Transport.Request(ctx, rpc.Request{Endpoint: endpoint, Body: []byte("ambiguous-original")})
		unknown <- err
	}()
	waitEvent(received, "ambiguous-original")
	t.Logf("FORCE_CLOSE_320 connection_name=%s-generation-1", name)
	select {
	case <-canceledHandler:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if m.Connection() != nil || m.Transport() != nil {
		t.Fatal("retired generation remained available during drain")
	}
	// Exceed the normal reconnect backoff while retaining the old handler.
	time.Sleep(1200 * time.Millisecond)
	if generations.Load() != 1 || active.Load() != 1 {
		t.Fatal("replacement started before old handler drained")
	}
	release()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if m.Connection() == initial.Connection || generations.Load() != 2 {
		t.Fatal("connection was not replaced exactly once")
	}
	select {
	case err := <-unknown:
		if err == nil {
			t.Fatal("lost reply became a success")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	request("after")
	if err := m.Transport().Publish(ctx, rpc.Request{Endpoint: endpoint, Body: []byte("publish-after")}); err != nil {
		t.Fatal(err)
	}
	waitEvent(received, "publish-after")
	if ambiguous.Load() != 1 {
		t.Fatalf("ambiguous request replayed %d times", ambiguous.Load())
	}
	select {
	case err := <-errorsSeen:
		var closeError *amqp.Error
		if !errors.As(err, &closeError) || closeError.Code != 320 {
			t.Fatalf("expected original broker close320, got %v", err)
		}
	default:
		t.Fatal("original broker close was not observed")
	}
	// Delete only the unique harness queue while the second session is live.
	channel, err := m.Connection().Channel()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.QueueDelete(endpoint, false, false, false); err != nil {
		t.Fatal(err)
	}
	_ = channel.Close()
	t.Log("RECOVERY_320_PASSED: request/consumption before+after, unavailable during drain, one generation, no ambiguous-request replay")
}

func loopbackBrokerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return errors.New("CORE_AMQP_INTEGRATION_URL is required")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "amqp" || ip == nil || !ip.IsLoopback() || u.Port() == "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("integration broker must be an explicit numeric loopback AMQP URL and port")
	}
	return nil
}

func TestLocalBrokerURLRequiresExplicitNumericLoopback(t *testing.T) {
	for _, raw := range []string{"", "amqp://guest:guest@localhost:25679/", "amqp://192.0.2.1:5672/", "amqp://127.0.0.1/", "https://127.0.0.1:25679/", "amqp://127.0.0.1:25679/?target=other"} {
		if loopbackBrokerURL(raw) == nil {
			t.Fatalf("unsafe or implicit test URL accepted: %q", raw)
		}
	}
	for _, raw := range []string{"amqp://guest:guest@127.0.0.1:25679/", "amqp://guest:guest@[::1]:25679/"} {
		if err := loopbackBrokerURL(raw); err != nil {
			t.Fatalf("literal loopback rejected: %v", err)
		}
	}
}
