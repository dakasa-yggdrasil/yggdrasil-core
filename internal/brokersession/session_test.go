package brokersession

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	amqp "github.com/rabbitmq/amqp091-go"
)

type recordingTransport struct {
	publishes atomic.Int32
	requests  atomic.Int32
	err       error
}

func (*recordingTransport) Consume(rpc.ConsumerConfig) (rpc.Subscription, error) {
	panic("factory owns subscription setup")
}
func (r *recordingTransport) Publish(context.Context, rpc.Request) error {
	r.publishes.Add(1)
	return r.err
}
func (r *recordingTransport) Request(context.Context, rpc.Request) (rpc.Reply, error) {
	r.requests.Add(1)
	return rpc.Reply{}, r.err
}
func (*recordingTransport) Close() error { return nil }

type fixture struct {
	session *Session
	closed  chan *amqp.Error
	live    atomic.Bool
	closes  atomic.Int32
	rpc     *recordingTransport
}

func newFixture() *fixture {
	f := &fixture{closed: make(chan *amqp.Error, 1), rpc: &recordingTransport{}}
	f.live.Store(true)
	f.session = &Session{Connection: &amqp.Connection{}, Transport: f.rpc, Closed: f.closed,
		Live: f.live.Load, Close: func() { f.live.Store(false); f.closes.Add(1) }}
	return f
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("test event not observed")
		var zero T
		return zero
	}
}

func shutdown(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryWaitsForInitializationAndClosesOldSessionBeforeNewOne(t *testing.T) {
	old, next := newFixture(), newFixture()
	opening, registered, ready := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	factory := func(ctx context.Context) (*Session, error) {
		if old.closes.Load() != 1 {
			t.Error("old session was not closed before dialing replacement")
		}
		close(opening)
		select {
		case <-registered:
			return next.session, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m := start(context.Background(), old.session, factory, func(s *Session) {
		if s == next.session {
			ready <- struct{}{}
		}
	}, nil,
		func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil })
	old.live.Store(false)
	old.closed <- &amqp.Error{Code: 320, Reason: "shutdown"}
	receive(t, opening)
	if m.Connection() != nil || m.Transport() != nil {
		t.Fatal("unregistered consumers were advertised as ready")
	}
	close(registered)
	receive(t, ready)
	if m.Connection() != next.session.Connection {
		t.Fatal("new operation retained old connection")
	}
	shutdown(t, m)
	if next.closes.Load() != 1 || m.Connection() != nil {
		t.Fatal("shutdown did not close and unpublish session exactly once")
	}
}

func TestBootDegradedRetriesBackoffAndCancellationStopsNewDial(t *testing.T) {
	delays, permits := make(chan time.Duration), make(chan struct{})
	var attempts atomic.Int32
	pause := func(ctx context.Context, delay time.Duration) bool {
		select {
		case delays <- delay:
		case <-ctx.Done():
			return false
		}
		select {
		case <-permits:
			return true
		case <-ctx.Done():
			return false
		}
	}
	m := start(context.Background(), nil, func(context.Context) (*Session, error) { attempts.Add(1); return nil, errors.New("broker unavailable") }, nil, nil, pause)
	for _, expected := range []time.Duration{1, 2, 4, 8, 16, 30, 30} {
		if actual := receive(t, delays); actual != expected*time.Second {
			t.Fatalf("delay=%s expected=%s", actual, expected*time.Second)
		}
		if m.Connection() != nil {
			t.Fatal("dial failure became ready")
		}
		permits <- struct{}{}
	}
	receive(t, delays)
	shutdown(t, m)
	if attempts.Load() != 7 {
		t.Fatalf("new dial after shutdown or lost retry: %d", attempts.Load())
	}
}

func TestPartialRegistrationCannotPublishSessionAndIsClosed(t *testing.T) {
	partial, complete := newFixture(), newFixture()
	attempts := 0
	ready := make(chan struct{}, 1)
	m := start(context.Background(), nil, func(context.Context) (*Session, error) {
		attempts++
		if attempts == 1 {
			return partial.session, errors.New("second consumer refused")
		}
		if partial.closes.Load() != 1 {
			t.Error("partial subscriptions leaked")
		}
		return complete.session, nil
	}, func(s *Session) {
		if s == partial.session {
			t.Error("partial registration marked ready")
		}
		if s == complete.session {
			ready <- struct{}{}
		}
	}, nil,
		func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil })
	receive(t, ready)
	shutdown(t, m)
}

func TestUnknownPublishAndRequestAreNotReplayedAfterRecovery(t *testing.T) {
	old, next := newFixture(), newFixture()
	old.rpc.err = errors.New("publish outcome unknown after socket close")
	ready := make(chan struct{}, 1)
	m := start(context.Background(), old.session, func(context.Context) (*Session, error) { return next.session, nil },
		func(s *Session) {
			if s == next.session {
				ready <- struct{}{}
			}
		}, nil,
		func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil })
	request := rpc.Request{Endpoint: "mutation", Body: []byte("original payload"), CorrelationID: "original-correlation"}
	if err := m.Transport().Publish(context.Background(), request); err == nil {
		t.Fatal("unknown publish became success")
	}
	if _, err := m.Transport().Request(context.Background(), request); err == nil {
		t.Fatal("unknown request became success")
	}
	old.live.Store(false)
	close(old.closed)
	receive(t, ready)
	if old.rpc.publishes.Load() != 1 || old.rpc.requests.Load() != 1 || next.rpc.publishes.Load() != 0 || next.rpc.requests.Load() != 0 {
		t.Fatal("reconnect replayed ambiguous work")
	}
	// Only a separately authorized new caller operation uses the new session.
	if err := m.Transport().Publish(context.Background(), rpc.Request{Endpoint: "new-operation"}); err != nil || next.rpc.publishes.Load() != 1 {
		t.Fatal("new session did not serve a new operation")
	}
	shutdown(t, m)
}

func TestDrainDeadlineReportsFailureAndKeepsReplacementWithheld(t *testing.T) {
	old := newFixture()
	draining, release := make(chan struct{}), make(chan struct{})
	old.session.Close = func() { close(draining); <-release; old.closes.Add(1) }
	failed, done := make(chan error, 1), make(chan struct{})
	go func() { drain(old.session, 10*time.Millisecond, func(err error) { failed <- err }); close(done) }()
	receive(t, draining)
	if err := receive(t, failed); !errors.Is(err, ErrDrainDeadline) {
		t.Fatalf("missing explicit drain failure: %v", err)
	}
	select {
	case <-done:
		t.Fatal("deadline released a still-running generation")
	default:
	}
	close(release)
	receive(t, done)
	if old.closes.Load() != 1 {
		t.Fatal("drain did not finish exactly once")
	}
}

func TestReplacementAndShutdownWaitForOldHandlerDrain(t *testing.T) {
	old, next := newFixture(), newFixture()
	draining, release := make(chan struct{}), make(chan struct{})
	old.session.Close = func() { close(draining); <-release; old.closes.Add(1) }
	var attempts atomic.Int32
	m := start(context.Background(), old.session, func(context.Context) (*Session, error) {
		attempts.Add(1)
		return next.session, nil
	}, nil, nil, func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil })
	old.live.Store(false)
	close(old.closed)
	receive(t, draining)
	if m.Connection() != nil || m.Transport() != nil || attempts.Load() != 0 {
		t.Fatal("replacement exposed before drain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown should report undrained session: %v", err)
	}
	close(release)
	shutdown(t, m)
	if attempts.Load() != 0 || old.closes.Load() != 1 {
		t.Fatal("shutdown allowed a concurrent or replacement session")
	}
}

func TestShutdownDuringInitializationClosesCandidateWithoutPublishing(t *testing.T) {
	next := newFixture()
	opening := make(chan struct{})
	m := start(context.Background(), nil, func(ctx context.Context) (*Session, error) { close(opening); <-ctx.Done(); return next.session, nil },
		func(s *Session) {
			if s != nil {
				t.Error("cancelled initialization was published")
			}
		}, nil,
		func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil })
	receive(t, opening)
	shutdown(t, m)
	if next.closes.Load() != 1 {
		t.Fatal("cancelled candidate leaked")
	}
}

func TestConcurrentReadersAndRepeatedShutdown(t *testing.T) {
	f := newFixture()
	m := Start(context.Background(), f.session, func(context.Context) (*Session, error) {
		t.Error("unexpected reconnect")
		return nil, errors.New("unused")
	}, nil, nil)
	var readers sync.WaitGroup
	for i := 0; i < 16; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 200; j++ {
				_ = m.Connection()
				_ = m.Transport()
			}
		}()
	}
	shutdown(t, m)
	readers.Wait()
	shutdown(t, m)
	if f.closes.Load() != 1 {
		t.Fatal("session closed more than once")
	}
}
