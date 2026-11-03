package brokersession_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/brokersession"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"go.uber.org/zap"
)

type registerTestSubscription struct {
	endpoint string
	closed   atomic.Int32
}

func (s *registerTestSubscription) Endpoint() string { return s.endpoint }
func (s *registerTestSubscription) Close() error {
	s.closed.Add(1)
	return nil
}

type registerTestTransport struct {
	configs       []rpc.ConsumerConfig
	subscriptions []*registerTestSubscription
	failAt        int
	failure       error
	onConsume     func(rpc.ConsumerConfig)
	outbound      atomic.Int32
}

func (f *registerTestTransport) Consume(cfg rpc.ConsumerConfig) (rpc.Subscription, error) {
	f.configs = append(f.configs, cfg)
	if f.failAt == len(f.configs) {
		return nil, f.failure
	}
	subscription := &registerTestSubscription{endpoint: cfg.Endpoint}
	f.subscriptions = append(f.subscriptions, subscription)
	if f.onConsume != nil {
		f.onConsume(cfg)
	}
	return subscription, nil
}

func (f *registerTestTransport) Request(context.Context, rpc.Request) (rpc.Reply, error) {
	f.outbound.Add(1)
	return rpc.Reply{}, errors.New("unexpected request")
}
func (f *registerTestTransport) Publish(context.Context, rpc.Request) error {
	f.outbound.Add(1)
	return errors.New("unexpected publish")
}
func (f *registerTestTransport) Close() error { return nil }

func TestRegisterConsumersSessionStopCancelsDrainsAndRejectsLaterStarts(t *testing.T) {
	type contextKey struct{}
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var starts atomic.Int32
	var socketAlive atomic.Bool
	socketAlive.Store(true)
	fake := &registerTestTransport{}
	deliveryCtx, cancelDelivery := context.WithTimeout(context.WithValue(context.Background(), contextKey{}, "original"), time.Minute)
	defer cancelDelivery()
	wantDeadline, _ := deliveryCtx.Deadline()
	stop, err := brokersession.RegisterConsumers(context.Background(), fake, []rpc.ConsumerConfig{{
		Endpoint: "test.session", Timeout: time.Minute, Concurrency: 2,
		Handler: func(ctx context.Context, _ rpc.Delivery) error {
			starts.Add(1)
			if ctx.Value(contextKey{}) != "original" {
				t.Error("delivery values were lost")
			}
			if deadline, ok := ctx.Deadline(); !ok || deadline != wantDeadline {
				t.Error("delivery deadline was lost")
			}
			close(started)
			<-ctx.Done()
			if socketAlive.Load() {
				t.Error("session cancellation reached handler before connection close")
			}
			close(canceled)
			<-release
			return ctx.Err()
		},
	}}, func() { socketAlive.Store(false) })
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan error, 1)
	go func() { returned <- fake.configs[0].Handler(deliveryCtx, rpc.Delivery{}) }()
	awaitRegisterSignal(t, started)
	drained := make(chan struct{})
	go func() { stop(); close(drained) }()
	awaitRegisterSignal(t, canceled)
	select {
	case <-drained:
		t.Fatal("stop returned while the handler was still running")
	default:
	}
	var settlement atomic.Int32
	delivery := rpc.Delivery{
		AckFn:   func() error { settlement.Add(1); return nil },
		NackFn:  func(bool) error { settlement.Add(1); return nil },
		ReplyFn: func(context.Context, []byte, string) error { settlement.Add(1); return nil },
	}
	if err := fake.configs[0].Handler(context.Background(), delivery); !errors.Is(err, rpc.ErrClosed) {
		t.Fatalf("handler after stop = %v; want rpc.ErrClosed", err)
	}
	if starts.Load() != 1 || settlement.Load() != 0 || fake.outbound.Load() != 0 {
		t.Fatal("stop started another operation or settled/replayed a delivery")
	}
	close(release)
	awaitRegisterSignal(t, drained)
	if err := <-returned; !errors.Is(err, context.Canceled) {
		t.Fatalf("handler cancellation = %v", err)
	}
	stop()
	if fake.subscriptions[0].closed.Load() != 1 {
		t.Fatal("repeated stop did not close the subscription exactly once")
	}
}

func TestRegisterConsumersPartialFailureCancelsAndCleansRegisteredHandlers(t *testing.T) {
	failure := errors.New("subscribe refused")
	started := make(chan struct{})
	returned := make(chan struct{})
	var socketAlive atomic.Bool
	socketAlive.Store(true)
	fake := &registerTestTransport{failAt: 2, failure: failure}
	fake.onConsume = func(cfg rpc.ConsumerConfig) {
		go func() {
			_ = cfg.Handler(context.Background(), rpc.Delivery{})
			close(returned)
		}()
		awaitRegisterSignal(t, started)
	}
	stop, err := brokersession.RegisterConsumers(context.Background(), fake, []rpc.ConsumerConfig{
		{Endpoint: "first", Handler: func(ctx context.Context, _ rpc.Delivery) error {
			close(started)
			<-ctx.Done()
			if socketAlive.Load() {
				t.Error("partial-registration cleanup canceled handler on a live socket")
			}
			return ctx.Err()
		}},
		{Endpoint: "second", Handler: func(context.Context, rpc.Delivery) error {
			t.Error("a failed registration must never run its handler")
			return nil
		}},
	}, func() { socketAlive.Store(false) })
	if !errors.Is(err, failure) || stop == nil {
		t.Fatalf("partial registration = %v, stop nil=%v", err, stop == nil)
	}
	if !socketAlive.Load() || fake.subscriptions[0].closed.Load() != 0 {
		t.Fatal("registration performed cleanup before returning it to the drain owner")
	}
	stop()
	awaitRegisterSignal(t, returned)
	if len(fake.subscriptions) != 1 || fake.subscriptions[0].closed.Load() != 1 {
		t.Fatal("partial registration did not close the already registered subscription")
	}
	if err := fake.configs[0].Handler(context.Background(), rpc.Delivery{}); !errors.Is(err, rpc.ErrClosed) {
		t.Fatalf("partial registration retained a usable handler: %v", err)
	}
	if fake.outbound.Load() != 0 {
		t.Fatal("partial cleanup dispatched an outbound operation")
	}
	// Wrapping must not conceal the SDK's required-handler validation.
	invalid := &registerTestTransport{}
	invalidStop, invalidErr := brokersession.RegisterConsumers(context.Background(), invalid, []rpc.ConsumerConfig{
		{Endpoint: "registered", Handler: func(context.Context, rpc.Delivery) error { return nil }},
		{Endpoint: "nil-handler"},
	}, func() {})
	if invalidErr == nil || invalidStop == nil || len(invalid.configs) != 1 {
		t.Fatal("nil handler was hidden by the wrapper instead of returning owned partial cleanup")
	}
	if invalid.subscriptions[0].closed.Load() != 0 {
		t.Fatal("invalid registration drained before returning cleanup ownership")
	}
	invalidStop()
	if invalid.subscriptions[0].closed.Load() != 1 {
		t.Fatal("invalid registration cleanup did not close the earlier subscription")
	}
}

func TestRegisterConsumersParentCancellationAndConcurrentStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Even an already canceled parent cannot cancel a handler before the
	// session owner has closed the socket through stopDrain.
	cancel()
	fake := &registerTestTransport{}
	started := make(chan struct{})
	finished := make(chan struct{})
	var socketAlive atomic.Bool
	socketAlive.Store(true)
	var socketCloses atomic.Int32
	stop, err := brokersession.RegisterConsumers(ctx, fake, []rpc.ConsumerConfig{{Endpoint: "test.parent", Handler: func(ctx context.Context, _ rpc.Delivery) error {
		close(started)
		<-ctx.Done()
		if socketAlive.Load() {
			t.Error("external cancellation reached the handler on a live socket")
		}
		return ctx.Err()
	}}}, func() { socketCloses.Add(1); socketAlive.Store(false) })
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = fake.configs[0].Handler(context.Background(), rpc.Delivery{}); close(finished) }()
	awaitRegisterSignal(t, started)
	select {
	case <-finished:
		t.Fatal("the canceled parent stopped a handler before socket close")
	default:
	}
	var concurrent sync.WaitGroup
	for i := 0; i < 8; i++ {
		concurrent.Add(1)
		go func() { defer concurrent.Done(); stop() }()
	}
	concurrent.Wait()
	awaitRegisterSignal(t, finished)
	if fake.subscriptions[0].closed.Load() != 1 || socketCloses.Load() != 1 {
		t.Fatal("concurrent stop must close socket and each subscription exactly once")
	}
	if err := fake.configs[0].Handler(context.Background(), rpc.Delivery{}); !errors.Is(err, rpc.ErrClosed) {
		t.Fatalf("stopped session accepted another handler: %v", err)
	}
}

func TestRegisterAllConsumersContextPreservesLegacyEndpointsAndOptions(t *testing.T) {
	legacy := &registerTestTransport{}
	if err := messagecontroller.RegisterAllConsumers(legacy, nil, nil, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	session := &registerTestTransport{}
	stop, err := messagecontroller.RegisterAllConsumersWithContext(context.Background(), session, nil, nil, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if len(session.configs) == 0 || len(session.configs) != len(legacy.configs) {
		t.Fatal("consumer set changed")
	}
	for i, cfg := range session.configs {
		old := legacy.configs[i]
		if cfg.Endpoint != old.Endpoint || cfg.Timeout != old.Timeout || cfg.Concurrency != old.Concurrency || cfg.Handler == nil {
			t.Fatalf("consumer %d configuration changed: %+v vs %+v", i, cfg, old)
		}
	}
	failure := errors.New("legacy partial registration")
	partial := &registerTestTransport{failAt: 2, failure: failure}
	if err := messagecontroller.RegisterAllConsumers(partial, nil, nil, zap.NewNop()); !errors.Is(err, failure) {
		t.Fatalf("legacy partial registration error = %v", err)
	}
	if len(partial.subscriptions) != 1 || partial.subscriptions[0].closed.Load() != 1 {
		t.Fatal("legacy wrapper did not clean partial subscriptions before returning")
	}
}

func TestRegisterConsumersDeliveryDuringCloseWaitsForClosedSocket(t *testing.T) {
	var socketAlive atomic.Bool
	socketAlive.Store(true)
	closeEntered := make(chan struct{})
	allowClose := make(chan struct{})
	activeStarted := make(chan struct{})
	activeReturned := make(chan error, 1)
	lateReturned := make(chan error, 1)
	var starts atomic.Int32
	var settlement atomic.Int32
	fake := &registerTestTransport{}
	stop, err := brokersession.RegisterConsumers(context.Background(), fake, []rpc.ConsumerConfig{{Endpoint: "close-race", Handler: func(ctx context.Context, _ rpc.Delivery) error {
		starts.Add(1)
		close(activeStarted)
		<-ctx.Done()
		if socketAlive.Load() {
			t.Error("active handler was canceled while the socket was live")
		}
		return ctx.Err()
	}}}, func() {
		close(closeEntered)
		<-allowClose
		socketAlive.Store(false)
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { activeReturned <- fake.configs[0].Handler(context.Background(), rpc.Delivery{}) }()
	awaitRegisterSignal(t, activeStarted)
	drained := make(chan struct{})
	go func() { stop(); close(drained) }()
	awaitRegisterSignal(t, closeEntered)
	delivery := rpc.Delivery{
		AckFn:   func() error { settlement.Add(1); return nil },
		NackFn:  func(bool) error { settlement.Add(1); return nil },
		ReplyFn: func(context.Context, []byte, string) error { settlement.Add(1); return nil },
	}
	go func() { lateReturned <- fake.configs[0].Handler(context.Background(), delivery) }()
	select {
	case err := <-lateReturned:
		close(allowClose)
		awaitRegisterSignal(t, drained)
		t.Fatalf("delivery returned %v before socket close; SDK could Nack(false)", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowClose)
	awaitRegisterSignal(t, drained)
	if err := <-activeReturned; !errors.Is(err, context.Canceled) {
		t.Fatalf("active handler error = %v", err)
	}
	if err := <-lateReturned; !errors.Is(err, rpc.ErrClosed) {
		t.Fatalf("late handler error = %v", err)
	}
	if socketAlive.Load() || starts.Load() != 1 || settlement.Load() != 0 || fake.outbound.Load() != 0 {
		t.Fatal("close gate dispatched, settled, replayed, or returned before closing the socket")
	}
}

func awaitRegisterSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("consumer lifecycle signal did not arrive")
	}
}
