package addons

import (
	"context"
	"database/sql"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// TestBrokerLive covers the single canonical gate used by every addon
// background loop. It must be false for a typed-nil connection (boot-degraded)
// and — critically — must NOT panic when the receiver is nil (the && short
// circuits before conn.IsClosed(), which dereferences the struct).
func TestBrokerLive(t *testing.T) {
	// Boot-degraded: the rabbitmq resource carries a typed-nil connection.
	var nilConn *amqp.Connection
	if brokerLive(nilConn) {
		t.Fatal("brokerLive(nil) = true, want false (boot-degraded conn must be treated as down)")
	}
	// Sanity: calling it must not panic on the nil receiver.
	_ = brokerLive(nil)
}

// TestExternalIdentityResync_SkipsWhenBrokerUnavailable is the B1 regression.
//
// It drives runExternalIdentityResync with a nil connection AND a
// brokerAvailable gate that reports the broker down, then asserts the loop
// completes its initial tick (and one ticker tick) without panicking. If the
// gate were defeated — as it was via RabbitMQ(app) returning (nil, true) —
// the runner would call externalidentity.ResyncTick(ctx, db, nil), which fans
// out to message.ExecuteIntegration → rpcamqp.New(nil) → conn.Channel() on a
// nil *amqp.Connection and PANIC, crashing the process.
//
// Passing db=nil and conn=nil makes the test load-bearing: a working gate
// never reaches ResyncTick, so neither the nil DB nor the nil conn is ever
// dereferenced. A regressed gate would panic here.
func TestExternalIdentityResync_SkipsWhenBrokerUnavailable(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("runExternalIdentityResync panicked with broker unavailable: %v", r)
		}
	}()

	brokerDown := func() bool { return false }

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		// nil db + nil conn: only reachable code is the gate, which must skip.
		runExternalIdentityResync(
			context.Background(),
			(*sql.DB)(nil),
			(*amqp.Connection)(nil),
			brokerDown,
			nil,
			5*time.Millisecond, // tiny interval so a ticker tick also fires
			stop,
		)
	}()

	// Let the initial tick + at least one ticker tick run, then stop.
	time.Sleep(40 * time.Millisecond)
	close(stop)

	select {
	case <-done:
		// Loop returned cleanly after the stop signal — no panic, no DB/conn touch.
	case <-time.After(time.Second):
		t.Fatal("runExternalIdentityResync did not return after stop")
	}
}

// TestBootstrapExternalIdentityResync_NoPanicOnBootDegradedBroker exercises the
// full bootstrap entry point in the exact floor scenario the review proved
// crashed the process: the rabbitmq resource is present but typed-nil (broker
// unreachable at boot). bootstrapExternalIdentityResync must return nil and
// start NO runner goroutine — guarded by `if !ok || conn == nil`.
func TestBootstrapExternalIdentityResync_NoPanicOnBootDegradedBroker(t *testing.T) {
	app := newTestApp(t)
	// Seed a non-nil postgres so the addon gets past the Postgres gate, then a
	// typed-nil rabbitmq to reproduce the boot-degraded floor.
	app.SetResource("postgres", &sql.DB{})
	app.SetResource("rabbitmq", (*amqp.Connection)(nil))

	if err := bootstrapExternalIdentityResync(context.Background(), app); err != nil {
		t.Fatalf("bootstrap must soft-skip on boot-degraded broker, got error: %v", err)
	}

	// Give any (erroneously started) goroutine a moment to crash the process.
	time.Sleep(20 * time.Millisecond)
}
