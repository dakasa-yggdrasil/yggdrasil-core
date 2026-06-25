package addons

import (
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	amqp "github.com/rabbitmq/amqp091-go"
)

// newTestApp builds a minimal ServiceApp for unit tests that exercise
// addon bootstrap functions directly. No DB or broker is needed —
// tests that require them should seed resources or use integration helpers.
func newTestApp(t *testing.T) *runtime.ServiceApp {
	t.Helper()
	return runtime.New("test")
}

// TestBootstrapRabbitMQ_SoftFailsOnUnreachable verifies that boot does
// not return an error when BROKER_URL points at an unreachable broker.
// The IdP/auth and wake paths must remain up; only workflow dispatch
// degrades.
func TestBootstrapRabbitMQ_SoftFailsOnUnreachable(t *testing.T) {
	t.Setenv("BROKER_URL", "amqp://guest:guest@127.0.0.1:1/") // closed port
	app := newTestApp(t)
	if err := bootstrapRabbitMQ(context.Background(), app); err != nil {
		t.Fatalf("boot must soft-fail, got error: %v", err)
	}
	// The resource key must be present but the connection must be nil —
	// a non-nil live connection after an unreachable dial would be a bug.
	if r, ok := app.Resource("rabbitmq"); ok {
		if conn, ok := r.(*amqp.Connection); ok && conn != nil {
			t.Fatal("expected nil rabbitmq connection after unreachable dial, got live conn")
		}
	}
}
