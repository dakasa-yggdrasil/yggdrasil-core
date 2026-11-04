package addons

import (
	"context"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestBackgroundConnectionProviderFollowsRecoveryAndDoesNotFallBackWhileDown(t *testing.T) {
	app := newTestApp(t)
	old, next := &amqp.Connection{}, &amqp.Connection{}
	app.SetResource("rabbitmq", old)
	ctx := withBrokerConnection(context.Background(), app)
	for _, want := range []*amqp.Connection{old, nil, next} {
		app.SetResource("rabbitmq", want)
		if got := brokerConnectionFor(ctx, old); got != want {
			t.Fatalf("background operation used %p, current generation=%p", got, want)
		}
	}
	if got := brokerConnectionFor(context.Background(), old); got != old {
		t.Fatal("legacy direct caller lost its explicit connection")
	}
}

func TestCachedBackgroundDispatchersRefuseNilCurrentSessionBeforeUsingDatabase(t *testing.T) {
	legacy := &amqp.Connection{}
	provider := func() *amqp.Connection { return nil }
	caller := &rabbitmqReactorCaller{conn: legacy, connection: provider}
	if err := caller.Call(context.Background(), "unused", "unused", nil); err == nil || !strings.Contains(err.Error(), "connection unavailable") {
		t.Fatalf("reactor fell back to stale session: %v", err)
	}
	dispatcher := newSurfaceQueryDispatcher(legacy, nil)
	dispatcher.connection = provider
	if _, err := dispatcher.Execute(context.Background(), model.ExecuteIntegrationRequest{}); err == nil {
		t.Fatal("surface dispatcher used a stale session")
	}
	deps := &productionDeps{conn: legacy, connection: provider}
	if _, err := deps.InvokeDescribe(context.Background(), model.Manifest{}, model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.IntegrationTypeManifestSpec{}); err == nil {
		t.Fatal("manifest sync used a stale session")
	}
}
