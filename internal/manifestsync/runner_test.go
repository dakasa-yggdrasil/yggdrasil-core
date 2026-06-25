package manifestsync

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type countingDeps struct {
	fakeDeps
	calls    atomic.Int32
	hold     chan struct{} // gates the call inside InvokeDescribe
	released chan struct{} // signals a goroutine has entered describe
}

func (c *countingDeps) InvokeDescribe(ctx context.Context, _ model.Manifest, _ model.Manifest, _ model.IntegrationInstanceManifestSpec, _ model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, error) {
	c.calls.Add(1)
	if c.released != nil {
		c.released <- struct{}{}
	}
	if c.hold != nil {
		<-c.hold
	}
	return c.describeSpec, c.describeErr
}

func TestRunner_SignalsTriggerSync(t *testing.T) {
	resetNotifyChannelForTest(t)

	f := &countingDeps{fakeDeps: *newFakeWithHappyPath()}
	r := &Runner{Deps: f, CronInterval: 0} // 0 disables cron for this test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	Notify(f.typeManifest.ID)

	require.Eventually(t, func() bool {
		return f.calls.Load() >= 1
	}, 1*time.Second, 10*time.Millisecond, "expected InvokeDescribe called after Notify")
}

func TestRunner_SerializesPerType(t *testing.T) {
	resetNotifyChannelForTest(t)

	f := &countingDeps{
		fakeDeps: *newFakeWithHappyPath(),
		hold:     make(chan struct{}),
		released: make(chan struct{}, 1),
	}
	r := &Runner{Deps: f, CronInterval: 0}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	typeID := f.typeManifest.ID
	Notify(typeID)
	Notify(typeID) // second signal must wait for first to finish

	<-f.released // first goroutine entered
	// Second goroutine must be blocked on the per-type mutex.
	time.Sleep(50 * time.Millisecond)
	assert.EqualValues(t, 1, f.calls.Load(), "second sync must not start until first releases mutex")

	close(f.hold) // release first
	// Now second can proceed.
	require.Eventually(t, func() bool {
		return f.calls.Load() == 2
	}, 1*time.Second, 10*time.Millisecond)
}

func TestRunner_CronFires(t *testing.T) {
	resetNotifyChannelForTest(t)

	f := &countingDeps{fakeDeps: *newFakeWithHappyPath()}
	typeIDs := []uuid.UUID{f.typeManifest.ID}
	r := &Runner{
		Deps:         f,
		CronInterval: 30 * time.Millisecond,
		EnumerateTypeIDs: func(_ context.Context) ([]uuid.UUID, error) {
			return typeIDs, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	require.Eventually(t, func() bool {
		return f.calls.Load() >= 2 // at least two cron ticks
	}, 500*time.Millisecond, 10*time.Millisecond)
}

// TestRunner_SkipsSyncWhenBrokerUnavailable asserts that when BrokerLive
// returns false the runner does NOT invoke a sync for either the event-driven
// Notify path or the cron sweep. SyncIntegrationType → InvokeDescribe issues a
// broker RPC (conn.Channel()); a nil/closed connection there panics the
// process. The runner must skip — leaving the integration_type unchanged for
// the next live tick — never dispatch through a dead broker.
func TestRunner_SkipsSyncWhenBrokerUnavailable(t *testing.T) {
	resetNotifyChannelForTest(t)

	f := &countingDeps{fakeDeps: *newFakeWithHappyPath()}
	typeIDs := []uuid.UUID{f.typeManifest.ID}
	r := &Runner{
		Deps:         f,
		CronInterval: 20 * time.Millisecond,
		EnumerateTypeIDs: func(_ context.Context) ([]uuid.UUID, error) {
			return typeIDs, nil
		},
		BrokerLive: func() bool { return false }, // broker down
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	// Drive both paths: a Notify signal and several cron ticks.
	Notify(f.typeManifest.ID)
	time.Sleep(150 * time.Millisecond)

	assert.EqualValues(t, 0, f.calls.Load(),
		"InvokeDescribe must not be called while the broker is unavailable (Notify + cron both gated)")
}

func TestRunner_DisabledByKillSwitch(t *testing.T) {
	resetNotifyChannelForTest(t)
	t.Setenv("MANIFEST_SYNC_ENABLED", "false")

	f := &countingDeps{fakeDeps: *newFakeWithHappyPath()}
	r := &Runner{Deps: f, CronInterval: 30 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	Notify(f.typeManifest.ID)
	time.Sleep(100 * time.Millisecond)
	assert.EqualValues(t, 0, f.calls.Load(), "runner must be inert when MANIFEST_SYNC_ENABLED=false")
}
