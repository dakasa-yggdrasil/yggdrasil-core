package manifestsync

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Runner consumes the Notify channel (event-driven) and a cron ticker
// (safety-net), serializing per-typeID syncs through a mutex map.
type Runner struct {
	Deps         Deps
	CronInterval time.Duration // 0 disables the cron loop (useful in tests)
	// EnumerateTypeIDs returns all active integration_type IDs to sweep on
	// each cron tick. Required when CronInterval > 0.
	EnumerateTypeIDs func(ctx context.Context) ([]uuid.UUID, error)

	// BrokerLive, when set, is consulted before every sync (both the
	// event-driven Notify path and the cron sweep). When it returns false the
	// sync is skipped: SyncIntegrationType calls InvokeDescribe → a broker RPC
	// (conn.Channel()), which panics on a nil/closed connection. Skipping
	// leaves the integration_type unchanged so the next live tick re-syncs it.
	// When nil the runner always proceeds (backward-compatible default for
	// callers — e.g. tests — that do not wire it).
	BrokerLive func() bool

	mu      sync.Mutex
	typeMtx map[uuid.UUID]*sync.Mutex
}

// Run blocks until ctx is canceled or the kill switch is off.
func (r *Runner) Run(ctx context.Context) error {
	if os.Getenv("MANIFEST_SYNC_ENABLED") == "false" {
		<-ctx.Done()
		return ctx.Err()
	}
	r.typeMtx = map[uuid.UUID]*sync.Mutex{}

	// cron loop (optional)
	var cronCh <-chan time.Time
	if r.CronInterval > 0 && r.EnumerateTypeIDs != nil {
		t := time.NewTicker(r.CronInterval)
		defer t.Stop()
		cronCh = t.C
	}

	notifyCh := NotifyChannel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case id := <-notifyCh:
			if r.brokerUnavailable() {
				continue
			}
			go r.runOne(ctx, id)

		case <-cronCh:
			if r.brokerUnavailable() {
				continue
			}
			ids, err := r.EnumerateTypeIDs(ctx)
			if err != nil {
				continue
			}
			for _, id := range ids {
				go r.runOne(ctx, id)
			}
		}
	}
}

// brokerUnavailable reports whether the broker is known to be down. The gate
// lives on BOTH the select arm (so we never spawn a goroutine) and the
// goroutine body (so a drop between dispatch and execution is still caught) —
// the runOne re-check closes the race where the conn dies in that window.
func (r *Runner) brokerUnavailable() bool {
	return r.BrokerLive != nil && !r.BrokerLive()
}

func (r *Runner) runOne(ctx context.Context, id uuid.UUID) {
	// Re-check liveness inside the goroutine: the broker can drop between the
	// dispatch decision and the actual InvokeDescribe RPC. Skipping here keeps
	// the bare goroutine from calling conn.Channel() on a dead connection.
	if r.brokerUnavailable() {
		return
	}
	m := r.lockFor(id)
	m.Lock()
	defer m.Unlock()
	_ = SyncIntegrationType(ctx, r.Deps, id)
}

func (r *Runner) lockFor(id uuid.UUID) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.typeMtx[id]
	if !ok {
		m = &sync.Mutex{}
		r.typeMtx[id] = m
	}
	return m
}
