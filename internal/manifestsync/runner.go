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
			go r.runOne(ctx, id)

		case <-cronCh:
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

func (r *Runner) runOne(ctx context.Context, id uuid.UUID) {
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
