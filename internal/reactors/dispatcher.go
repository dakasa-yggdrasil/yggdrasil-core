package reactors

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Caller abstracts the RabbitMQ RPC to an integration adapter capability.
// Production wires this to messagecontroller's existing helper; tests pass a mock.
type Caller interface {
	Call(ctx context.Context, integrationInstanceID string, capability string, payload []byte) error
}

// ClaimedReaction is a thin row carried from ClaimPendingBatch to the worker.
type ClaimedReaction struct {
	ID                    uuid.UUID
	EventID               uuid.UUID
	EventType             string
	IntegrationInstanceID uuid.UUID
	Capability            string
	Attempt               int
}

// Runner is the background worker that drives the reactor dispatch loop.
type Runner struct {
	DB             *sql.DB
	Logger         *zap.Logger
	Caller         Caller
	Interval       time.Duration
	BatchSize      int
	Parallelism    int
	StuckThreshold time.Duration

	// BrokerAvailable, when set, is called at the start of each tick.
	// If it returns false the tick is skipped entirely: no reactions are
	// claimed, so rows remain pending and are replayed as soon as the
	// broker recovers. When nil, the runner always proceeds (backward-
	// compatible default for callers that do not set it).
	BrokerAvailable func() bool

	// claimBatch is overridable in tests.
	claimBatch func(ctx context.Context, limit int) ([]ClaimedReaction, error)
}

// Run loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	r.defaults()
	if r.claimBatch == nil {
		r.claimBatch = r.realClaim
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if err := r.tickOnce(ctx); err != nil && r.Logger != nil {
			r.Logger.Error("reactor runner tick failed", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (r *Runner) defaults() {
	if r.Interval == 0 {
		r.Interval = 5 * time.Second
	}
	if r.BatchSize == 0 {
		r.BatchSize = 50
	}
	if r.Parallelism == 0 {
		r.Parallelism = 10
	}
	if r.StuckThreshold == 0 {
		r.StuckThreshold = 10 * time.Minute
	}
}

func (r *Runner) tickOnce(ctx context.Context) error {
	// Skip the entire tick when the broker is known to be unavailable.
	// Reactions are NOT claimed so they remain pending and replay
	// immediately after the broker recovers — skip, not fail.
	if r.BrokerAvailable != nil && !r.BrokerAvailable() {
		if r.Logger != nil {
			r.Logger.Warn("reactor runner: broker unavailable — skipping tick, reactions left for replay")
		}
		return nil
	}

	if r.DB != nil {
		if _, err := repository.HealStuckInProgress(ctx, r.DB, r.StuckThreshold); err != nil && r.Logger != nil {
			r.Logger.Warn("heal stuck failed", zap.Error(err))
		}
	}

	batch, err := r.claimBatch(ctx, r.BatchSize)
	if err != nil {
		return fmt.Errorf("claim batch: %w", err)
	}
	if len(batch) == 0 {
		return nil
	}

	sem := make(chan struct{}, r.Parallelism)
	var wg sync.WaitGroup
	for _, c := range batch {
		c := c
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					metrics.IncGoroutinePanic("reactor_dispatch_one")
					if r.Logger != nil {
						r.Logger.Error("reactor dispatch panic recovered",
							zap.Any("panic", rec),
							zap.String("reaction_id", c.ID.String()))
					}
				}
				<-sem
				wg.Done()
			}()
			r.dispatchOne(ctx, c)
		}()
	}
	wg.Wait()
	return nil
}

func (r *Runner) realClaim(ctx context.Context, limit int) ([]ClaimedReaction, error) {
	rows, err := repository.ClaimPendingBatch(ctx, r.DB, limit)
	if err != nil {
		return nil, err
	}
	out := make([]ClaimedReaction, 0, len(rows))
	for _, x := range rows {
		out = append(out, ClaimedReaction{
			ID:                    x.ID,
			EventID:               x.EventID,
			EventType:             x.EventType,
			IntegrationInstanceID: x.IntegrationInstanceID,
			Capability:            x.Capability,
			Attempt:               x.Attempt,
		})
	}
	return out, nil
}

func (r *Runner) dispatchOne(ctx context.Context, c ClaimedReaction) {
	rawPayload, emittedAt, actor, err := repository.FetchEventForReactor(ctx, r.DB, c.EventID)
	if err != nil {
		_ = repository.MarkFailed(ctx, r.DB, c.ID, fmt.Sprintf("fetch event: %v", err), backoffFor(c.Attempt))
		return
	}
	payload, err := BuildReactorPayload(c.EventID, c.EventType, "v1", rawPayload, emittedAt, actor, c.Attempt)
	if err != nil {
		_ = repository.MarkFailed(ctx, r.DB, c.ID, fmt.Sprintf("build payload: %v", err), backoffFor(c.Attempt))
		return
	}

	if r.Logger != nil {
		r.Logger.Info("reactor dispatched",
			zap.String("reaction_id", c.ID.String()),
			zap.String("event_id", c.EventID.String()),
			zap.String("event_type", c.EventType),
			zap.String("capability", c.Capability),
			zap.Int("attempt", c.Attempt),
		)
	}

	err = r.Caller.Call(ctx, c.IntegrationInstanceID.String(), c.Capability, payload)
	if err == nil {
		_ = repository.MarkSucceeded(ctx, r.DB, c.ID)
		metrics.IncReactorDispatch(metrics.ReactorDispatchSucceeded)
		return
	}

	wait, deadLetter := BackoffFor(c.Attempt)
	if deadLetter {
		_ = repository.MarkDeadLettered(ctx, r.DB, c.ID, err.Error())
		r.emitDeadLetterEvent(ctx, c, err)
		// Terminal: count as dead_lettered.  We do NOT also count as failed —
		// the dispatch reached a terminal state exactly once.
		metrics.IncReactorDispatch(metrics.ReactorDispatchDeadLettered)
		return
	}
	_ = repository.MarkFailed(ctx, r.DB, c.ID, err.Error(), wait)
	// Non-terminal failure: bumps the failed counter once per retriable
	// failure so the rate captures the operator-visible "tried and missed"
	// signal.  The same reaction id may bump this counter multiple times
	// across retries; that mirrors what dispatch attempts actually do.
	metrics.IncReactorDispatch(metrics.ReactorDispatchFailed)
}

func backoffFor(attempt int) time.Duration {
	d, _ := BackoffFor(attempt)
	return d
}

func (r *Runner) emitDeadLetterEvent(ctx context.Context, c ClaimedReaction, finalErr error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("emit dead_lettered begin tx", zap.Error(err))
		}
		return
	}
	defer tx.Rollback()
	_, err = repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          repository.EventTypeReactorDeadLettered,
		SchemaVersion: "v1",
		AggregateType: "reactor",
		AggregateID:   c.ID.String(),
		Payload: map[string]any{
			"reaction_id":             c.ID.String(),
			"event_id":                c.EventID.String(),
			"event_type":              c.EventType,
			"integration_instance_id": c.IntegrationInstanceID.String(),
			"capability":              c.Capability,
			"final_error":             finalErr.Error(),
			"attempts":                c.Attempt,
		},
	})
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("emit dead_lettered", zap.Error(err))
		}
		return
	}
	_ = tx.Commit()
}
