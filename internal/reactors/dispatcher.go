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
	DispatchInstanceID    uuid.UUID
	PriorStatus           model.ReactionStatus
	PriorLastError        string
	Capability            string
	Attempt               int
}

// Runner is the background worker that drives the reactor dispatch loop.
type Runner struct {
	DB                 *sql.DB
	Logger             *zap.Logger
	Caller             Caller
	Interval           time.Duration
	BatchSize          int
	Parallelism        int
	StuckThreshold     time.Duration
	BacklogInterval    time.Duration
	nextBacklogRefresh time.Time

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
	if r.BacklogInterval == 0 {
		r.BacklogInterval = time.Minute
	}
}

func (r *Runner) tickOnce(ctx context.Context) error {
	if r.DB != nil && !time.Now().Before(r.nextBacklogRefresh) {
		r.nextBacklogRefresh = time.Now().Add(r.BacklogInterval)
		refreshCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		count, age, err := repository.PausedReactionBacklog(refreshCtx, r.DB)
		cancel()
		if err != nil {
			if r.Logger != nil {
				r.Logger.Warn("paused reactor backlog refresh failed", zap.Error(err))
			}
		} else {
			metrics.SetReactorPausedBacklog(count, age, time.Now())
		}
	}
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
			DispatchInstanceID:    x.DispatchInstanceID,
			PriorStatus:           x.PriorStatus,
			PriorLastError:        x.PriorLastError,
			Capability:            x.Capability,
			Attempt:               x.Attempt,
		})
	}
	return out, nil
}

func (r *Runner) dispatchOne(ctx context.Context, c ClaimedReaction) {
	if !r.claimDispatchAllowed(ctx, c) {
		return
	}
	rawPayload, emittedAt, actor, err := repository.FetchEventForReactor(ctx, r.DB, c.EventID)
	if err != nil {
		if !r.claimDispatchAllowed(ctx, c) {
			return
		}
		_ = repository.MarkFailed(ctx, r.DB, c.ID, c.Attempt, fmt.Sprintf("fetch event: %v", err), backoffFor(c.Attempt))
		return
	}
	payload, err := BuildReactorPayload(c.EventID, c.EventType, "v1", rawPayload, emittedAt, actor, c.Attempt)
	if err != nil {
		if !r.claimDispatchAllowed(ctx, c) {
			return
		}
		_ = repository.MarkFailed(ctx, r.DB, c.ID, c.Attempt, fmt.Sprintf("build payload: %v", err), backoffFor(c.Attempt))
		return
	}

	if !r.claimDispatchAllowed(ctx, c) {
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

	err = r.Caller.Call(ctx, c.DispatchInstanceID.String(), c.Capability, payload)
	if err == nil {
		if err := repository.MarkSucceeded(ctx, r.DB, c.ID, c.Attempt); err != nil {
			if r.Logger != nil {
				r.Logger.Warn("reactor success claim no longer current", zap.Error(err), zap.String("reaction_id", c.ID.String()))
			}
			return
		}
		metrics.IncReactorDispatch(metrics.ReactorDispatchSucceeded)
		return
	}

	wait, deadLetter := BackoffFor(c.Attempt)
	if deadLetter {
		if markErr := repository.MarkDeadLettered(ctx, r.DB, c.ID, c.Attempt, err.Error()); markErr != nil {
			if r.Logger != nil {
				r.Logger.Warn("reactor dead-letter claim no longer current", zap.Error(markErr), zap.String("reaction_id", c.ID.String()))
			}
			return
		}
		r.emitDeadLetterEvent(ctx, c, err)
		// Terminal: count as dead_lettered.  We do NOT also count as failed —
		// the dispatch reached a terminal state exactly once.
		metrics.IncReactorDispatch(metrics.ReactorDispatchDeadLettered)
		return
	}
	if markErr := repository.MarkFailed(ctx, r.DB, c.ID, c.Attempt, err.Error(), wait); markErr != nil {
		if r.Logger != nil {
			r.Logger.Warn("reactor failure claim no longer current", zap.Error(markErr), zap.String("reaction_id", c.ID.String()))
		}
		return
	}
	// Non-terminal failure: bumps the failed counter once per retriable
	// failure so the rate captures the operator-visible "tried and missed"
	// signal.  The same reaction id may bump this counter multiple times
	// across retries; that mirrors what dispatch attempts actually do.
	metrics.IncReactorDispatch(metrics.ReactorDispatchFailed)
}

// claimDispatchAllowed runs immediately after claim and immediately before
// RPC. A pause, logical deletion, or active-version replacement returns the
// row to the queue without consuming an attempt. A policy read failure is a
// dispatch stop, never permission to send an adapter call.
func (r *Runner) claimDispatchAllowed(ctx context.Context, c ClaimedReaction) bool {
	activeID, allowed, policyErr := repository.ReactionDispatchAllowed(ctx, r.DB, c.ID, c.Attempt)
	if policyErr == nil && allowed && activeID == c.DispatchInstanceID {
		return true
	}
	if err := repository.ReleaseClaim(ctx, r.DB, c.ID, c.Attempt, c.PriorStatus, c.PriorLastError); err != nil && r.Logger != nil {
		r.Logger.Warn("release blocked reactor claim failed", zap.Error(err), zap.String("reaction_id", c.ID.String()))
	}
	if policyErr != nil && r.Logger != nil {
		r.Logger.Warn("reactor policy recheck failed", zap.Error(policyErr), zap.String("reaction_id", c.ID.String()))
	}
	return false
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
