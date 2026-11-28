package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Start owns ONLY recovery/cleanup for this policy+Source+whole-file scope.
// It never opens a run, creates a resource, challenges a worker or sends UDP.
// Start admission does not borrow the caller's canceled receiving lifetime.
func (p *NativeWorkerReadinessProducer) Start(ctx context.Context) error {
	if p == nil || p.state == nil || ctx == nil || ctx.Err() != nil {
		return errNativeReadinessRun
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.cleanupDone != nil {
		return errNativeReadinessRun
	}
	owned, cancel := context.WithCancel(context.Background())
	s.cleanupCancel = cancel
	s.cleanupDone = make(chan struct{})
	safego.SafeGo("native readiness owned cleanup", func() {
		normal := false
		defer func() { s.mu.Lock(); s.cleanupFailed = !normal; s.mu.Unlock(); close(s.cleanupDone) }()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-owned.Done():
				normal = true
				return
			case <-tick.C:
			}
			call, stop := context.WithTimeout(owned, 30*time.Second)
			p.recoverOne(call)
			stop()
		}
	})
	return nil
}

// Stop joins all owned recovery WAN before the callback listener is closed.
// The journal key remains available for original receiving until Close AFTER
// a successful listener join. Neither method closes the borrowed DB/SDK ports.
func (p *NativeWorkerReadinessProducer) Stop(ctx context.Context) error {
	if p == nil || p.state == nil {
		return nil
	}
	if ctx == nil {
		return errNativeReadinessRun
	}
	s := p.state
	s.mu.Lock()
	cancel, done := s.cleanupCancel, s.cleanupDone
	s.mu.Unlock()
	if done == nil {
		return nil
	}
	cancel()
	select {
	case <-ctx.Done():
		return errNativeReadinessRun
	case <-done:
	}
	s.mu.Lock()
	failed := s.cleanupFailed
	s.mu.Unlock()
	if failed {
		return errNativeReadinessRun
	}
	return nil
}

func (p *NativeWorkerReadinessProducer) recoverOne(ctx context.Context) {
	s := p.state
	var attempt uuid.UUID
	s.mu.Lock()
	cursor := s.cleanupCursor
	s.mu.Unlock()
	var runID uuid.UUID
	if err := s.journal.db.QueryRowContext(ctx, `SELECT attempt_id,id FROM public.capacity_native_worker_readiness_runs WHERE record#>>'{identity,policy_id}'=$1 AND record#>>'{identity,policy_checksum}'=$2 AND record#>>'{identity,source_commit}'=$3 AND record#>>'{identity,producer_scope_sha256}'=$4 AND record->'closed'='false'::jsonb AND (not_after<=clock_timestamp() OR record ? 'pending_proof') AND id>$5 ORDER BY id LIMIT 1`, s.journal.policy.ID.String(), s.journal.policy.Checksum, s.journal.source, s.journal.scope, cursor).Scan(&attempt, &runID); err != nil {
		if err == sql.ErrNoRows {
			s.mu.Lock()
			s.cleanupCursor = uuid.Nil
			s.mu.Unlock()
		}
		return
	}
	s.mu.Lock()
	s.cleanupCursor = runID
	s.mu.Unlock()
	done, err := p.enter(attempt)
	if err != nil {
		return
	}
	defer done()
	r, err := s.journal.read(ctx, attempt)
	if err != nil || r.Closed {
		return
	}
	var raw []byte
	var a model.CapacityNativeWorkerAttempt
	if s.journal.db.QueryRowContext(ctx, `SELECT attempt FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, attempt, s.journal.policy.ID, s.journal.policy.Metadata.Namespace).Scan(&raw) != nil || capacity.DecodeNativeCapacity(json.RawMessage(raw), &a) != nil {
		return
	}
	r, err = s.cleanup(ctx, a, r)
	if err != nil {
		return
	}
	if r.PendingProof != nil {
		_, _ = s.journal.finishWithProof(ctx, a, r, r.PendingProof.value())
	} else {
		_, _ = s.finishCleanup(ctx, r)
	}
}
