package reconciler

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"go.uber.org/zap"
)

// Engine drives periodic and reactive reconciliation of managed resources
// into Kubernetes clusters.
type Engine struct {
	pool          *KubeClientPool
	db            *sql.DB
	logger        *zap.Logger
	materializers map[string]Materializer // keyed by Owns()

	eventCh     chan ReconcileEvent
	lastResults map[string]ReconcileResult
	mu          sync.RWMutex // protects lastResults
}

// NewEngine creates a reconciliation engine with the given materializers.
func NewEngine(pool *KubeClientPool, db *sql.DB, logger *zap.Logger, materializers ...Materializer) *Engine {
	if logger == nil {
		logger = zap.NewNop()
	}
	m := make(map[string]Materializer, len(materializers))
	for _, mat := range materializers {
		m[mat.Owns()] = mat
	}
	return &Engine{
		pool:          pool,
		db:            db,
		logger:        logger,
		materializers: m,
		eventCh:       make(chan ReconcileEvent, 64),
		lastResults:   make(map[string]ReconcileResult),
	}
}

// Materialize resolves the target cluster from the pool and delegates to
// the appropriate materializer for the given kind.
func (e *Engine) Materialize(ctx context.Context, kind string, resource any) error {
	mat, ok := e.materializers[kind]
	if !ok {
		return fmt.Errorf("no materializer for kind %q", kind)
	}
	targetName := resolveTargetNameFromAny(resource)
	target, err := e.pool.Target(ctx, targetName)
	if err != nil {
		return err
	}
	return mat.Materialize(ctx, *target, resource)
}

// MaterializeSecret is a convenience method that materializes a single secret.
// It delegates to Materialize with kind "secrets".
func (e *Engine) MaterializeSecret(ctx context.Context, secret model.ManagedSecret) error {
	return e.Materialize(ctx, "secrets", secret)
}

// NotifyChange enqueues a generic resource event for immediate reconciliation.
// If the event channel is full the notification is silently dropped to avoid
// blocking callers.
func (e *Engine) NotifyChange(kind string, resource any) {
	select {
	case e.eventCh <- ReconcileEvent{Kind: kind, Resource: resource}:
	default:
		e.logger.Warn("event channel full, dropping notification",
			zap.String("kind", kind),
		)
	}
}

// NotifySecretChange enqueues a secret for immediate reconciliation.
// Backward-compatible convenience method for HTTP handlers.
func (e *Engine) NotifySecretChange(secret model.ManagedSecret) {
	e.NotifyChange("secrets", secret)
}

// LastResults returns a copy of the most recent reconciliation results
// for all materializers.
func (e *Engine) LastResults() map[string]ReconcileResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]ReconcileResult, len(e.lastResults))
	for k, v := range e.lastResults {
		out[k] = v
	}
	return out
}

// LastResult returns the result of the most recent full reconciliation pass
// for secrets. Backward-compatible convenience method for HTTP handlers.
func (e *Engine) LastResult() ReconcileResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastResults["secrets"]
}

// Run blocks and runs the reconciliation loop until the context is cancelled.
// It reacts to events on the event channel and runs a full reconciliation on
// the configured interval.
func (e *Engine) Run(ctx context.Context) {
	interval := reconcileInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	e.logger.Info("reconciler engine started", zap.Duration("interval", interval))

	// Run an initial full reconcile immediately.
	e.runFullReconcile(ctx)

	for {
		select {
		case evt := <-e.eventCh:
			mat, ok := e.materializers[evt.Kind]
			if !ok {
				e.logger.Warn("no materializer for event kind", zap.String("kind", evt.Kind))
				continue
			}
			targetName := resolveTargetNameFromAny(evt.Resource)
			target, err := e.pool.Target(ctx, targetName)
			if err != nil {
				e.logger.Error("reactive materialize: resolve target failed",
					zap.String("kind", evt.Kind),
					zap.Error(err),
				)
				continue
			}
			if err := mat.Materialize(ctx, *target, evt.Resource); err != nil {
				e.logger.Error("reactive materialize failed",
					zap.String("kind", evt.Kind),
					zap.Error(err),
				)
			}
		case <-ticker.C:
			e.runFullReconcile(ctx)
		case <-ctx.Done():
			e.logger.Info("reconciler engine stopped")
			return
		}
	}
}

// runFullReconcile iterates all materializers and delegates reconciliation
// to each one.
func (e *Engine) runFullReconcile(ctx context.Context) {
	if e.db == nil {
		e.logger.Debug("skipping full reconcile: no database configured")
		return
	}

	target, err := e.pool.Local()
	if err != nil {
		e.logger.Error("local target not available", zap.Error(err))
		return
	}

	for kind, mat := range e.materializers {
		result, err := mat.Reconcile(ctx, *target, e.db)
		if err != nil {
			e.logger.Error("reconcile failed", zap.String("kind", kind), zap.Error(err))
			continue
		}
		e.mu.Lock()
		e.lastResults[kind] = result
		e.mu.Unlock()
		if result.Created > 0 || result.Updated > 0 || result.Errors > 0 {
			e.logger.Info("reconcile pass",
				zap.String("kind", kind),
				zap.Int("created", result.Created),
				zap.Int("updated", result.Updated),
				zap.Int("skipped", result.Skipped),
				zap.Int("errors", result.Errors),
			)
		}
	}
}

// resolveTargetNameFromAny inspects the resource to determine which cluster
// target it should be materialized into. Falls back to "local".
func resolveTargetNameFromAny(resource any) string {
	switch r := resource.(type) {
	case model.ManagedSecret:
		return resolveTargetName(r)
	default:
		return "local"
	}
}

// reconcileInterval reads RECONCILE_INTERVAL from the environment and returns
// the parsed duration, defaulting to 60s.
func reconcileInterval() time.Duration {
	raw := os.Getenv("RECONCILE_INTERVAL")
	if raw == "" {
		return 60 * time.Second
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 60 * time.Second
	}
	return d
}
