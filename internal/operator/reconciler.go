package operator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Reconciler polls the core for control_plane manifests and
// dispatches yggdrasil-deploy-control-plane when a new version
// lands. Tracker state lives in memory — on restart, the operator
// re-dispatches every active control_plane once. Re-dispatch is
// safe because the deploy workflow is idempotent (server-side
// apply + keyed migrations), but it does produce one extra run per
// manifest per restart, which is a fine trade for not needing a
// DB-backed tracker.
type Reconciler struct {
	client   *Client
	logger   *zap.Logger
	interval time.Duration
	opts     DispatchOptions

	mu      sync.Mutex
	tracker map[string]int // "<namespace>/<name>" → last dispatched version
}

// New constructs a Reconciler with defaults filled in. interval=0
// uses the default 30s poll.
func New(client *Client, logger *zap.Logger, interval time.Duration, opts DispatchOptions) *Reconciler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Reconciler{
		client:   client,
		logger:   logger,
		interval: interval,
		opts:     opts.WithDefaults(),
		tracker:  map[string]int{},
	}
}

// Run blocks until ctx is cancelled, reconciling on ticks. One pass
// runs immediately at startup so the first reconcile does not wait
// for the full interval.
func (r *Reconciler) Run(ctx context.Context) error {
	r.logger.Info("yggdrasil-operator reconciler starting",
		zap.Duration("interval", r.interval),
		zap.String("kubernetes_instance", r.opts.KubernetesInstance),
		zap.String("schema_migrations_instance", r.opts.SchemaMigrationsInstance),
	)

	r.reconcileOnce(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("yggdrasil-operator reconciler stopping", zap.String("reason", ctx.Err().Error()))
			return nil
		case <-ticker.C:
			r.reconcileOnce(ctx)
		}
	}
}

// reconcileOnce runs a single list → diff → dispatch pass. Errors
// are logged, not returned — the caller never cares, and swallowing
// them here keeps the ticker going on transient failures.
func (r *Reconciler) reconcileOnce(ctx context.Context) {
	manifests, err := r.client.ListControlPlanes(ctx)
	if err != nil {
		r.logger.Warn("list control_plane manifests failed", zap.Error(err))
		return
	}

	for _, cp := range manifests {
		if err := r.maybeDispatch(ctx, cp); err != nil {
			r.logger.Error("dispatch failed",
				zap.String("control_plane", controlPlaneKey(cp)),
				zap.Int("version", cp.Version),
				zap.Error(err),
			)
		}
	}
}

// maybeDispatch runs the workflow iff the version is newer than
// the last one the reconciler dispatched for this (namespace,
// name). Writes the tracker AFTER a successful dispatch — a failed
// run retries next tick.
func (r *Reconciler) maybeDispatch(ctx context.Context, cp ManifestRecord) error {
	key := controlPlaneKey(cp)

	r.mu.Lock()
	lastVersion := r.tracker[key]
	r.mu.Unlock()

	if cp.Version <= lastVersion {
		return nil
	}

	r.logger.Info("dispatching deploy-control-plane",
		zap.String("control_plane", key),
		zap.Int("version", cp.Version),
		zap.Int("last_version", lastVersion),
	)

	result, err := r.client.RunDeployWorkflow(ctx, cp, r.opts)
	if err != nil {
		return err
	}

	if result.Status != "succeeded" {
		return fmt.Errorf("workflow status=%s; first failed step: %s", result.Status, firstFailedStep(result))
	}

	r.mu.Lock()
	r.tracker[key] = cp.Version
	r.mu.Unlock()

	r.logger.Info("control_plane reconciled",
		zap.String("control_plane", key),
		zap.Int("version", cp.Version),
		zap.Int("steps", len(result.Steps)),
	)
	return nil
}

// controlPlaneKey is the tracker map key: namespace + name is the
// natural identifier (same (ns, name) stays the same record across
// versions, which is exactly what we want to track progress
// against).
func controlPlaneKey(cp ManifestRecord) string {
	ns := cp.Metadata.Namespace
	if ns == "" {
		ns = "global"
	}
	return ns + "/" + cp.Metadata.Name
}

func firstFailedStep(result WorkflowRunResult) string {
	for _, step := range result.Steps {
		if step.Status == "failed" {
			if step.Error != "" {
				return step.ID + ": " + step.Error
			}
			return step.ID
		}
	}
	return "<none>"
}
