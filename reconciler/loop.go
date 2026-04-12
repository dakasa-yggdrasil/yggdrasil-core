package reconciler

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"go.uber.org/zap"
)

// Engine drives periodic and reactive reconciliation of managed secrets
// into Kubernetes clusters.
type Engine struct {
	pool    *KubeClientPool
	db      *sql.DB
	logger  *zap.Logger
	secrets *SecretMaterializer

	eventCh    chan model.ManagedSecret
	lastResult ReconcileResult
}

// NewEngine creates a reconciliation engine.
func NewEngine(pool *KubeClientPool, db *sql.DB, logger *zap.Logger) *Engine {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Engine{
		pool:    pool,
		db:      db,
		logger:  logger,
		secrets: &SecretMaterializer{},
		eventCh: make(chan model.ManagedSecret, 64),
	}
}

// MaterializeSecret resolves the target cluster from the pool and materializes
// a single secret.
func (e *Engine) MaterializeSecret(ctx context.Context, secret model.ManagedSecret) error {
	targetName := resolveTargetName(secret)
	target, err := e.pool.Target(ctx, targetName)
	if err != nil {
		return err
	}
	return e.secrets.Materialize(ctx, *target, secret)
}

// NotifyChange enqueues a secret for immediate reconciliation. If the event
// channel is full the notification is silently dropped to avoid blocking
// callers.
func (e *Engine) NotifyChange(secret model.ManagedSecret) {
	select {
	case e.eventCh <- secret:
	default:
		e.logger.Warn("event channel full, dropping notification",
			zap.String("namespace", secret.Namespace),
			zap.String("name", secret.Name),
		)
	}
}

// LastResult returns the result of the most recent full reconciliation pass.
func (e *Engine) LastResult() ReconcileResult {
	return e.lastResult
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
		case secret := <-e.eventCh:
			if err := e.MaterializeSecret(ctx, secret); err != nil {
				e.logger.Error("reactive materialize failed",
					zap.String("namespace", secret.Namespace),
					zap.String("name", secret.Name),
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

// runFullReconcile fetches all active secrets from the database and reconciles
// them against Kubernetes.
func (e *Engine) runFullReconcile(ctx context.Context) {
	if e.db == nil {
		e.logger.Debug("skipping full reconcile: no database configured")
		return
	}

	secrets, err := repository.ListManagedSecrets(ctx, e.db, model.ListManagedSecretsRequest{
		Status: "active",
	})
	if err != nil {
		e.logger.Error("list managed secrets failed", zap.Error(err))
		return
	}

	result := e.reconcileSecretList(ctx, secrets)
	e.lastResult = result

	e.logger.Info("full reconcile complete",
		zap.Int("created", result.Created),
		zap.Int("updated", result.Updated),
		zap.Int("skipped", result.Skipped),
		zap.Int("errors", result.Errors),
		zap.Duration("duration", result.Duration),
	)
}

// reconcileSecretList iterates a list of managed secrets, comparing each
// against the corresponding Kubernetes Secret and materializing when needed.
func (e *Engine) reconcileSecretList(ctx context.Context, secrets []model.ManagedSecret) ReconcileResult {
	start := time.Now()
	result := ReconcileResult{
		Kind:      "secrets",
		Timestamp: start,
	}

	for _, secret := range secrets {
		targetName := resolveTargetName(secret)
		target, err := e.pool.Target(ctx, targetName)
		if err != nil {
			e.logger.Error("resolve target failed",
				zap.String("target", targetName),
				zap.String("namespace", secret.Namespace),
				zap.String("name", secret.Name),
				zap.Error(err),
			)
			result.Errors++
			continue
		}

		ns, name := resolveTargetLocation(secret)

		existing, err := target.Client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			if mErr := e.secrets.Materialize(ctx, *target, secret); mErr != nil {
				e.logger.Error("create secret failed",
					zap.String("namespace", ns),
					zap.String("name", name),
					zap.Error(mErr),
				)
				result.Errors++
			} else {
				result.Created++
			}
			continue
		}
		if err != nil {
			e.logger.Error("get secret failed",
				zap.String("namespace", ns),
				zap.String("name", name),
				zap.Error(err),
			)
			result.Errors++
			continue
		}

		// Compare the version annotation with the managed secret version.
		existingVersion := existing.Annotations[AnnotationVersion]
		if existingVersion == strconv.Itoa(secret.Version) {
			result.Skipped++
			continue
		}

		if mErr := e.secrets.Materialize(ctx, *target, secret); mErr != nil {
			e.logger.Error("update secret failed",
				zap.String("namespace", ns),
				zap.String("name", name),
				zap.Error(mErr),
			)
			result.Errors++
		} else {
			result.Updated++
		}
	}

	result.Duration = time.Since(start)
	return result
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
