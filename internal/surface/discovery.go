package surface

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// AdapterTarget is the minimum info Discovery needs to talk to one
// adapter: its surface id (= integration id) and the base URL of its
// health server.
type AdapterTarget struct {
	ID      string
	BaseURL string
}

// TargetSource enumerates currently registered adapters. The default
// implementation in addons reads from integration_instance_runtime_states
// (only those with last_success_at within the last 5 minutes are
// considered alive).
type TargetSource interface {
	List(ctx context.Context) ([]AdapterTarget, error)
}

// PermissionReconciler is invoked after every successful manifest fetch
// to reconcile that surface's permissions into permissions_catalog.
type PermissionReconciler interface {
	Reconcile(ctx context.Context, surfaceID string, perms []SurfacePerm) error
}

// SurfacePerm is the slim shape passed to the reconciler — decouples
// the reconciler interface from the SDK type.
type SurfacePerm struct {
	ID    string
	Label string
}

// Discovery refreshes the surface_manifests cache from live adapters.
type Discovery struct {
	db         *sql.DB
	client     *Client
	logger     *zap.Logger
	source     TargetSource
	reconciler PermissionReconciler
	stopOnce   sync.Once
	stopChan   chan struct{}
}

func NewDiscovery(db *sql.DB, client *Client, logger *zap.Logger) *Discovery {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Discovery{
		db:       db,
		client:   client,
		logger:   logger,
		stopChan: make(chan struct{}),
	}
}

// WithSource sets the live adapter list source.
func (d *Discovery) WithSource(s TargetSource) *Discovery { d.source = s; return d }

// WithReconciler sets the permission reconciler.
func (d *Discovery) WithReconciler(r PermissionReconciler) *Discovery { d.reconciler = r; return d }

// RefreshOne fetches one adapter's manifest and upserts it. Treats
// ErrNoSurface as a no-op (adapter has no surface yet).
func (d *Discovery) RefreshOne(ctx context.Context, t AdapterTarget) error {
	manifest, err := d.client.FetchManifest(ctx, t.BaseURL)
	if errors.Is(err, ErrNoSurface) {
		return nil
	}
	if err != nil {
		d.logger.Warn("surface manifest fetch failed",
			zap.String("surface", t.ID),
			zap.String("base_url", t.BaseURL),
			zap.Error(err))
		return d.markDown(ctx, t.ID)
	}

	raw, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("re-marshal manifest %s: %w", t.ID, err)
	}

	row := model.SurfaceManifestRow{
		SurfaceID:       manifest.Surface,
		SurfaceVersion:  manifest.SurfaceVersion,
		SchemaVersion:   manifest.SchemaVersion,
		DisplayName:     manifest.DisplayName,
		Icon:            manifest.Icon,
		Description:     manifest.Description,
		PageCount:       len(manifest.Pages),
		WidgetCount:     len(manifest.Widgets),
		PermissionCount: len(manifest.Permissions),
		Raw:             raw,
		Health:          "ok",
		FetchedAt:       time.Now().UTC(),
	}
	if err := repository.UpsertSurfaceManifest(ctx, d.db, row); err != nil {
		return err
	}

	if d.reconciler != nil {
		perms := make([]SurfacePerm, len(manifest.Permissions))
		for i, p := range manifest.Permissions {
			perms[i] = SurfacePerm{ID: p.ID, Label: p.Label}
		}
		if err := d.reconciler.Reconcile(ctx, manifest.Surface, perms); err != nil {
			// Audit G4: bump the failure counter alongside the log so
			// operators can chart the rate via Prometheus instead of
			// grep'ing logs.
			metrics.IncReconcileFailure(metrics.ReconcileKindPermissionCatalog)
			d.logger.Warn("permission reconcile failed",
				zap.String("surface", manifest.Surface), zap.Error(err))
		}
	}
	return nil
}

func (d *Discovery) markDown(ctx context.Context, surfaceID string) error {
	const q = `UPDATE public.surface_manifests SET health = 'down', fetched_at = NOW() WHERE surface_id = $1`
	_, err := d.db.ExecContext(ctx, q, surfaceID)
	return err
}

// Run starts the periodic refresh loop. Returns when ctx is canceled.
// Each tick refreshes ALL targets concurrently (bounded by `parallelism`).
func (d *Discovery) Run(ctx context.Context, interval time.Duration, parallelism int) error {
	if d.source == nil {
		return errors.New("surface discovery: source not configured")
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if parallelism <= 0 {
		parallelism = 4
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	d.runOnce(ctx, parallelism) // immediate first run
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-d.stopChan:
			return nil
		case <-t.C:
			d.runOnce(ctx, parallelism)
		}
	}
}

func (d *Discovery) runOnce(ctx context.Context, parallelism int) {
	targets, err := d.source.List(ctx)
	if err != nil {
		d.logger.Warn("surface discovery target list failed", zap.Error(err))
		return
	}
	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for _, tt := range targets {
		tt := tt
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := d.RefreshOne(ctx, tt); err != nil {
				d.logger.Warn("surface refresh failed", zap.String("surface", tt.ID), zap.Error(err))
			}
		}()
	}
	wg.Wait()
}

// Stop cancels the loop. Safe to call multiple times.
func (d *Discovery) Stop() {
	d.stopOnce.Do(func() { close(d.stopChan) })
}
