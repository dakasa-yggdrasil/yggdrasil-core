package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ErrSurfaceManifestNotFound is returned by GetSurfaceManifest when no
// row matches the surface id.
var ErrSurfaceManifestNotFound = errors.New("surface_manifest not found")

// ErrSurfaceRuntimeTargetNotFound is returned when no runtime endpoint
// was configured for a surface id.
var ErrSurfaceRuntimeTargetNotFound = errors.New("surface_runtime_target not found")

// UpsertSurfaceManifest inserts or updates the cached manifest for one
// surface. Called by internal/surface.Discovery on every successful
// fetch.
func UpsertSurfaceManifest(ctx context.Context, db *sql.DB, m model.SurfaceManifestRow) error {
	const q = `
		INSERT INTO public.surface_manifests (
			surface_id, surface_version, schema_version, display_name,
			icon, description, page_count, widget_count, permission_count,
			raw, health, fetched_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)
		ON CONFLICT (surface_id) DO UPDATE SET
			surface_version  = EXCLUDED.surface_version,
			schema_version   = EXCLUDED.schema_version,
			display_name     = EXCLUDED.display_name,
			icon             = EXCLUDED.icon,
			description      = EXCLUDED.description,
			page_count       = EXCLUDED.page_count,
			widget_count     = EXCLUDED.widget_count,
			permission_count = EXCLUDED.permission_count,
			raw              = EXCLUDED.raw,
			health           = EXCLUDED.health,
			fetched_at       = EXCLUDED.fetched_at
	`
	_, err := db.ExecContext(ctx, q,
		m.SurfaceID, m.SurfaceVersion, m.SchemaVersion, m.DisplayName,
		m.Icon, m.Description, m.PageCount, m.WidgetCount, m.PermissionCount,
		[]byte(m.Raw), m.Health, m.FetchedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert surface_manifest %s: %w", m.SurfaceID, err)
	}
	return nil
}

// ListSurfaceManifests returns one entry per cached surface (Raw is
// excluded for cheap list rendering).
func ListSurfaceManifests(ctx context.Context, db *sql.DB) ([]model.SurfaceCachedListEntry, error) {
	const q = `
		SELECT surface_id, surface_version, schema_version, display_name,
		       icon, description, page_count, widget_count, permission_count,
		       health, fetched_at
		FROM public.surface_manifests
		ORDER BY display_name
	`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list surface_manifests: %w", err)
	}
	defer rows.Close()
	var out []model.SurfaceCachedListEntry
	for rows.Next() {
		var e model.SurfaceCachedListEntry
		if err := rows.Scan(
			&e.SurfaceID, &e.SurfaceVersion, &e.SchemaVersion, &e.DisplayName,
			&e.Icon, &e.Description, &e.PageCount, &e.WidgetCount, &e.PermissionCount,
			&e.Health, &e.FetchedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetSurfaceManifest returns the full cached manifest including raw JSON.
func GetSurfaceManifest(ctx context.Context, db *sql.DB, surfaceID string) (model.SurfaceManifestRow, error) {
	const q = `
		SELECT surface_id, surface_version, schema_version, display_name,
		       icon, description, page_count, widget_count, permission_count,
		       raw, health, fetched_at
		FROM public.surface_manifests
		WHERE surface_id = $1
	`
	var m model.SurfaceManifestRow
	var raw []byte
	err := db.QueryRowContext(ctx, q, surfaceID).Scan(
		&m.SurfaceID, &m.SurfaceVersion, &m.SchemaVersion, &m.DisplayName,
		&m.Icon, &m.Description, &m.PageCount, &m.WidgetCount, &m.PermissionCount,
		&raw, &m.Health, &m.FetchedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SurfaceManifestRow{}, ErrSurfaceManifestNotFound
	}
	if err != nil {
		return model.SurfaceManifestRow{}, err
	}
	m.Raw = raw
	return m, nil
}

// DeleteStaleSurfaceManifests removes rows whose fetched_at is older
// than the supplied cutoff. Called by Discovery sweeps to reap removed
// adapters.
func DeleteStaleSurfaceManifests(ctx context.Context, db *sql.DB, cutoff string) (int64, error) {
	const q = `DELETE FROM public.surface_manifests WHERE fetched_at < NOW() - $1::interval`
	res, err := db.ExecContext(ctx, q, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func UpsertSurfaceRuntimeTarget(ctx context.Context, db *sql.DB, req model.UpsertSurfaceRuntimeTargetRequest) (model.SurfaceRuntimeTarget, error) {
	surfaceID := normalizeSurfaceRuntimeTargetID(req.SurfaceID)
	baseURL := strings.TrimRight(strings.TrimSpace(req.BaseURL), "/")
	if surfaceID == "" {
		return model.SurfaceRuntimeTarget{}, fmt.Errorf("surface id is required")
	}
	if baseURL == "" {
		return model.SurfaceRuntimeTarget{}, fmt.Errorf("surface base URL is required")
	}

	const q = `
		INSERT INTO public.surface_runtime_targets (
			surface_id, base_url, enabled, description
		)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (surface_id) DO UPDATE SET
			base_url    = EXCLUDED.base_url,
			enabled     = EXCLUDED.enabled,
			description = EXCLUDED.description
		RETURNING surface_id, base_url, enabled, description, created_at, updated_at
	`
	var out model.SurfaceRuntimeTarget
	if err := db.QueryRowContext(
		ctx,
		q,
		surfaceID,
		baseURL,
		req.Enabled,
		strings.TrimSpace(req.Description),
	).Scan(&out.SurfaceID, &out.BaseURL, &out.Enabled, &out.Description, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return model.SurfaceRuntimeTarget{}, fmt.Errorf("upsert surface_runtime_target %s: %w", surfaceID, err)
	}
	return out, nil
}

func ListSurfaceRuntimeTargets(ctx context.Context, db *sql.DB, includeDisabled bool) ([]model.SurfaceRuntimeTarget, error) {
	const q = `
		SELECT surface_id, base_url, enabled, description, created_at, updated_at
		FROM public.surface_runtime_targets
		WHERE ($1::boolean OR enabled)
		ORDER BY surface_id
	`
	rows, err := db.QueryContext(ctx, q, includeDisabled)
	if err != nil {
		return nil, fmt.Errorf("list surface_runtime_targets: %w", err)
	}
	defer rows.Close()
	out := []model.SurfaceRuntimeTarget{}
	for rows.Next() {
		var target model.SurfaceRuntimeTarget
		if err := rows.Scan(
			&target.SurfaceID,
			&target.BaseURL,
			&target.Enabled,
			&target.Description,
			&target.CreatedAt,
			&target.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, rows.Err()
}

func GetSurfaceRuntimeTarget(ctx context.Context, db *sql.DB, surfaceID string) (model.SurfaceRuntimeTarget, error) {
	const q = `
		SELECT surface_id, base_url, enabled, description, created_at, updated_at
		FROM public.surface_runtime_targets
		WHERE surface_id = $1
	`
	var target model.SurfaceRuntimeTarget
	err := db.QueryRowContext(ctx, q, normalizeSurfaceRuntimeTargetID(surfaceID)).Scan(
		&target.SurfaceID,
		&target.BaseURL,
		&target.Enabled,
		&target.Description,
		&target.CreatedAt,
		&target.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SurfaceRuntimeTarget{}, ErrSurfaceRuntimeTargetNotFound
	}
	if err != nil {
		return model.SurfaceRuntimeTarget{}, err
	}
	return target, nil
}

func DeleteSurfaceRuntimeTarget(ctx context.Context, db *sql.DB, surfaceID string) error {
	const q = `DELETE FROM public.surface_runtime_targets WHERE surface_id = $1`
	res, err := db.ExecContext(ctx, q, normalizeSurfaceRuntimeTargetID(surfaceID))
	if err != nil {
		return fmt.Errorf("delete surface_runtime_target %s: %w", surfaceID, err)
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrSurfaceRuntimeTargetNotFound
	}
	return nil
}

func normalizeSurfaceRuntimeTargetID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
