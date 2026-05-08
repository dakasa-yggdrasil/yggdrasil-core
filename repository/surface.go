package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ErrSurfaceManifestNotFound is returned by GetSurfaceManifest when no
// row matches the surface id.
var ErrSurfaceManifestNotFound = errors.New("surface_manifest not found")

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
