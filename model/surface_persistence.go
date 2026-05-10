package model

import (
	"encoding/json"
	"time"
)

// SurfaceManifestRow mirrors a row in public.surface_manifests with
// persistence metadata. `Raw` is the canonical JSON received from the
// adapter; the indexed columns (DisplayName, etc.) are denormalized for
// cheap list rendering without parsing JSON.
type SurfaceManifestRow struct {
	SurfaceID       string          `json:"surface_id"`
	SurfaceVersion  string          `json:"surface_version"`
	SchemaVersion   int             `json:"schema_version"`
	DisplayName     string          `json:"display_name"`
	Icon            string          `json:"icon"`
	Description     string          `json:"description"`
	PageCount       int             `json:"page_count"`
	WidgetCount     int             `json:"widget_count"`
	PermissionCount int             `json:"permission_count"`
	Raw             json.RawMessage `json:"raw"`
	Health          string          `json:"health"`
	FetchedAt       time.Time       `json:"fetched_at"`
}

// SurfaceCachedListEntry is the list row served by GET /api/v1/ops/surfaces
// (Phase 3+). Excludes Raw and adds counts. Distinct from the existing
// SurfaceListEntry in ops_surface.go, which kept only the wire shape
// during Phase 1 when the list was always empty.
type SurfaceCachedListEntry struct {
	SurfaceID       string    `json:"surface_id"`
	SurfaceVersion  string    `json:"surface_version"`
	SchemaVersion   int       `json:"schema_version"`
	DisplayName     string    `json:"display_name"`
	Icon            string    `json:"icon"`
	Description     string    `json:"description"`
	Health          string    `json:"health"`
	PageCount       int       `json:"page_count"`
	WidgetCount     int       `json:"widget_count"`
	PermissionCount int       `json:"permission_count"`
	FetchedAt       time.Time `json:"fetched_at"`
}

// SurfaceRuntimeTarget stores the adapter endpoint used by the ops
// console to fetch a generic integration surface.
type SurfaceRuntimeTarget struct {
	SurfaceID   string    `json:"surface"`
	BaseURL     string    `json:"base_url"`
	Enabled     bool      `json:"enabled"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type UpsertSurfaceRuntimeTargetRequest struct {
	SurfaceID   string
	BaseURL     string
	Enabled     bool
	Description string
}
