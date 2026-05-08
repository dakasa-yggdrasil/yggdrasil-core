-- +goose Up
-- +goose StatementBegin

-- surface_manifests caches the latest manifest fetched from each
-- adapter that exposes GET /surface/manifest. Used by the console
-- list endpoint, the per-page renderer, and the permission catalog
-- reconciler.
--
-- Rows are keyed by surface id (which equals the integration id).
-- They are upserted by internal/surface/discovery on every successful
-- fetch and deleted by DeleteStaleSurfaceManifests when an adapter
-- has been unregistered or hasn't responded for > stale_after.

CREATE TABLE IF NOT EXISTS public.surface_manifests (
    surface_id        TEXT PRIMARY KEY,
    surface_version   TEXT NOT NULL,
    schema_version    INTEGER NOT NULL,
    display_name      TEXT NOT NULL,
    icon              TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    page_count        INTEGER NOT NULL DEFAULT 0,
    widget_count      INTEGER NOT NULL DEFAULT 0,
    permission_count  INTEGER NOT NULL DEFAULT 0,
    raw               JSONB NOT NULL,
    fetched_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    health            TEXT NOT NULL DEFAULT 'unknown',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS surface_manifests_fetched_at_idx
    ON public.surface_manifests (fetched_at DESC);

CREATE INDEX IF NOT EXISTS surface_manifests_health_idx
    ON public.surface_manifests (health);

DROP TRIGGER IF EXISTS surface_manifests_touch_updated_at
    ON public.surface_manifests;
CREATE TRIGGER surface_manifests_touch_updated_at
    BEFORE UPDATE ON public.surface_manifests
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.surface_manifests CASCADE;
-- +goose StatementEnd
