-- +goose Up
-- +goose StatementBegin

-- surface_runtime_targets keeps the adapter endpoints that the ops
-- console may manage at runtime. The table stores only generic surface
-- ids and base URLs; each adopter decides which adapters exist in its
-- own deployment topology.
CREATE TABLE IF NOT EXISTS public.surface_runtime_targets (
    surface_id   TEXT PRIMARY KEY,
    base_url     TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    description  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS surface_runtime_targets_enabled_idx
    ON public.surface_runtime_targets (enabled);

DROP TRIGGER IF EXISTS surface_runtime_targets_touch_updated_at
    ON public.surface_runtime_targets;
CREATE TRIGGER surface_runtime_targets_touch_updated_at
    BEFORE UPDATE ON public.surface_runtime_targets
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.surface_runtime_targets CASCADE;
-- +goose StatementEnd
