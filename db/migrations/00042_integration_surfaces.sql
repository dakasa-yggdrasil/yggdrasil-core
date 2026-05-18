-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS integration_surfaces (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text NOT NULL UNIQUE,
    integration_type text,
    category         text NOT NULL CHECK (category IN ('integration','core','domain')),
    spec             jsonb NOT NULL,
    active           boolean NOT NULL DEFAULT true,
    registered_at    timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Note: no FK to integration_types(name) — that table is keyed by uuid, and surfaces
-- reference integration_types by their canonical name string. Enforcement is at the
-- application layer (the syncer rejects unknown types).

CREATE INDEX IF NOT EXISTS integration_surfaces_active_idx
    ON integration_surfaces (active) WHERE active;

CREATE INDEX IF NOT EXISTS integration_surfaces_appears_on_idx
    ON integration_surfaces USING gin ((spec->'display'->'appears_on'));

CREATE INDEX IF NOT EXISTS integration_surfaces_integration_type_idx
    ON integration_surfaces (integration_type) WHERE active;

DROP TRIGGER IF EXISTS integration_surfaces_touch_updated_at ON integration_surfaces;
CREATE TRIGGER integration_surfaces_touch_updated_at
    BEFORE UPDATE ON integration_surfaces
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS integration_surfaces CASCADE;
-- +goose StatementEnd
