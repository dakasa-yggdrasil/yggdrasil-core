-- +goose Up
-- +goose StatementBegin

-- Adds a metadata JSONB column on public.manifests for arbitrary
-- annotations attached at write time. First use case: the warn-only
-- capability-naming validator (Phase 1 of the integration convention
-- rollout) persists a `{"warnings":[...]}` blob so the console can
-- render a conformance badge without re-running the validator on
-- every page load.
--
-- Defaults to '{}' so existing rows and writes that don't set it stay
-- well-formed JSON. No CHECK constraint: callers own the shape.
ALTER TABLE public.manifests
    ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.manifests DROP COLUMN IF EXISTS metadata;
-- +goose StatementEnd
