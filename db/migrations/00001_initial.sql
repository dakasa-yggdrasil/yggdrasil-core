-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION public.touch_updated_at() RETURNS trigger
    LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TABLE IF NOT EXISTS public.manifests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_version TEXT NOT NULL,
    kind TEXT NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    spec JSONB NOT NULL,
    checksum TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS manifests_identity_version_uidx
    ON public.manifests (kind, namespace, name, version);

CREATE UNIQUE INDEX IF NOT EXISTS manifests_single_active_uidx
    ON public.manifests (kind, namespace, name)
    WHERE active = TRUE;

CREATE INDEX IF NOT EXISTS manifests_lookup_idx
    ON public.manifests (kind, namespace, name, version DESC);

DROP TRIGGER IF EXISTS manifests_touch_updated_at ON public.manifests;
CREATE TRIGGER manifests_touch_updated_at
    BEFORE UPDATE ON public.manifests
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS manifests_touch_updated_at ON public.manifests;
DROP TABLE IF EXISTS public.manifests;
DROP FUNCTION IF EXISTS public.touch_updated_at();
-- +goose StatementEnd
