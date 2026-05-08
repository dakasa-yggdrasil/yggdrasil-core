-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.scim_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    bearer_token_hash TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '{"users":"read","groups":"read"}'::jsonb,
    last_used_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT scim_clients_slug_unique UNIQUE (slug),
    CONSTRAINT scim_clients_bearer_token_hash_unique UNIQUE (bearer_token_hash)
);

CREATE INDEX IF NOT EXISTS scim_clients_active_idx
    ON public.scim_clients (revoked_at, expires_at) WHERE revoked_at IS NULL;

DROP TRIGGER IF EXISTS scim_clients_touch_updated_at ON public.scim_clients;
CREATE TRIGGER scim_clients_touch_updated_at
    BEFORE UPDATE ON public.scim_clients
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS scim_clients_touch_updated_at ON public.scim_clients;
DROP TABLE IF EXISTS public.scim_clients;
-- +goose StatementEnd
