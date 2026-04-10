-- +goose Up
-- +goose StatementBegin
CREATE UNIQUE INDEX IF NOT EXISTS collaborators_primary_email_uidx
    ON public.collaborators (LOWER(primary_email))
    WHERE primary_email <> '';

CREATE TABLE IF NOT EXISTS public.collaborator_password_credentials (
    collaborator_id UUID PRIMARY KEY REFERENCES public.collaborators(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active',
    password_scheme TEXT NOT NULL DEFAULT 'pbkdf2_sha256',
    password_hash TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    password_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS collaborator_password_credentials_touch_updated_at ON public.collaborator_password_credentials;
CREATE TRIGGER collaborator_password_credentials_touch_updated_at
    BEFORE UPDATE ON public.collaborator_password_credentials
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active',
    token_hash TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_seen_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_sessions_token_hash_unique UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS auth_sessions_collaborator_status_idx
    ON public.auth_sessions (collaborator_id, status, expires_at DESC);

CREATE INDEX IF NOT EXISTS auth_sessions_status_expires_idx
    ON public.auth_sessions (status, expires_at DESC);

DROP TRIGGER IF EXISTS auth_sessions_touch_updated_at ON public.auth_sessions;
CREATE TRIGGER auth_sessions_touch_updated_at
    BEFORE UPDATE ON public.auth_sessions
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS auth_sessions_touch_updated_at ON public.auth_sessions;
DROP TABLE IF EXISTS public.auth_sessions;

DROP TRIGGER IF EXISTS collaborator_password_credentials_touch_updated_at ON public.collaborator_password_credentials;
DROP TABLE IF EXISTS public.collaborator_password_credentials;

DROP INDEX IF EXISTS collaborators_primary_email_uidx;
-- +goose StatementEnd
