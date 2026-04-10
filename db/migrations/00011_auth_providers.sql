-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.auth_third_party_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'oidc',
    status TEXT NOT NULL DEFAULT 'active',
    display_name TEXT NOT NULL DEFAULT '',
    issuer_url TEXT NOT NULL DEFAULT '',
    authorize_url TEXT NOT NULL DEFAULT '',
    token_url TEXT NOT NULL DEFAULT '',
    userinfo_url TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    client_secret_ref TEXT NOT NULL DEFAULT '',
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    auto_link_by_email BOOLEAN NOT NULL DEFAULT FALSE,
    subject_field TEXT NOT NULL DEFAULT '',
    login_field TEXT NOT NULL DEFAULT '',
    email_field TEXT NOT NULL DEFAULT '',
    display_name_field TEXT NOT NULL DEFAULT '',
    avatar_url_field TEXT NOT NULL DEFAULT '',
    profile_url_field TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_third_party_providers_name_unique UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS auth_third_party_providers_status_type_idx
    ON public.auth_third_party_providers (status, type, name);

DROP TRIGGER IF EXISTS auth_third_party_providers_touch_updated_at ON public.auth_third_party_providers;
CREATE TRIGGER auth_third_party_providers_touch_updated_at
    BEFORE UPDATE ON public.auth_third_party_providers
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS auth_third_party_providers_touch_updated_at ON public.auth_third_party_providers;
DROP TABLE IF EXISTS public.auth_third_party_providers;
-- +goose StatementEnd
