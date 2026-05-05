-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.oidc_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}'::TEXT[],
    scopes TEXT[] NOT NULL DEFAULT ARRAY['openid','email','profile','roles'],
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code','refresh_token'],
    pkce_required BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.oidc_auth_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id TEXT NOT NULL REFERENCES public.oidc_clients(client_id),
    collaborator_id UUID NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    code_challenge TEXT NULL,
    code_challenge_method TEXT NULL,
    state TEXT NULL,
    nonce TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS oidc_auth_requests_expires_idx
    ON public.oidc_auth_requests (expires_at);

CREATE TABLE IF NOT EXISTS public.oidc_auth_codes (
    code TEXT PRIMARY KEY,
    auth_request_id UUID NOT NULL REFERENCES public.oidc_auth_requests(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS oidc_auth_codes_expires_idx
    ON public.oidc_auth_codes (expires_at);

CREATE TABLE IF NOT EXISTS public.oidc_refresh_tokens (
    token TEXT PRIMARY KEY,
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES public.oidc_clients(client_id),
    scopes TEXT[] NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_from TEXT NULL REFERENCES public.oidc_refresh_tokens(token) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS oidc_refresh_tokens_lookup_idx
    ON public.oidc_refresh_tokens (collaborator_id, revoked_at);

CREATE TABLE IF NOT EXISTS public.oidc_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm TEXT NOT NULL DEFAULT 'RS256',
    private_pem TEXT NOT NULL,
    public_jwk JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_at TIMESTAMPTZ NOT NULL,
    retire_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS public.oidc_provider_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    allowed_email_domains TEXT[] NOT NULL DEFAULT ARRAY['dakasa.me'],
    default_team_slug TEXT NOT NULL DEFAULT 'dakasa-internal',
    auto_provision BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (singleton = TRUE)
);
INSERT INTO public.oidc_provider_settings (singleton) VALUES (TRUE)
    ON CONFLICT (singleton) DO NOTHING;

-- Seed teams: 4 access groups for SSO
-- The teams table (00002_core_identities.sql) has no CHECK constraint on
-- the "type" column, so 'access_group' is accepted as-is. The "description"
-- column does not exist on teams, so we omit it from the INSERT.
INSERT INTO public.teams (slug, type, status, name) VALUES
  ('dakasa-internal',  'access_group', 'active', 'DaKasa Internal'),
  ('yggdrasil-admin',  'access_group', 'active', 'Yggdrasil Admin'),
  ('tartaro-mod',      'access_group', 'active', 'Tartaro Moderator'),
  ('tartaro-auditor',  'access_group', 'active', 'Tartaro Auditor')
ON CONFLICT (slug) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.oidc_provider_settings;
DROP TABLE IF EXISTS public.oidc_signing_keys;
DROP TABLE IF EXISTS public.oidc_refresh_tokens;
DROP TABLE IF EXISTS public.oidc_auth_codes;
DROP TABLE IF EXISTS public.oidc_auth_requests;
DROP TABLE IF EXISTS public.oidc_clients;
DELETE FROM public.teams WHERE slug IN ('dakasa-internal','yggdrasil-admin','tartaro-mod','tartaro-auditor');
-- +goose StatementEnd
