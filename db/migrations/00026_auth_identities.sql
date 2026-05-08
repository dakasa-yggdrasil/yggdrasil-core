-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS public.auth_identities (
    collaborator_id UUID PRIMARY KEY REFERENCES public.collaborators(id) ON DELETE CASCADE,
    username CITEXT NOT NULL,
    webauthn_credentials JSONB NOT NULL DEFAULT '[]'::jsonb,
    totp_secret_ciphertext BYTEA NULL,
    totp_secret_dek BYTEA NULL,
    recovery_codes_hashes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    mfa_enrolled_at TIMESTAMPTZ NULL,
    last_login_at TIMESTAMPTZ NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_identities_username_unique UNIQUE (username)
);

CREATE INDEX IF NOT EXISTS auth_identities_mfa_enrolled_idx
    ON public.auth_identities (mfa_enrolled_at) WHERE mfa_enrolled_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS auth_identities_locked_idx
    ON public.auth_identities (locked_until) WHERE locked_until IS NOT NULL;

DROP TRIGGER IF EXISTS auth_identities_touch_updated_at ON public.auth_identities;
CREATE TRIGGER auth_identities_touch_updated_at
    BEFORE UPDATE ON public.auth_identities
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

INSERT INTO public.auth_identities (collaborator_id, username)
SELECT id, LOWER(primary_email)
FROM public.collaborators
WHERE primary_email <> ''
ON CONFLICT (collaborator_id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS auth_identities_touch_updated_at ON public.auth_identities;
DROP TABLE IF EXISTS public.auth_identities;
-- +goose StatementEnd
