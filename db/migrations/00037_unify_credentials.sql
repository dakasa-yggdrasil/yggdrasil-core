-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.auth_identities
  ADD COLUMN password_hash         TEXT          NULL,
  ADD COLUMN password_scheme       TEXT          NULL,
  ADD COLUMN password_updated_at   TIMESTAMPTZ   NULL,
  ADD COLUMN password_expires_at   TIMESTAMPTZ   NULL,
  ADD COLUMN password_must_change  BOOLEAN       NOT NULL DEFAULT false,
  ADD COLUMN password_metadata     JSONB         NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX auth_identities_password_expires_idx
  ON public.auth_identities (password_expires_at)
  WHERE password_expires_at IS NOT NULL;

UPDATE public.auth_identities ai
SET password_hash       = cpc.password_hash,
    password_scheme     = cpc.password_scheme,
    password_updated_at = cpc.password_updated_at,
    password_metadata   = cpc.metadata
FROM public.collaborator_password_credentials cpc
WHERE ai.collaborator_id = cpc.collaborator_id;

DROP TRIGGER IF EXISTS collaborator_password_credentials_touch_updated_at ON public.collaborator_password_credentials;
DROP TABLE public.collaborator_password_credentials;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE public.collaborator_password_credentials (
    collaborator_id UUID PRIMARY KEY REFERENCES public.collaborators(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active',
    password_scheme TEXT NOT NULL DEFAULT 'pbkdf2_sha256',
    password_hash TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    password_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER collaborator_password_credentials_touch_updated_at
    BEFORE UPDATE ON public.collaborator_password_credentials
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

INSERT INTO public.collaborator_password_credentials
    (collaborator_id, status, password_scheme, password_hash, metadata, password_updated_at)
SELECT collaborator_id, 'active', COALESCE(password_scheme, 'pbkdf2_sha256'),
       password_hash, password_metadata, COALESCE(password_updated_at, NOW())
FROM public.auth_identities
WHERE password_hash IS NOT NULL;

DROP INDEX IF EXISTS auth_identities_password_expires_idx;

ALTER TABLE public.auth_identities
  DROP COLUMN password_metadata,
  DROP COLUMN password_must_change,
  DROP COLUMN password_expires_at,
  DROP COLUMN password_updated_at,
  DROP COLUMN password_scheme,
  DROP COLUMN password_hash;
-- +goose StatementEnd
