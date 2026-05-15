-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.auth_credential_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
  purpose         TEXT NOT NULL CHECK (purpose IN ('setup','reset')),
  token_hash      TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  consumed_at     TIMESTAMPTZ NULL,
  created_by      UUID NULL REFERENCES public.collaborators(id),
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT auth_credential_tokens_hash_unique UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS auth_credential_tokens_active_idx
  ON public.auth_credential_tokens (collaborator_id, purpose)
  WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS auth_credential_tokens_expires_idx
  ON public.auth_credential_tokens (expires_at)
  WHERE consumed_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.auth_credential_tokens;
-- +goose StatementEnd
