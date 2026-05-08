-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.mfa_enroll_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mfa_enroll_tokens_token_hash_unique UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS mfa_enroll_tokens_collab_idx
    ON public.mfa_enroll_tokens (collaborator_id, consumed_at, expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.mfa_enroll_tokens;
-- +goose StatementEnd
