-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.managed_secrets
    ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS rotation JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS last_rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL;

UPDATE public.managed_secrets
SET
    version = COALESCE(version, 1),
    rotation = COALESCE(rotation, '{}'::jsonb),
    last_rotated_at = COALESCE(last_rotated_at, updated_at, created_at, NOW())
WHERE version IS NULL
   OR rotation IS NULL
   OR last_rotated_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE public.managed_secrets
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS last_rotated_at,
    DROP COLUMN IF EXISTS rotation,
    DROP COLUMN IF EXISTS version;
-- +goose StatementEnd
