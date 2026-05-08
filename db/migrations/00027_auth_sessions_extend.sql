-- +goose Up
-- +goose StatementBegin
ALTER TABLE public.auth_sessions
    ADD COLUMN IF NOT EXISTS device_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ip_address INET NULL,
    ADD COLUMN IF NOT EXISTS step_up_authenticated_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS auth_sessions_device_idx
    ON public.auth_sessions (collaborator_id, device_fingerprint)
    WHERE device_fingerprint <> '';

CREATE INDEX IF NOT EXISTS auth_sessions_step_up_idx
    ON public.auth_sessions (step_up_authenticated_at)
    WHERE step_up_authenticated_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS auth_sessions_step_up_idx;
DROP INDEX IF EXISTS auth_sessions_device_idx;
ALTER TABLE public.auth_sessions
    DROP COLUMN IF EXISTS step_up_authenticated_at,
    DROP COLUMN IF EXISTS ip_address,
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS device_fingerprint;
-- +goose StatementEnd
