-- +goose Up
-- +goose StatementBegin

-- Phase 1: estende collaborators com colunas de lifecycle (version pra
-- optimistic locking, timezone/locale pra scheduling, role como coluna
-- queryable separada do employment_data JSONB, mfa_enrolled_at pra gate
-- de provisioning downstream). CHECK constraint canoniza valores aceitos
-- de status. Backfill converte rows existentes pra 'active'.

ALTER TABLE public.collaborators
    ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 0;

ALTER TABLE public.collaborators
    ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'America/Sao_Paulo';

ALTER TABLE public.collaborators
    ADD COLUMN IF NOT EXISTS locale TEXT NOT NULL DEFAULT 'pt-BR';

ALTER TABLE public.collaborators
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT '';

ALTER TABLE public.collaborators
    ADD COLUMN IF NOT EXISTS mfa_enrolled_at TIMESTAMPTZ NULL;

-- Backfill any unrecognized status to 'active' before adding the CHECK.
UPDATE public.collaborators
SET status = 'active'
WHERE status NOT IN ('pending_start', 'active', 'on_leave', 'suspended', 'offboarded');

-- Add the CHECK constraint guarding the canonical set.
ALTER TABLE public.collaborators
    DROP CONSTRAINT IF EXISTS collaborators_status_check;

ALTER TABLE public.collaborators
    ADD CONSTRAINT collaborators_status_check
    CHECK (status IN ('pending_start', 'active', 'on_leave', 'suspended', 'offboarded'));

-- Promote primary_email to a unique identifier. Existing empty defaults
-- (`''`) would conflict, so the index excludes them; production rows
-- always populate primary_email after Phase 1 cutover.
CREATE UNIQUE INDEX IF NOT EXISTS collaborators_primary_email_uidx
    ON public.collaborators (LOWER(primary_email))
    WHERE primary_email <> '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.collaborators_primary_email_uidx;

ALTER TABLE public.collaborators
    DROP CONSTRAINT IF EXISTS collaborators_status_check;

ALTER TABLE public.collaborators DROP COLUMN IF EXISTS mfa_enrolled_at;
ALTER TABLE public.collaborators DROP COLUMN IF EXISTS role;
ALTER TABLE public.collaborators DROP COLUMN IF EXISTS locale;
ALTER TABLE public.collaborators DROP COLUMN IF EXISTS timezone;
ALTER TABLE public.collaborators DROP COLUMN IF EXISTS version;

-- +goose StatementEnd
