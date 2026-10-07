-- +goose Up
ALTER TABLE public.team_memberships
    ADD COLUMN IF NOT EXISTS is_lead BOOLEAN NOT NULL DEFAULT FALSE;
-- No guessed backfill from free-form role, job titles or historical owners
-- input. Existing leadership needs a reviewed explicit owner assertion through
-- the canonical team writer after this migration and the new source are live.

-- +goose Down
ALTER TABLE public.team_memberships DROP COLUMN IF EXISTS is_lead;
