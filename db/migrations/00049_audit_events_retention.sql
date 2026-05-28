-- +goose Up
-- +goose StatementBegin

-- audit_events retention (G7): the table grows unbounded otherwise.
-- LGPD aligns at 2 years for general business records; the
-- `audit_events_retention` addon enforces this cadence with a 6h
-- cron-style sweep. Security-critical action codes are exempt from
-- deletion by addon logic (auth.login.*, auth.mfa.*, auth.session.*)
-- to satisfy the longer legal retention required for security
-- incident forensics — see addons/audit_events_retention.go for the
-- code-prefix exemption list.
--
-- We store the eviction deadline directly on the row so the addon's
-- sweep is a cheap `WHERE expires_at < NOW()` instead of computing
-- the offset client-side on every pass. Backfill existing rows with
-- the same 2-year horizon relative to their created_at.

ALTER TABLE public.audit_events
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Backfill: every row that doesn't yet carry an expires_at gets the
-- default 2-year horizon. Done in a single statement; the table is
-- small enough at the current operational scale that we can
-- afford the lock. Future schema additions for retention exemption
-- should add a new column rather than complicate this clause.
UPDATE public.audit_events
   SET expires_at = created_at + INTERVAL '2 years'
 WHERE expires_at IS NULL;

-- Default for new rows. Statement-level so existing INSERTs without
-- an explicit expires_at value get the canonical 2y window.
ALTER TABLE public.audit_events
    ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '2 years');

-- Partial index covers the cleanup sweep (WHERE expires_at < NOW())
-- without holding a btree page for every row in the table.
CREATE INDEX IF NOT EXISTS audit_events_expires_at_idx
    ON public.audit_events (expires_at)
    WHERE expires_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.audit_events_expires_at_idx;
ALTER TABLE public.audit_events ALTER COLUMN expires_at DROP DEFAULT;
ALTER TABLE public.audit_events DROP COLUMN IF EXISTS expires_at;

-- +goose StatementEnd
