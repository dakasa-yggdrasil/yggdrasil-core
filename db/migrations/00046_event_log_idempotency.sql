-- +goose Up
-- +goose StatementBegin

-- Adds an optional idempotency_key on public.event_log so callers (notably
-- adapter pods emitting <provider>.<resource>.<verb_past> mutation events
-- per INTEGRATION_CONTRACT §6.5) can safely retry a POST /api/v1/events
-- without duplicating the row.
--
-- Dedup scope is (type, idempotency_key) — same scope the contract describes
-- ("dedup key for re-emissions" of the same logical mutation). Nullable so
-- the column stays optional for all existing emitters (manifest sync,
-- workflow runs, team grants, …) that don't carry an idempotency key.
ALTER TABLE public.event_log
    ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(256);

-- Partial unique index: dedup applies only to rows that carry a key, so
-- emitters without one are not affected and we don't pay UNIQUE overhead
-- on the legacy 99% of inserts. The 24h soft window noted in the spec is
-- enforced at the application layer (INSERT … ON CONFLICT DO NOTHING then
-- SELECT existing event_id) — Postgres has no native TTL on unique
-- constraints. Cleanup happens via the existing event_retention_policy
-- machinery (CleanupExpiredEvents): when the older row falls past TTL,
-- the unique slot frees up automatically.
CREATE UNIQUE INDEX IF NOT EXISTS event_log_idempotency_unique_idx
    ON public.event_log (type, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS event_log_idempotency_unique_idx;
ALTER TABLE public.event_log DROP COLUMN IF EXISTS idempotency_key;

-- +goose StatementEnd
