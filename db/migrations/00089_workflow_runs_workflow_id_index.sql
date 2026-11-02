-- +goose NO TRANSACTION
-- +goose Up
-- Keep the complete workflow busy predicate unchanged. Its UUID identity arm
-- needs an index alongside the existing namespace/name index, including rows
-- whose UUID and catalog names disagree. CONCURRENTLY avoids blocking normal
-- workflow writes while this additive, nonunique index is built.
-- IF NOT EXISTS is name-idempotency only: after any attempted application,
-- operators must verify the actual definition and pg_index valid/ready/live
-- flags. An invalid or differently defined same-name index is a HOLD requiring
-- separate review; this migration never drops or repairs it automatically.
CREATE INDEX CONCURRENTLY IF NOT EXISTS workflow_runs_workflow_id_idx
    ON public.workflow_runs (workflow_id);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS public.workflow_runs_workflow_id_idx;
