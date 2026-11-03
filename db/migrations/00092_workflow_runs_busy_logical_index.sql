-- +goose NO TRANSACTION
-- +goose Up
-- Keep the complete workflow busy predicate and both identity arms unchanged.
-- Cover the logical namespace/name arm and its run-id projection, including
-- nonterminal rows with a finished_at and terminal rows without one. This
-- additive, nonunique partial index excludes only completely finished history.
-- CONCURRENTLY avoids blocking normal workflow writes during index creation.
-- IF NOT EXISTS is name-idempotency only: after any attempted application,
-- operators must verify the actual definition and pg_index valid/ready/live
-- flags. An invalid or differently defined same-name index is a HOLD requiring
-- separate review; this migration never drops or repairs it automatically.
CREATE INDEX CONCURRENTLY IF NOT EXISTS workflow_runs_busy_logical_idx
    ON public.workflow_runs (workflow_namespace, workflow_name, id)
    WHERE (COALESCE(status,'') NOT IN ('succeeded','failed','cancelled') OR finished_at IS NULL);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS public.workflow_runs_busy_logical_idx;
