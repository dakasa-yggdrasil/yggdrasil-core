-- +goose Up
-- +goose StatementBegin

-- Async workflow dispatch is the durable boundary used by Guardian after an
-- approval. A stable caller-supplied key makes retries (including a retry after
-- the provider run was accepted but the approval status write failed) converge
-- on the same run instead of reaching the provider twice.
CREATE UNIQUE INDEX IF NOT EXISTS workflow_runs_idempotency_unique_idx
    ON public.workflow_runs ((metadata ->> 'idempotency_key'))
    WHERE NULLIF(metadata ->> 'idempotency_key', '') IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.workflow_runs_idempotency_unique_idx;

-- +goose StatementEnd
