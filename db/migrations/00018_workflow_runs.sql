-- +goose Up
-- +goose StatementBegin

-- workflow_runs persists every async workflow execution so callers can
-- POST a request, get an id back, and poll status separately. This
-- decouples HTTP request lifetime from workflow execution lifetime —
-- before this table, long workflows (SES identity creation, SES smoke
-- send, multi-step AWS provisioning) hit the 60s ingress timeout and
-- the caller never saw the result even when the run completed
-- successfully on the backend.
--
-- Sync runs (the default for backwards-compat) do NOT use this table —
-- they execute in-band and return the full response. Only async=true
-- runs are persisted here.
CREATE TABLE IF NOT EXISTS public.workflow_runs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_namespace  VARCHAR(64)  NOT NULL,
    workflow_name       VARCHAR(64)  NOT NULL,
    workflow_version    INT,
    workflow_id         UUID,
    status              VARCHAR(32)  NOT NULL DEFAULT 'pending',
    inputs              JSONB        NOT NULL DEFAULT '{}'::jsonb,
    metadata            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    result              JSONB,
    error               TEXT,
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT workflow_runs_status_check
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS workflow_runs_workflow_idx
    ON public.workflow_runs (workflow_namespace, workflow_name, created_at DESC);

CREATE INDEX IF NOT EXISTS workflow_runs_status_idx
    ON public.workflow_runs (status, created_at DESC);

CREATE INDEX IF NOT EXISTS workflow_runs_pending_idx
    ON public.workflow_runs (created_at)
    WHERE status IN ('pending', 'running');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.workflow_runs_pending_idx;
DROP INDEX IF EXISTS public.workflow_runs_status_idx;
DROP INDEX IF EXISTS public.workflow_runs_workflow_idx;
DROP TABLE IF EXISTS public.workflow_runs;

-- +goose StatementEnd
