-- +goose Up
-- +goose StatementBegin

ALTER TABLE public.topology_build_projects
    ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR(32) NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS teardown_workflow_namespace VARCHAR(128),
    ADD COLUMN IF NOT EXISTS teardown_workflow_name VARCHAR(128),
    ADD COLUMN IF NOT EXISTS expiring_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS extended_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS teardown_run_id VARCHAR(128);

-- Index for the lifecycle enforcement loop: find ephemeral + active +
-- expired projects quickly, so the loop touches as few rows as possible.
CREATE INDEX IF NOT EXISTS topology_build_projects_expiring_idx
    ON public.topology_build_projects (lifecycle_status, expires_at)
    WHERE ephemeral = TRUE AND lifecycle_status = 'active';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.topology_build_projects_expiring_idx;

ALTER TABLE public.topology_build_projects
    DROP COLUMN IF EXISTS teardown_run_id,
    DROP COLUMN IF EXISTS extended_at,
    DROP COLUMN IF EXISTS deleted_at,
    DROP COLUMN IF EXISTS expiring_started_at,
    DROP COLUMN IF EXISTS teardown_workflow_name,
    DROP COLUMN IF EXISTS teardown_workflow_namespace,
    DROP COLUMN IF EXISTS lifecycle_status;

-- +goose StatementEnd
