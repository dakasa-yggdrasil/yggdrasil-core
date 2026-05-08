-- +goose Up
-- +goose StatementBegin

-- Phase 2 of yggdrasil-console-ops: extend audit_events to record the
-- richer payload required by /api/v1/ops/*. Existing columns stay; new
-- columns are nullable so legacy callers (RecordAuditEvent without
-- collaborator id) keep working.
ALTER TABLE public.audit_events
    ADD COLUMN IF NOT EXISTS actor_collaborator_id UUID,
    ADD COLUMN IF NOT EXISTS actor_session_id      TEXT,
    ADD COLUMN IF NOT EXISTS correlation_id        TEXT,
    ADD COLUMN IF NOT EXISTS request_body          JSONB,
    ADD COLUMN IF NOT EXISTS result                JSONB,
    ADD COLUMN IF NOT EXISTS result_status         TEXT;

-- result_status, when set, must match the spec enum. Older rows have NULL
-- and are exempt; new ops rows populate it.
ALTER TABLE public.audit_events
    DROP CONSTRAINT IF EXISTS audit_events_result_status_check;
ALTER TABLE public.audit_events
    ADD CONSTRAINT audit_events_result_status_check
    CHECK (result_status IS NULL
           OR result_status IN ('success', 'denied', 'error', 'pending'));

CREATE INDEX IF NOT EXISTS audit_events_actor_collaborator_idx
    ON public.audit_events (actor_collaborator_id, created_at DESC)
    WHERE actor_collaborator_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_events_correlation_idx
    ON public.audit_events (correlation_id)
    WHERE correlation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_events_action_prefix_idx
    ON public.audit_events (action text_pattern_ops, created_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.audit_events_actor_collaborator_idx;
DROP INDEX IF EXISTS public.audit_events_correlation_idx;
DROP INDEX IF EXISTS public.audit_events_action_prefix_idx;

ALTER TABLE public.audit_events
    DROP CONSTRAINT IF EXISTS audit_events_result_status_check;

ALTER TABLE public.audit_events
    DROP COLUMN IF EXISTS result_status,
    DROP COLUMN IF EXISTS result,
    DROP COLUMN IF EXISTS request_body,
    DROP COLUMN IF EXISTS correlation_id,
    DROP COLUMN IF EXISTS actor_session_id,
    DROP COLUMN IF EXISTS actor_collaborator_id;

-- +goose StatementEnd
