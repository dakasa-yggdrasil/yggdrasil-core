-- +goose Up
-- +goose StatementBegin
-- Operator-owned dispatch control is keyed by the logical instance, not a
-- manifest version. A manifest re-apply must never reset a pause.
CREATE TABLE IF NOT EXISTS public.integration_reactor_dispatch_policies (
    namespace          TEXT NOT NULL,
    name               TEXT NOT NULL,
    paused_event_types TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    revision           BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (namespace, name)
);

DROP TRIGGER IF EXISTS integration_reactor_dispatch_policies_touch_updated_at
    ON public.integration_reactor_dispatch_policies;
CREATE TRIGGER integration_reactor_dispatch_policies_touch_updated_at
    BEFORE UPDATE ON public.integration_reactor_dispatch_policies
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();

CREATE INDEX IF NOT EXISTS iers_paused_backlog_idx
    ON public.integration_event_reactions (integration_instance_id, event_type, created_at)
    WHERE status IN ('pending', 'failed', 'in_progress');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS integration_reactor_dispatch_policies_touch_updated_at
    ON public.integration_reactor_dispatch_policies;
DROP INDEX IF EXISTS public.iers_paused_backlog_idx;
DROP TABLE IF EXISTS public.integration_reactor_dispatch_policies;
-- +goose StatementEnd
