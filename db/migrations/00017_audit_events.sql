-- +goose Up
-- +goose StatementBegin

-- audit_events records every state-mutating action that crosses the public API.
-- v2.9.0 (Phase 4 patch): event sourcing for the surface-console audit log,
-- ship-with-evidence migrations, and adopter compliance review. Earlier
-- audit attempts lived in app logs only — those rotate, are not queryable,
-- and do not survive pod restarts.
CREATE TABLE IF NOT EXISTS public.audit_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor         VARCHAR(255) NOT NULL,
    action        VARCHAR(64)  NOT NULL,
    resource_kind VARCHAR(64)  NOT NULL,
    resource_id   VARCHAR(255) NOT NULL,
    outcome       VARCHAR(32)  NOT NULL,
    tenant_slug   VARCHAR(64),
    metadata      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    trace_id      VARCHAR(64),
    span_id       VARCHAR(32),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_events_created_at_idx
    ON public.audit_events (created_at DESC);

CREATE INDEX IF NOT EXISTS audit_events_actor_idx
    ON public.audit_events (actor, created_at DESC);

CREATE INDEX IF NOT EXISTS audit_events_resource_idx
    ON public.audit_events (resource_kind, resource_id, created_at DESC);

CREATE INDEX IF NOT EXISTS audit_events_tenant_idx
    ON public.audit_events (tenant_slug, created_at DESC)
    WHERE tenant_slug IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.audit_events_tenant_idx;
DROP INDEX IF EXISTS public.audit_events_resource_idx;
DROP INDEX IF EXISTS public.audit_events_actor_idx;
DROP INDEX IF EXISTS public.audit_events_created_at_idx;
DROP TABLE IF EXISTS public.audit_events;

-- +goose StatementEnd
