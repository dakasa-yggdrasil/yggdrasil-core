-- +goose Up
-- +goose StatementBegin

-- Append-only audit log of every lifecycle event applied to a
-- collaborator. The collaborator row is the projection (current state);
-- this table is the source of truth for HOW it got there. Never UPDATE
-- or DELETE rows here — corrections are new events (`role-corrected`,
-- `hire-cancelled`).
--
-- effective_at lets callers schedule events in the future (e.g. an
-- offboarded event recorded today with effective_at=2026-06-30 fires the
-- offboard workflow on that date). occurred_at is always now() so audit
-- ordering is durable.

CREATE TABLE IF NOT EXISTS public.lifecycle_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    actor_type      TEXT NOT NULL,
    actor_id        TEXT NOT NULL DEFAULT '',
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT lifecycle_events_actor_type_check
        CHECK (actor_type IN ('human', 'workflow', 'cli', 'api', 'system'))
);

CREATE INDEX IF NOT EXISTS lifecycle_events_collaborator_idx
    ON public.lifecycle_events (collaborator_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS lifecycle_events_type_idx
    ON public.lifecycle_events (event_type, occurred_at DESC);

-- Full index on effective_at (no partial WHERE — NOW() is not IMMUTABLE
-- so partial index predicates rejecting it). Reconcile workers query
-- WHERE effective_at <= NOW() and ORDER BY effective_at LIMIT N — the
-- full index supports both efficiently.
CREATE INDEX IF NOT EXISTS lifecycle_events_effective_at_idx
    ON public.lifecycle_events (effective_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.lifecycle_events_effective_at_idx;
DROP INDEX IF EXISTS public.lifecycle_events_type_idx;
DROP INDEX IF EXISTS public.lifecycle_events_collaborator_idx;
DROP TABLE IF EXISTS public.lifecycle_events;

-- +goose StatementEnd
