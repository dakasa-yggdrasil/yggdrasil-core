-- +goose Up
-- +goose StatementBegin

-- Schedule triggers: tracks the last fire time per workflow so the scheduler
-- loop can compute the next fire time and avoid double-firing.
CREATE TABLE IF NOT EXISTS public.workflow_schedule_state (
    workflow_manifest_id  UUID PRIMARY KEY REFERENCES public.manifests(id) ON DELETE CASCADE,
    last_fired_at         TIMESTAMPTZ NOT NULL,
    next_fire_at          TIMESTAMPTZ NOT NULL,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS workflow_schedule_state_next_fire_idx
    ON public.workflow_schedule_state (next_fire_at);

-- Event triggers: single-row table holding the cursor for the event trigger
-- subscription loop. Core workers coordinate via pg_try_advisory_lock so only
-- one worker holds the "leader" role at a time and processes events.
CREATE TABLE IF NOT EXISTS public.workflow_event_trigger_state (
    id           VARCHAR(64) PRIMARY KEY,
    last_cursor  TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.workflow_event_trigger_state (id, last_cursor)
VALUES ('workflow_event_trigger_loop', '')
ON CONFLICT (id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS public.workflow_event_trigger_state;
DROP TABLE IF EXISTS public.workflow_schedule_state;

-- +goose StatementEnd
