-- +goose Up
-- +goose StatementBegin

-- Heimdall inbox — durable bucket of alert events Heimdall MUST process.
--
-- Existing flow: event_log (durable) → workflow_event_triggers loop (single
-- global cursor) → heimdall-react-on-infra-alert workflow_run. The cursor
-- advances regardless of run outcome and workflow.event.matched is recorded
-- before the dispatch fires, so a failed react run loses the alert
-- permanently — next pass dedups via HasWorkflowEventMatched and skips.
--
-- That's fine for steady-state degradation (queue still high next tick) but
-- breaks for transient incidents that the K8s pod-recovery model creates
-- routinely: OOM → restart → service back in 5s. A spike that fires-then-
-- resolves inside one trigger pass and another pass already advanced the
-- cursor past it has no second chance.
--
-- This table gives Heimdall a per-consumer queue with idempotent insertion
-- (UNIQUE source_event_id), explicit processed_at sentinel for "I'm done
-- with this one", failure_count for poison-pill detection (operator alert
-- when N consecutive failures on the same event_id), and a partial index
-- on the pending bucket for cheap polling.
--
-- The writer (addons/heimdall_inbox_writer.go) tails event_log for
-- infra.alert.firing and copies into inbox under its own cursor — separate
-- from workflow_event_triggers' cursor — so reactive triage runs at
-- Heimdall's own pace, never blocked by other consumers and never starving
-- under cursor contention.

CREATE TABLE IF NOT EXISTS public.heimdall_inbox (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_event_id     UUID NOT NULL REFERENCES public.event_log(event_id) ON DELETE CASCADE,
    aggregate_id        TEXT NOT NULL,
    payload             JSONB NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at        TIMESTAMPTZ,
    failure_count       INTEGER NOT NULL DEFAULT 0,
    last_attempt_at     TIMESTAMPTZ,
    last_failure_reason TEXT,
    dispatched_run_id   UUID,
    UNIQUE(source_event_id)
);

-- Cheap polling index: dispatcher pass scans only pending rows.
CREATE INDEX IF NOT EXISTS heimdall_inbox_pending_idx
    ON public.heimdall_inbox (received_at)
    WHERE processed_at IS NULL;

-- Writer cursor: persists the last event_log id the writer copied from.
-- Single row, id=fixed string. Distinct from workflow_event_trigger_state.
CREATE TABLE IF NOT EXISTS public.heimdall_inbox_writer_state (
    id          TEXT PRIMARY KEY,
    last_cursor TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.heimdall_inbox_writer_state (id, last_cursor)
VALUES ('heimdall_inbox_writer_loop', '')
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS public.heimdall_inbox_writer_state;
DROP INDEX IF EXISTS public.heimdall_inbox_pending_idx;
DROP TABLE IF EXISTS public.heimdall_inbox;

-- +goose StatementEnd
