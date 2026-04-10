-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS public.event_log (
    event_id        UUID PRIMARY KEY,
    sequence        BIGSERIAL NOT NULL UNIQUE,
    type            VARCHAR(128) NOT NULL,
    schema_version  VARCHAR(16) NOT NULL DEFAULT 'v1',
    aggregate_type  VARCHAR(64) NOT NULL,
    aggregate_id    VARCHAR(128) NOT NULL,
    actor_type      VARCHAR(32),
    actor_id        VARCHAR(128),
    actor_context   JSONB,
    emitted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload         JSONB NOT NULL,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS event_log_sequence_idx ON public.event_log (sequence);
CREATE INDEX IF NOT EXISTS event_log_type_sequence_idx ON public.event_log (type, sequence);
CREATE INDEX IF NOT EXISTS event_log_aggregate_idx ON public.event_log (aggregate_type, aggregate_id, sequence);
CREATE INDEX IF NOT EXISTS event_log_emitted_at_idx ON public.event_log (emitted_at);
CREATE INDEX IF NOT EXISTS event_log_type_emitted_idx ON public.event_log (type, emitted_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS public.event_log;

-- +goose StatementEnd
