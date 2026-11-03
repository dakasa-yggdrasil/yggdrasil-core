-- +goose Up
CREATE TABLE IF NOT EXISTS public.capacity_intents (
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    intent JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace, environment, domain, dimension)
);

CREATE TABLE IF NOT EXISTS public.capacity_intent_events (
    id BIGSERIAL PRIMARY KEY,
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    generation BIGINT NOT NULL,
    fencing_token BIGINT NOT NULL,
    phase TEXT NOT NULL,
    receipt_ref TEXT NOT NULL DEFAULT '',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS capacity_intent_events_scope_idx
    ON public.capacity_intent_events (namespace, environment, domain, dimension, id DESC);
CREATE INDEX IF NOT EXISTS capacity_intent_events_retention_idx
    ON public.capacity_intent_events (recorded_at);

-- +goose Down
DROP TABLE IF EXISTS public.capacity_intent_events;
DROP TABLE IF EXISTS public.capacity_intents;
