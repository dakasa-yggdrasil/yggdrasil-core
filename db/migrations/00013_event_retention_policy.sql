-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS public.event_retention_policy (
    type_pattern    VARCHAR(128) PRIMARY KEY,
    ttl_days        INTEGER NOT NULL CHECK (ttl_days >= 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.event_retention_policy (type_pattern, ttl_days) VALUES
    ('*', 90),
    ('authorization.*', 2555),
    ('manifest.*', 0),
    ('buildproject.*', 365),
    ('workflow.step.*', 30),
    ('workflow.run.*', 180)
ON CONFLICT (type_pattern) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS public.event_retention_policy;

-- +goose StatementEnd
