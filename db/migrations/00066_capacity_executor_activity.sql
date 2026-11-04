-- +goose Up
-- Activity is demand and a shutdown prerequisite, never a provider mutation grant.
-- No row is implicitly created on heartbeat; initialization is an explicit,
-- authorized workflow operation. Missing storage cannot mean an idle executor.
CREATE TABLE IF NOT EXISTS public.capacity_executor_activity (
    scope_key TEXT PRIMARY KEY CHECK (length(scope_key) BETWEEN 1 AND 256),
    binding_sha256 TEXT NOT NULL CHECK (binding_sha256 ~ '^[a-f0-9]{64}$'),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision BETWEEN 0 AND 9007199254740990),
    state JSONB NOT NULL CHECK (jsonb_typeof(state) = 'object' AND octet_length(state::text) <= 2097152),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (state ?& ARRAY['revision','tasks','updated_at']),
    CHECK (jsonb_typeof(state->'revision') = 'number'),
    CHECK (jsonb_typeof(state->'tasks') = 'object'),
    CHECK ((state->>'revision')::BIGINT = revision)
);

-- +goose Down
-- Deliberately no automatic DROP: possible_send records and replay tombstones
-- must survive rollback. Archival/removal requires explicit operator review.
SELECT 1;
