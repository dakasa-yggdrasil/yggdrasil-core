-- +goose Up
CREATE TABLE IF NOT EXISTS public.capacity_native_commands (
    id UUID PRIMARY KEY,
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    generation BIGINT NOT NULL,
    operation TEXT NOT NULL,
    phase TEXT NOT NULL,
    subject_uid TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    authority_token_sha256 TEXT NOT NULL UNIQUE,
    command_record JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (namespace, environment, domain, dimension, generation, operation, subject_uid, phase)
);
CREATE INDEX IF NOT EXISTS capacity_native_commands_scope_idx
    ON public.capacity_native_commands (namespace, environment, domain, dimension, generation, state);

CREATE TABLE IF NOT EXISTS public.capacity_native_pod_checkpoints (
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    generation BIGINT NOT NULL,
    pod_uid TEXT NOT NULL,
    checkpoint_record JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace, environment, domain, dimension, generation, pod_uid)
);

CREATE TABLE IF NOT EXISTS public.capacity_native_scope_owners (
    native_uid TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    owner_scope JSONB NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS public.capacity_native_scope_owners;
DROP TABLE IF EXISTS public.capacity_native_pod_checkpoints;
DROP TABLE IF EXISTS public.capacity_native_commands;
