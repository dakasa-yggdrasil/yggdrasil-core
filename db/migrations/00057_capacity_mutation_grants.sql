-- +goose Up
CREATE TABLE IF NOT EXISTS public.capacity_mutation_grants (
    id UUID PRIMARY KEY,
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    generation BIGINT NOT NULL,
    integration_instance_id UUID NOT NULL,
    scope_checksum TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    slot INTEGER NOT NULL CHECK (slot > 0),
    state TEXT NOT NULL CHECK (state IN ('issued','redeemed','settled','confirmed','rejected','expired')),
    grant_record JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_mutation_grants_open_slot_idx
    ON public.capacity_mutation_grants (integration_instance_id, scope_checksum, profile_name, slot)
    WHERE state IN ('issued','redeemed','settled');
CREATE INDEX IF NOT EXISTS capacity_mutation_grants_scope_idx
    ON public.capacity_mutation_grants (namespace,environment,domain,dimension,generation,state);

CREATE TABLE IF NOT EXISTS public.capacity_resource_slots (
    integration_instance_id UUID NOT NULL,
    scope_checksum TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    slot INTEGER NOT NULL CHECK (slot > 0),
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    slot_record JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (integration_instance_id,scope_checksum,profile_name,slot)
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_resource_slots_resource_idx
    ON public.capacity_resource_slots (integration_instance_id,resource_id)
    WHERE resource_id <> '';
CREATE INDEX IF NOT EXISTS capacity_resource_slots_scope_idx
    ON public.capacity_resource_slots (namespace,environment,domain,dimension);

-- No lease expiry or retention job removes redeemed grants or slot tombstones.
-- +goose Down
DROP TABLE IF EXISTS public.capacity_resource_slots;
DROP TABLE IF EXISTS public.capacity_mutation_grants;
