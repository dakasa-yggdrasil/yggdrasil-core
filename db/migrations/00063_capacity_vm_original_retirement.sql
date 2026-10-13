-- +goose Up
-- Every provisioning/retirement identity is permanent. Original partial or
-- uncertain results remain reserved; expiry or a GET never creates a retry.
CREATE TABLE IF NOT EXISTS public.capacity_vm_provisioning_preregistrations (
    id UUID PRIMARY KEY,
    create_grant_id UUID NOT NULL UNIQUE REFERENCES public.capacity_mutation_grants(id),
    nonce_sha256 TEXT NOT NULL UNIQUE,
    profile_manifest_sha256 TEXT NOT NULL,
    preregistration_record JSONB NOT NULL,
    original_deadline TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_vm_original_enrollments (
    preregistration_id UUID PRIMARY KEY REFERENCES public.capacity_vm_provisioning_preregistrations(id),
    resource_tuple_sha256 TEXT NOT NULL UNIQUE,
    enrollment_sha256 TEXT NOT NULL UNIQUE,
    original_provisioning_sha256 TEXT NOT NULL,
    enrollment_record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_vm_retirement_intents (
    id UUID PRIMARY KEY,
    preregistration_id UUID NOT NULL UNIQUE REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
    attempt_id UUID NOT NULL UNIQUE,
    nonce_sha256 TEXT NOT NULL UNIQUE,
    intent_sha256 TEXT NOT NULL UNIQUE,
    intent_record JSONB NOT NULL,
    original_deadline TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_vm_retirement_original_returns (
    intent_id UUID NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    kind TEXT NOT NULL,
    previous_sha256 TEXT NOT NULL,
    return_sha256 TEXT NOT NULL UNIQUE,
    original_return_record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (intent_id, sequence)
);
CREATE TABLE IF NOT EXISTS public.capacity_vm_retirement_delete_bindings (
    destroy_grant_id UUID PRIMARY KEY REFERENCES public.capacity_mutation_grants(id),
    intent_id UUID NOT NULL UNIQUE REFERENCES public.capacity_vm_retirement_intents(id),
    eligibility_sha256 TEXT NOT NULL,
    original_eligibility_record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);
-- Native readback is append-only and never establishes writer quiescence.
-- Historical accepted originals lacking Guest enrollment can be retained here
-- without tombstoning the slot or upgrading an uncertain owning DELETE.
CREATE TABLE IF NOT EXISTS public.capacity_vm_retirement_native_readbacks (
    id UUID PRIMARY KEY,
    destroy_grant_id UUID NOT NULL REFERENCES public.capacity_mutation_grants(id),
    observation_sha256 TEXT NOT NULL,
    original_observation_record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE (destroy_grant_id, observation_sha256)
);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_vm_original_retirement_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'original VM provisioning, enrollment, intent and return records are immutable';
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE
    relation_name TEXT;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'capacity_vm_provisioning_preregistrations',
        'capacity_vm_original_enrollments',
        'capacity_vm_retirement_intents',
        'capacity_vm_retirement_original_returns',
        'capacity_vm_retirement_delete_bindings',
        'capacity_vm_retirement_native_readbacks'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname=relation_name || '_immutable' AND tgrelid=('public.' || relation_name)::regclass) THEN
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable()', relation_name || '_immutable', relation_name);
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
-- +goose Down
DROP TABLE IF EXISTS public.capacity_vm_retirement_native_readbacks;
DROP TABLE IF EXISTS public.capacity_vm_retirement_delete_bindings;
DROP TABLE IF EXISTS public.capacity_vm_retirement_original_returns;
DROP TABLE IF EXISTS public.capacity_vm_retirement_intents;
DROP TABLE IF EXISTS public.capacity_vm_original_enrollments;
DROP TABLE IF EXISTS public.capacity_vm_provisioning_preregistrations;
DROP FUNCTION IF EXISTS public.capacity_vm_original_retirement_immutable();
