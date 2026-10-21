-- +goose Up
-- Lifetime obligations are independent of reservation decision generations.
-- Retained rows have no TTL. A restarted same UID never replaces its origin.
CREATE TABLE IF NOT EXISTS public.capacity_native_lifetimes (
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    pod_uid TEXT NOT NULL,
    origin_generation BIGINT NOT NULL CHECK (origin_generation > 0),
    checkpoint_record JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace, environment, domain, dimension, pod_uid)
);
CREATE INDEX IF NOT EXISTS capacity_native_lifetimes_state_idx
    ON public.capacity_native_lifetimes (namespace, environment, domain, dimension, (checkpoint_record->>'state'));

CREATE TABLE IF NOT EXISTS public.capacity_native_lifetime_archive (
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    pod_uid TEXT NOT NULL,
    origin_generation BIGINT NOT NULL,
    origin_sha256 TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    bundle_record JSONB NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace, environment, domain, dimension, pod_uid)
);

-- A permanent command identity fence survives hot-record compaction.
CREATE TABLE IF NOT EXISTS public.capacity_native_command_identities (
    id UUID PRIMARY KEY,
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    generation BIGINT NOT NULL,
    operation TEXT NOT NULL,
    subject_uid TEXT NOT NULL,
    phase TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 4),
    authority_token_sha256 TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL,
    UNIQUE (namespace, environment, domain, dimension, generation, operation, subject_uid, phase, sequence)
);
INSERT INTO public.capacity_native_command_identities
    (id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)
SELECT id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,command_record->>'request_sha256'
FROM public.capacity_native_commands ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS public.capacity_native_command_archive (
    id UUID PRIMARY KEY REFERENCES public.capacity_native_command_identities(id),
    record_sha256 TEXT NOT NULL,
    command_record JSONB NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_archive_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'native capacity archive and identity tombstones are immutable';
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capacity_native_lifetime_archive_immutable' AND tgrelid='public.capacity_native_lifetime_archive'::regclass) THEN
        CREATE TRIGGER capacity_native_lifetime_archive_immutable
            BEFORE UPDATE OR DELETE ON public.capacity_native_lifetime_archive
            FOR EACH ROW EXECUTE FUNCTION public.capacity_native_archive_immutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capacity_native_command_archive_immutable' AND tgrelid='public.capacity_native_command_archive'::regclass) THEN
        CREATE TRIGGER capacity_native_command_archive_immutable
            BEFORE UPDATE OR DELETE ON public.capacity_native_command_archive
            FOR EACH ROW EXECUTE FUNCTION public.capacity_native_archive_immutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capacity_native_command_identities_immutable' AND tgrelid='public.capacity_native_command_identities'::regclass) THEN
        CREATE TRIGGER capacity_native_command_identities_immutable
            BEFORE UPDATE OR DELETE ON public.capacity_native_command_identities
            FOR EACH ROW EXECUTE FUNCTION public.capacity_native_archive_immutable();
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS public.capacity_native_command_archive;
DROP TABLE IF EXISTS public.capacity_native_command_identities;
DROP TABLE IF EXISTS public.capacity_native_lifetime_archive;
DROP TABLE IF EXISTS public.capacity_native_lifetimes;
DROP FUNCTION IF EXISTS public.capacity_native_archive_immutable();
