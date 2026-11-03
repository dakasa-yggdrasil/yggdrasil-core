-- +goose Up
-- +goose StatementBegin
-- These are pre-start workflow ownership records, never native capacity grants.
CREATE TABLE IF NOT EXISTS public.capacity_dispatch_jobs (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
    protocol TEXT NOT NULL,
    realm TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    source_tick TEXT NOT NULL,
    envelope TEXT NOT NULL CHECK (jsonb_typeof(envelope::jsonb) = 'object'),
    envelope_sha256 TEXT NOT NULL CHECK (envelope_sha256 ~ '^[a-f0-9]{64}$'),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'started', 'unknown', 'returned')),
    lease_owner UUID,
    fencing_token BIGINT NOT NULL DEFAULT 0 CHECK (fencing_token BETWEEN 0 AND 9007199254740991),
    lease_expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    returned_at TIMESTAMPTZ,
    pending_wake_count INTEGER NOT NULL DEFAULT 1 CHECK (pending_wake_count BETWEEN 1 AND 32),
    return_status TEXT,
    return_error TEXT,
    finalization_error TEXT,
    finalization_ack_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (length(protocol) BETWEEN 1 AND 128),
    CHECK (length(realm) BETWEEN 1 AND 64 AND length(environment) BETWEEN 1 AND 128
           AND length(domain) BETWEEN 1 AND 128 AND length(dimension) BETWEEN 1 AND 128),
    CHECK (length(source_tick) BETWEEN 1 AND 256 AND octet_length(envelope) <= 16384),
    CHECK ((lease_owner IS NULL AND lease_expires_at IS NULL AND fencing_token = 0)
           OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND fencing_token > 0)),
    CHECK ((state = 'queued' AND started_at IS NULL AND returned_at IS NULL)
           OR (state = 'started' AND started_at IS NOT NULL AND returned_at IS NULL)
           OR (state = 'unknown' AND started_at IS NOT NULL)
           OR (state = 'returned' AND started_at IS NOT NULL AND returned_at IS NOT NULL)),
    CHECK (returned_at IS NULL OR started_at IS NOT NULL),
    CHECK (finalization_ack_at IS NULL OR (state='returned' AND returned_at IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_dispatch_active_scope_idx
    ON public.capacity_dispatch_jobs (realm, environment, domain, dimension)
    WHERE state IN ('queued', 'started', 'unknown')
       OR (state='returned' AND finalization_ack_at IS NULL);
CREATE INDEX IF NOT EXISTS capacity_dispatch_claim_idx
    ON public.capacity_dispatch_jobs (realm, environment, created_at, id)
    WHERE protocol = 'capacity_dispatch_prestart_v1' AND state = 'queued' AND started_at IS NULL;

-- Retained exact tick keys coalesce wakes without replacing original execution
-- pins. Saturation rolls back the caller's tick transaction; it cannot drop it.
CREATE TABLE IF NOT EXISTS public.capacity_dispatch_wakes (
    realm TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    source_tick TEXT NOT NULL,
    job_id UUID NOT NULL REFERENCES public.capacity_dispatch_jobs(id),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (realm, environment, domain, dimension, source_tick)
);

CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.id, NEW.run_id, NEW.protocol, NEW.realm, NEW.environment, NEW.domain,
        NEW.dimension, NEW.source_tick, NEW.envelope, NEW.envelope_sha256, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.run_id, OLD.protocol, OLD.realm, OLD.environment, OLD.domain,
        OLD.dimension, OLD.source_tick, OLD.envelope, OLD.envelope_sha256, OLD.created_at) THEN
        RAISE EXCEPTION 'capacity dispatch immutable identity';
    END IF;
    IF OLD.started_at IS NOT NULL AND
       (NEW.started_at, NEW.lease_owner, NEW.fencing_token, NEW.lease_expires_at)
       IS DISTINCT FROM
       (OLD.started_at, OLD.lease_owner, OLD.fencing_token, OLD.lease_expires_at) THEN
        RAISE EXCEPTION 'capacity dispatch immutable start ownership';
    END IF;
    IF OLD.started_at IS NULL AND NEW.started_at IS NOT NULL AND
       (OLD.protocol <> 'capacity_dispatch_prestart_v1' OR OLD.state <> 'queued'
        OR NEW.state <> 'started' OR NEW.lease_owner IS NULL
        OR NEW.lease_expires_at IS NULL OR clock_timestamp() >= NEW.lease_expires_at
        OR NEW.started_at >= NEW.lease_expires_at) THEN
        RAISE EXCEPTION 'capacity dispatch start requires live original deadline';
    END IF;
    IF OLD.started_at IS NULL AND
       (NEW.lease_owner, NEW.fencing_token, NEW.lease_expires_at) IS DISTINCT FROM
       (OLD.lease_owner, OLD.fencing_token, OLD.lease_expires_at) AND
       (OLD.protocol <> 'capacity_dispatch_prestart_v1' OR OLD.state <> 'queued'
        OR NEW.state <> 'queued' OR NEW.started_at IS NOT NULL
        OR NEW.fencing_token <> OLD.fencing_token + 1 OR NEW.lease_owner IS NULL
        OR NEW.lease_expires_at IS NULL OR NEW.lease_expires_at <= clock_timestamp()
        OR OLD.lease_expires_at > clock_timestamp()) THEN
        RAISE EXCEPTION 'capacity dispatch claim requires expired prestart fence';
    END IF;
    IF NEW.pending_wake_count < OLD.pending_wake_count OR
       NEW.pending_wake_count > OLD.pending_wake_count + 1 THEN
        RAISE EXCEPTION 'capacity dispatch bounded wake increment';
    END IF;
    IF OLD.returned_at IS NOT NULL AND NEW.returned_at IS DISTINCT FROM OLD.returned_at THEN
        RAISE EXCEPTION 'capacity dispatch immutable actual return';
    END IF;
    IF OLD.returned_at IS NOT NULL AND
       (NEW.return_status, NEW.return_error) IS DISTINCT FROM
       (OLD.return_status, OLD.return_error) THEN
        RAISE EXCEPTION 'capacity dispatch immutable actual return cause';
    END IF;
    IF OLD.finalization_ack_at IS NOT NULL AND
       (NEW.finalization_ack_at,NEW.state) IS DISTINCT FROM
       (OLD.finalization_ack_at,OLD.state) THEN
        RAISE EXCEPTION 'capacity dispatch immutable observed acknowledgment';
    END IF;
    IF OLD.finalization_ack_at IS NULL AND NEW.finalization_ack_at IS NOT NULL AND
       (OLD.state <> 'returned' OR OLD.returned_at IS NULL OR NEW.state <> 'returned'
        OR clock_timestamp() >= OLD.lease_expires_at) THEN
        RAISE EXCEPTION 'capacity dispatch acknowledgment requires live original owner';
    END IF;
    -- A truthful original return is retained when the commit acknowledgment
    -- crosses the original context/deadline. Downgrade only; never replay.
    IF (OLD.state = 'returned' AND NEW.state NOT IN ('returned', 'unknown')) OR
       (OLD.state = 'unknown' AND NEW.state <> 'unknown') OR
       (OLD.state = 'started' AND NEW.state = 'queued') THEN
        RAISE EXCEPTION 'capacity dispatch cannot replay';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS capacity_dispatch_job_guard ON public.capacity_dispatch_jobs;
CREATE TRIGGER capacity_dispatch_job_guard BEFORE UPDATE ON public.capacity_dispatch_jobs
    FOR EACH ROW EXECUTE FUNCTION public.guard_capacity_dispatch_job();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.capacity_dispatch_wakes;
DROP TABLE IF EXISTS public.capacity_dispatch_jobs;
DROP FUNCTION IF EXISTS public.guard_capacity_dispatch_job();
-- +goose StatementEnd
