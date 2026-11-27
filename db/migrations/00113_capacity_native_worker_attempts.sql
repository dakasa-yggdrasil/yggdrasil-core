-- +goose Up
-- New opt-in authority only. Legacy slot/grant tables and their constraints are untouched.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_attempts (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES public.manifests(id),
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK(generation>0),
    fencing_token BIGINT NOT NULL CHECK(fencing_token>0),
    ipam_scope TEXT NOT NULL,
    overlay_ipv4 INET NOT NULL CHECK(family(overlay_ipv4)=4 AND masklen(overlay_ipv4)=32),
    state TEXT NOT NULL CHECK(state IN('reserved','send_started','acknowledged','unknown','registered','admitted','draining','absent')),
    revision BIGINT NOT NULL CHECK(revision>0),
    attempt JSONB NOT NULL,
    launch_wire BYTEA NOT NULL CHECK(octet_length(launch_wire) BETWEEN 1 AND 32768),
    CHECK((attempt->>'id'=id::text AND attempt->>'policy_id'=policy_id::text
      AND attempt->>'namespace'=namespace AND attempt->>'environment'=environment
      AND attempt->>'domain'=domain AND attempt->>'dimension'=dimension
      AND (attempt->>'generation')::bigint=generation
      AND (attempt->>'fencing_token')::bigint=fencing_token
      AND attempt->>'state'=state AND (attempt->>'revision')::bigint=revision
      AND attempt->>'overlay_ipv4'=host(overlay_ipv4)
      AND attempt->>'launch_sha256'=encode(sha256(launch_wire),'hex')) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_live_ip
    ON public.capacity_native_worker_attempts(ipam_scope,overlay_ipv4) WHERE state<>'absent';
CREATE INDEX IF NOT EXISTS capacity_native_worker_parent
    ON public.capacity_native_worker_attempts(policy_id,generation,fencing_token);

-- Original return bytes may contain provider secrets (for example root_password).
-- They and their raw digest are private DB custody and never a public birth digest.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_original_returns (
    attempt_id UUID PRIMARY KEY REFERENCES public.capacity_native_worker_attempts(id),
    wire BYTEA NOT NULL CHECK(octet_length(wire)<=1048576),
    raw_sha256 TEXT NOT NULL CHECK(raw_sha256=encode(sha256(wire),'hex')),
    capture_complete BOOLEAN NOT NULL,
    error_class TEXT NOT NULL CHECK(length(error_class)<=128),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_events (
    attempt_id UUID NOT NULL REFERENCES public.capacity_native_worker_attempts(id),
    revision BIGINT NOT NULL CHECK(revision>0),
    record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(attempt_id,revision)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_attempt_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Native attempt history cannot be deleted'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'reserved' OR NEW.revision<>1
  THEN RAISE EXCEPTION 'Native attempt must begin reserved'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.revision<>OLD.revision+1 OR NEW.launch_wire<>OLD.launch_wire
    OR (NEW.attempt-ARRAY['state','revision','physical','birth_sha256','node_uid','updated_at'])
       IS DISTINCT FROM (OLD.attempt-ARRAY['state','revision','physical','birth_sha256','node_uid','updated_at'])
    OR NEW.id<>OLD.id OR NEW.policy_id<>OLD.policy_id OR NEW.namespace<>OLD.namespace
    OR NEW.environment<>OLD.environment OR NEW.domain<>OLD.domain OR NEW.dimension<>OLD.dimension
    OR NEW.generation<>OLD.generation OR NEW.fencing_token<>OLD.fencing_token
    OR NEW.ipam_scope<>OLD.ipam_scope OR NEW.overlay_ipv4<>OLD.overlay_ipv4
 THEN RAISE EXCEPTION 'Native attempt immutable authority changed'; END IF;
 IF NOT (
   (OLD.state='reserved' AND NEW.state='send_started') OR
   (OLD.state IN('send_started','unknown') AND NEW.state IN('unknown','acknowledged')) OR
   (OLD.state='acknowledged' AND NEW.state='registered') OR
   (OLD.state='registered' AND NEW.state='admitted') OR
   (OLD.state='admitted' AND NEW.state='draining') OR
   (OLD.state='draining' AND NEW.state='absent'))
 THEN RAISE EXCEPTION 'Native attempt transition cannot resend or release uncertainty'; END IF;
 IF OLD.attempt ? 'physical' AND NEW.attempt->'physical' IS DISTINCT FROM OLD.attempt->'physical'
    OR OLD.attempt ? 'birth_sha256' AND NEW.attempt->'birth_sha256' IS DISTINCT FROM OLD.attempt->'birth_sha256'
    OR OLD.attempt ? 'node_uid' AND NEW.attempt->'node_uid' IS DISTINCT FROM OLD.attempt->'node_uid'
 THEN RAISE EXCEPTION 'Native physical birth and Node cannot be substituted'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_attempt_guard ON public.capacity_native_worker_attempts;
CREATE TRIGGER capacity_native_worker_attempt_guard BEFORE INSERT OR UPDATE OR DELETE
ON public.capacity_native_worker_attempts FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_attempt_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_archive_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Native original return and event custody is immutable'; END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_return_immutable ON public.capacity_native_worker_original_returns;
CREATE TRIGGER capacity_native_worker_return_immutable BEFORE UPDATE OR DELETE
ON public.capacity_native_worker_original_returns FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_archive_immutable();
DROP TRIGGER IF EXISTS capacity_native_worker_event_immutable ON public.capacity_native_worker_events;
CREATE TRIGGER capacity_native_worker_event_immutable BEFORE UPDATE OR DELETE
ON public.capacity_native_worker_events FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_archive_immutable();

-- Distinct one-CAS phase permits. These records and receive events are private;
-- public projections never include settlement tokens or original return blobs.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_phase_permits (
    id UUID PRIMARY KEY,
    attempt_id UUID NOT NULL REFERENCES public.capacity_native_worker_attempts(id),
    policy_id UUID NOT NULL REFERENCES public.manifests(id),
    namespace TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN('register','admit_registry','release_quarantine')),
    state TEXT NOT NULL CHECK(state IN('issued','redeemed','received','unknown','no_effect','observed')),
    revision BIGINT NOT NULL CHECK(revision>0),
    record JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_open_phase
ON public.capacity_native_worker_phase_permits(attempt_id,action)
WHERE state IN('issued','redeemed','received','unknown','observed');
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_phase_permit_events (
    permit_id UUID NOT NULL REFERENCES public.capacity_native_worker_phase_permits(id),
    revision BIGINT NOT NULL CHECK(revision>0),
    record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(permit_id,revision)
);
DROP TRIGGER IF EXISTS capacity_native_worker_phase_event_immutable ON public.capacity_native_worker_phase_permit_events;
CREATE TRIGGER capacity_native_worker_phase_event_immutable BEFORE UPDATE OR DELETE
ON public.capacity_native_worker_phase_permit_events FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_archive_immutable();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.capacity_native_worker_attempts IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_attempts) OR EXISTS(SELECT 1 FROM public.capacity_native_worker_phase_permits) OR EXISTS(SELECT 1 FROM public.capacity_native_worker_phase_permit_events)
 THEN RAISE EXCEPTION 'Native attempts and uncertainty cannot be discarded by rollback'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_worker_phase_permit_events;
DROP TABLE IF EXISTS public.capacity_native_worker_phase_permits;
DROP TABLE IF EXISTS public.capacity_native_worker_events;
DROP TABLE IF EXISTS public.capacity_native_worker_original_returns;
DROP TABLE IF EXISTS public.capacity_native_worker_attempts;
DROP FUNCTION IF EXISTS public.capacity_native_worker_attempt_guard();
DROP FUNCTION IF EXISTS public.capacity_native_worker_archive_immutable();
