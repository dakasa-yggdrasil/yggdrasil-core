-- +goose Up
-- Private diagnostic custody only. No readiness/admission/provider right is
-- conferred by a run or an event. Per-run private keys use authenticated
-- encryption with an independently mounted, process-owned journal key.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_readiness_runs (
    attempt_id UUID PRIMARY KEY REFERENCES public.capacity_native_worker_attempts(id),
    id UUID NOT NULL UNIQUE,
    revision BIGINT NOT NULL CHECK(revision > 0),
    record JSONB NOT NULL CHECK(octet_length(record::text)<=50331648),
    key_nonce BYTEA NOT NULL CHECK(octet_length(key_nonce) = 12),
    key_ciphertext BYTEA NOT NULL CHECK(octet_length(key_ciphertext) BETWEEN 48 AND 32784),
    created_at TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL CHECK(not_after > created_at),
    CHECK((record->>'schema' = 'native_worker_readiness_run_v1'
       AND record->>'id' = id::text
       AND record#>>'{identity,attempt_id}' = attempt_id::text
       AND (record->>'revision')::bigint = revision
       AND (record->>'created_at')::timestamptz = created_at
       AND (record->>'not_after')::timestamptz = not_after
       AND jsonb_typeof(record->'effects') = 'array'
       AND jsonb_typeof(record->'closed') = 'boolean') IS TRUE)
);

CREATE TABLE IF NOT EXISTS public.capacity_native_worker_readiness_events (
    attempt_id UUID NOT NULL REFERENCES public.capacity_native_worker_readiness_runs(attempt_id),
    revision BIGINT NOT NULL CHECK(revision > 0),
    record JSONB NOT NULL CHECK(octet_length(record::text)<=50331648),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(attempt_id, revision)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_readiness_run_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Native readiness custody cannot be deleted'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.record->'effects'<>'[]'::jsonb
     OR NEW.record->'closed'<>'false'::jsonb
     OR NEW.record ? 'proof'
     OR NEW.record ? 'pending_proof' OR NEW.record ? 'reads'
  THEN RAISE EXCEPTION 'Native readiness custody must start before effects'; END IF;
 ELSE
  IF NEW.attempt_id<>OLD.attempt_id OR NEW.id<>OLD.id
     OR NEW.created_at<>OLD.created_at OR NEW.not_after<>OLD.not_after
     OR NEW.key_nonce<>OLD.key_nonce OR NEW.key_ciphertext<>OLD.key_ciphertext
     OR NEW.revision<>OLD.revision+1
     OR (NEW.record-ARRAY['revision','effects','closed','proof','pending_proof','reads'])
       IS DISTINCT FROM (OLD.record-ARRAY['revision','effects','closed','proof','pending_proof','reads'])
     OR ((OLD.record ? 'proof') AND
         NEW.record->'proof' IS DISTINCT FROM OLD.record->'proof')
     OR ((OLD.record ? 'pending_proof') AND
         NEW.record->'pending_proof' IS DISTINCT FROM OLD.record->'pending_proof')
     OR OLD.record->'closed'='true'::jsonb
  THEN RAISE EXCEPTION 'Native readiness identity, keys and lifetime are immutable'; END IF;
 END IF;
 IF NEW.record ? 'proof' THEN
  IF (jsonb_typeof(NEW.record->'proof')='object'
      AND NEW.record->'closed'='true'::jsonb
      AND NEW.record->'proof'=NEW.record->'pending_proof'
      AND NEW.record#>>'{proof,attempt_id}'=NEW.attempt_id::text
      AND NEW.record#>>'{proof,node_uid}'=NEW.record#>>'{identity,node_uid}'
      AND NEW.record#>>'{proof,provider_id}'=NEW.record#>>'{identity,provider_id}'
      AND NEW.record#>>'{proof,birth_sha256}'=NEW.record#>>'{identity,birth_sha256}'
      AND (NEW.record#>>'{proof,observed_at}')::timestamptz>=NEW.created_at
      AND (NEW.record#>>'{proof,valid_until}')::timestamptz<=NEW.not_after
      AND (NEW.record#>>'{proof,valid_until}')::timestamptz>
          (NEW.record#>>'{proof,observed_at}')::timestamptz) IS NOT TRUE
  THEN RAISE EXCEPTION 'Native readiness proof must retain original identity and lifetime'; END IF;
 END IF;
 IF NEW.record ? 'pending_proof' THEN
  IF (jsonb_typeof(NEW.record->'pending_proof')='object'
      AND NEW.record#>>'{pending_proof,attempt_id}'=NEW.attempt_id::text
      AND NEW.record#>>'{pending_proof,node_uid}'=NEW.record#>>'{identity,node_uid}'
      AND NEW.record#>>'{pending_proof,provider_id}'=NEW.record#>>'{identity,provider_id}'
      AND NEW.record#>>'{pending_proof,birth_sha256}'=NEW.record#>>'{identity,birth_sha256}'
      AND (NEW.record#>>'{pending_proof,observed_at}')::timestamptz>=NEW.created_at
      AND (NEW.record#>>'{pending_proof,valid_until}')::timestamptz<=NEW.not_after
      AND (NEW.record#>>'{pending_proof,valid_until}')::timestamptz>
          (NEW.record#>>'{pending_proof,observed_at}')::timestamptz) IS NOT TRUE
  THEN RAISE EXCEPTION 'Native readiness pending proof must retain original identity and lifetime'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_readiness_run_guard ON public.capacity_native_worker_readiness_runs;
CREATE TRIGGER capacity_native_worker_readiness_run_guard BEFORE INSERT OR UPDATE OR DELETE
ON public.capacity_native_worker_readiness_runs FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_readiness_run_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_readiness_run_event()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO public.capacity_native_worker_readiness_events(attempt_id,revision,record)
 VALUES(NEW.attempt_id,NEW.revision,NEW.record);
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_readiness_run_event ON public.capacity_native_worker_readiness_runs;
CREATE TRIGGER capacity_native_worker_readiness_run_event AFTER INSERT OR UPDATE
ON public.capacity_native_worker_readiness_runs FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_readiness_run_event();
DROP TRIGGER IF EXISTS capacity_native_worker_readiness_event_immutable ON public.capacity_native_worker_readiness_events;
CREATE TRIGGER capacity_native_worker_readiness_event_immutable BEFORE UPDATE OR DELETE
ON public.capacity_native_worker_readiness_events FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_archive_immutable();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.capacity_native_worker_readiness_runs IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_readiness_runs)
   OR EXISTS(SELECT 1 FROM public.capacity_native_worker_readiness_events)
 THEN RAISE EXCEPTION 'Native readiness effects and key custody cannot be discarded'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_worker_readiness_events;
DROP TABLE IF EXISTS public.capacity_native_worker_readiness_runs;
DROP FUNCTION IF EXISTS public.capacity_native_worker_readiness_run_event();
DROP FUNCTION IF EXISTS public.capacity_native_worker_readiness_run_guard();
