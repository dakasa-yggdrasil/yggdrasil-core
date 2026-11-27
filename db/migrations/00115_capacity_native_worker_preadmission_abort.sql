-- +goose Up
-- Default-off pre-admission cleanup only. Historical113/114 remain unchanged.
ALTER TABLE public.capacity_native_worker_attempts DROP CONSTRAINT IF EXISTS capacity_native_worker_attempts_state_check;
ALTER TABLE public.capacity_native_worker_attempts ADD CONSTRAINT capacity_native_worker_attempts_state_check
 CHECK(state IN('reserved','send_started','acknowledged','unknown','registered','admitted','draining','aborting','absent'));
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
   (OLD.state='draining' AND NEW.state='absent') OR
   (OLD.state IN('acknowledged','registered') AND NEW.state='aborting') OR
   (OLD.state='aborting' AND NEW.state='absent'))
 THEN RAISE EXCEPTION 'Native attempt transition cannot resend or release uncertainty'; END IF;
 IF OLD.attempt ? 'physical' AND NEW.attempt->'physical' IS DISTINCT FROM OLD.attempt->'physical'
    OR OLD.attempt ? 'birth_sha256' AND NEW.attempt->'birth_sha256' IS DISTINCT FROM OLD.attempt->'birth_sha256'
    OR OLD.attempt ? 'node_uid' AND NEW.attempt->'node_uid' IS DISTINCT FROM OLD.attempt->'node_uid'
 THEN RAISE EXCEPTION 'Native physical birth and Node cannot be substituted'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

CREATE TABLE IF NOT EXISTS public.capacity_native_worker_abort_permits (
 id UUID PRIMARY KEY,
 attempt_id UUID NOT NULL REFERENCES public.capacity_native_worker_attempts(id),
 policy_id UUID NOT NULL REFERENCES public.manifests(id),
 namespace TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN('issued','redeemed','received','unknown','no_effect','observed')),
 revision BIGINT NOT NULL CHECK(revision>0),
 record JSONB NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 CHECK((record#>>'{context,permit_id}'=id::text
  AND record#>>'{context,attempt_id}'=attempt_id::text
  AND record#>>'{attempt,policy_id}'=policy_id::text
  AND record#>>'{attempt,namespace}'=namespace
  AND record#>>'{context,state}'=state AND (record->>'revision')::bigint=revision
  AND record#>>'{context,schema}'='native_worker_pre_admission_abort_v1'
  AND record#>>'{context,mutation_permitted}'='false'
  AND record#>>'{context,redeemable}'='false'
  AND COALESCE(record#>>'{context,settlement_token}','')='') IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_open_abort
 ON public.capacity_native_worker_abort_permits(attempt_id) WHERE state<>'no_effect';
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_abort_events (
 permit_id UUID NOT NULL REFERENCES public.capacity_native_worker_abort_permits(id),
 revision BIGINT NOT NULL,
 record JSONB NOT NULL,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(permit_id,revision)
);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_abort_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Native cleanup custody cannot be deleted'; END IF;
 IF NEW.id<>OLD.id OR NEW.attempt_id<>OLD.attempt_id OR NEW.policy_id<>OLD.policy_id
 OR NEW.namespace<>OLD.namespace OR NEW.expires_at<>OLD.expires_at OR NEW.revision<>OLD.revision+1
 OR NEW.record->'attempt' IS DISTINCT FROM OLD.record->'attempt'
 OR NEW.record->'binding' IS DISTINCT FROM OLD.record->'binding'
 OR NEW.record->'source_commit' IS DISTINCT FROM OLD.record->'source_commit'
 OR NEW.record->'executor_id' IS DISTINCT FROM OLD.record->'executor_id'
 OR NEW.record->'workflow_id' IS DISTINCT FROM OLD.record->'workflow_id'
 OR (NEW.record->'context'-'state') IS DISTINCT FROM (OLD.record->'context'-'state')
 THEN RAISE EXCEPTION 'Native cleanup immutable authority changed'; END IF;
 IF OLD.record ? 'original' AND NEW.record->'original' IS DISTINCT FROM OLD.record->'original'
 OR OLD.record ? 'token_sha256' AND NEW.record->'token_sha256' IS DISTINCT FROM OLD.record->'token_sha256'
 THEN RAISE EXCEPTION 'Native cleanup original or one-send token changed'; END IF;
 IF NOT (
  OLD.state='issued' AND NEW.state IN('issued','redeemed','no_effect','observed') OR
  OLD.state='redeemed' AND NEW.state IN('received','unknown','observed') OR
  OLD.state='received' AND NEW.state IN('unknown','observed') OR
  OLD.state='unknown' AND NEW.state IN('unknown','received','observed') OR
  OLD.state='observed' AND NEW.state='observed')
 THEN RAISE EXCEPTION 'Native cleanup cannot re-open an exposed right'; END IF;
 IF NEW.state='no_effect' AND (OLD.state<>'issued' OR OLD.record ? 'token_sha256' OR OLD.record ? 'original')
 THEN RAISE EXCEPTION 'Only unredeemed cleanup can expire without effect'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_abort_guard ON public.capacity_native_worker_abort_permits;
CREATE TRIGGER capacity_native_worker_abort_guard BEFORE UPDATE OR DELETE ON public.capacity_native_worker_abort_permits
 FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_abort_guard();
DROP TRIGGER IF EXISTS capacity_native_worker_abort_event_immutable ON public.capacity_native_worker_abort_events;
CREATE TRIGGER capacity_native_worker_abort_event_immutable BEFORE UPDATE OR DELETE ON public.capacity_native_worker_abort_events
 FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_archive_immutable();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.capacity_native_worker_abort_permits IN ACCESS EXCLUSIVE MODE;
 LOCK TABLE public.capacity_native_worker_attempts IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_abort_permits)
 OR EXISTS(SELECT 1 FROM public.capacity_native_worker_attempts WHERE state='aborting')
 THEN RAISE EXCEPTION 'Native cleanup and possible effects cannot be discarded'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_worker_abort_events;
DROP TABLE IF EXISTS public.capacity_native_worker_abort_permits;
DROP FUNCTION IF EXISTS public.capacity_native_worker_abort_guard();
ALTER TABLE public.capacity_native_worker_attempts DROP CONSTRAINT IF EXISTS capacity_native_worker_attempts_state_check;
ALTER TABLE public.capacity_native_worker_attempts ADD CONSTRAINT capacity_native_worker_attempts_state_check
 CHECK(state IN('reserved','send_started','acknowledged','unknown','registered','admitted','draining','absent'));
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
