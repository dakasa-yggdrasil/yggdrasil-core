-- +goose Up
-- A retained server proof can close an expired command that never granted a send.
-- It cannot cancel any possible create, release uncertainty or delete history.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_unsent_closures (
 attempt_id UUID PRIMARY KEY REFERENCES public.capacity_native_worker_attempts(id),
 policy_id UUID NOT NULL REFERENCES public.manifests(id),
 namespace TEXT NOT NULL,
 from_revision BIGINT NOT NULL CHECK(from_revision=1),
 command_context JSONB NOT NULL,
 closed_at TIMESTAMPTZ NOT NULL,
 CHECK((command_context->>'attempt_id'=attempt_id::text
  AND command_context->>'policy_id'=policy_id::text
  AND command_context->>'namespace'=namespace
  AND closed_at >= (command_context->>'expires_at')::timestamptz) IS TRUE)
);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_unsent_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a public.capacity_native_worker_attempts%ROWTYPE; command JSONB;
BEGIN
 SELECT * INTO a FROM public.capacity_native_worker_attempts WHERE id=NEW.attempt_id FOR UPDATE;
 SELECT record INTO command FROM public.capacity_native_worker_command_contexts WHERE attempt_id=NEW.attempt_id;
 IF (a.state='reserved' AND a.revision=NEW.from_revision AND a.policy_id=NEW.policy_id
     AND a.namespace=NEW.namespace AND NEW.command_context=command
     AND NEW.closed_at<=clock_timestamp() AND isfinite(NEW.closed_at)
     AND NOT(a.attempt ? 'physical') AND NOT(a.attempt ? 'birth_sha256') AND NOT(a.attempt ? 'node_uid')
     AND NOT EXISTS(SELECT 1 FROM public.capacity_native_worker_original_returns WHERE attempt_id=NEW.attempt_id)) IS NOT TRUE
 THEN RAISE EXCEPTION 'Only a proven original unsent reservation can be closed'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_unsent_guard ON public.capacity_native_worker_unsent_closures;
CREATE TRIGGER capacity_native_worker_unsent_guard BEFORE INSERT ON public.capacity_native_worker_unsent_closures
 FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_unsent_guard();
DROP TRIGGER IF EXISTS capacity_native_worker_unsent_immutable ON public.capacity_native_worker_unsent_closures;
CREATE TRIGGER capacity_native_worker_unsent_immutable BEFORE UPDATE OR DELETE ON public.capacity_native_worker_unsent_closures
 FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_archive_immutable();

-- Serialize original custody against unsent closure; a sealed no-send attempt
-- can never receive a later fabricated provider response or be revived.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_original_unsent_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM 1 FROM public.capacity_native_worker_attempts WHERE id=NEW.attempt_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_unsent_closures WHERE attempt_id=NEW.attempt_id)
 THEN RAISE EXCEPTION 'An original unsent closure cannot acquire provider custody'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_original_unsent_guard ON public.capacity_native_worker_original_returns;
CREATE TRIGGER capacity_native_worker_original_unsent_guard BEFORE INSERT ON public.capacity_native_worker_original_returns
 FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_original_unsent_guard();

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
   (OLD.state='reserved' AND NEW.state='absent'
    AND NOT(NEW.attempt ? 'physical') AND NOT(NEW.attempt ? 'birth_sha256') AND NOT(NEW.attempt ? 'node_uid')
    AND EXISTS(SELECT 1 FROM public.capacity_native_worker_unsent_closures c
      JOIN public.capacity_native_worker_command_contexts command ON command.attempt_id=c.attempt_id
      WHERE c.attempt_id=OLD.id AND c.policy_id=OLD.policy_id AND c.namespace=OLD.namespace
       AND c.from_revision=OLD.revision AND c.command_context=command.record)
    AND NOT EXISTS(SELECT 1 FROM public.capacity_native_worker_original_returns r WHERE r.attempt_id=OLD.id)) OR
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

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.capacity_native_worker_unsent_closures IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_unsent_closures)
 THEN RAISE EXCEPTION 'Native unsent closure history cannot be discarded'; END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_original_unsent_guard ON public.capacity_native_worker_original_returns;
DROP FUNCTION IF EXISTS public.capacity_native_worker_original_unsent_guard();
DROP TABLE IF EXISTS public.capacity_native_worker_unsent_closures;
DROP FUNCTION IF EXISTS public.capacity_native_worker_unsent_guard();
-- Restore exactly the schema115 attempt guard;113/114/115 remain immutable.
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
