-- +goose Up
-- Extend only the optional provider-specific witness. The complete schema116
-- authority, transitions, protected physical birth and Node guards are retained.
-- Full safe witness hashing and current policy pins remain validated by Core
-- before this transaction; SQL independently gates its first appearance and
-- makes that complete JSONB value permanently immutable.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_attempt_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w JSONB;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Native attempt history cannot be deleted'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.attempt ? 'hcloud_witness'
  THEN RAISE EXCEPTION 'Native HCloud witness cannot preexist original creation'; END IF;
  IF NEW.state<>'reserved' OR NEW.revision<>1
  THEN RAISE EXCEPTION 'Native attempt must begin reserved'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.revision<>OLD.revision+1 OR NEW.launch_wire<>OLD.launch_wire
    OR (NEW.attempt-ARRAY['state','revision','physical','birth_sha256','hcloud_witness','node_uid','updated_at'])
       IS DISTINCT FROM (OLD.attempt-ARRAY['state','revision','physical','birth_sha256','hcloud_witness','node_uid','updated_at'])
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
 -- Removing this field from the authority comparison grants no general
 -- mutability: only the first physical ACK can add it, and it is frozen forever.
 IF OLD.attempt ? 'hcloud_witness' THEN
  IF NEW.attempt->'hcloud_witness' IS DISTINCT FROM OLD.attempt->'hcloud_witness'
  THEN RAISE EXCEPTION 'Native HCloud witness is immutable after first ACK'; END IF;
 ELSIF NEW.attempt ? 'hcloud_witness' THEN
  w:=NEW.attempt->'hcloud_witness';
  IF (
    OLD.state IN('send_started','unknown') AND NEW.state='acknowledged'
    AND NEW.attempt->>'provider'='hetzner'
    AND NOT(OLD.attempt ? 'physical') AND NOT(OLD.attempt ? 'birth_sha256')
    AND jsonb_typeof(NEW.attempt->'physical')='object'
    AND NEW.attempt->>'birth_sha256' ~ '^[a-f0-9]{64}$'
    AND jsonb_typeof(w)='object'
    AND w->>'schema'='native_worker_hcloud_ack_witness_v1'
    AND w->>'core_source_commit'=NEW.attempt->>'source_commit'
    AND w->>'attempt_id'=NEW.id::text AND w->>'policy_id'=NEW.policy_id::text
    AND w->>'pool_uid'=NEW.attempt->>'pool_uid'
    AND w->'pool_epoch'=NEW.attempt->'pool_epoch'
    AND w->'intent_generation'=NEW.attempt->'generation'
    AND w->'fencing_token'=NEW.attempt->'fencing_token'
    AND w->>'launch_sha256'=NEW.attempt->>'launch_sha256'
    AND w->>'evidence_sha256' ~ '^[a-f0-9]{64}$'
    AND w->>'physical_identity_sha256' ~ '^[a-f0-9]{64}$'
    AND w->'acceptance'->>'resource_id'=NEW.attempt->'physical'->>'resource_id'
    AND w->'observation'->'physical'->>'resource_id'=NEW.attempt->'physical'->>'resource_id'
    AND w->'observation'->'physical'->>'provider_id'=NEW.attempt->'physical'->>'provider_id'
    AND NEW.attempt->'physical'->>'account_id'=''
    AND w->'observation'->'physical'->>'account_id'=''
    AND NEW.attempt->'physical'->>'launch_sha256'=NEW.attempt->>'launch_sha256'
    AND w->'observation'->'physical'->>'launch_sha256'=NEW.attempt->>'launch_sha256'
    AND w->'reader'->>'profile'=NEW.attempt->>'profile'
    AND w->'reader'->>'provider'='hetzner'
    AND w->'reader'->>'region'=NEW.attempt->>'region'
    AND w->'reader'->>'scope_sha256'=w->'observation'->>'binding_scope_sha256'
    AND w->'reader'->>'source_commit'=w->'observation'->>'source_commit'
    AND w->'reader'->'adapter'=w->'observation'->'adapter'
    AND w->'reader'->'hcloud_scope'=w->'observation'->'project_scope'
    AND EXISTS(SELECT 1 FROM public.capacity_native_worker_original_returns r
      WHERE r.attempt_id=NEW.id AND r.capture_complete AND r.error_class='')
  ) IS NOT TRUE THEN
   RAISE EXCEPTION 'Native HCloud witness requires the first exact complete physical ACK';
  END IF;
 ELSIF NEW.state='acknowledged' AND NEW.attempt->>'provider'='hetzner' THEN
  RAISE EXCEPTION 'Native HCloud ACK requires its complete witness';
 END IF;
 IF OLD.attempt ? 'physical' AND NEW.attempt->'physical' IS DISTINCT FROM OLD.attempt->'physical'
    OR OLD.attempt ? 'birth_sha256' AND NEW.attempt->'birth_sha256' IS DISTINCT FROM OLD.attempt->'birth_sha256'
    OR OLD.attempt ? 'node_uid' AND NEW.attempt->'node_uid' IS DISTINCT FROM OLD.attempt->'node_uid'
 THEN RAISE EXCEPTION 'Native physical birth and Node cannot be substituted'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- The application inserts immutable event/birth custody after updating Attempt.
-- Defer this check until commit so that both writes are required atomically.
-- Go owns its canonical safe SHA; jsonb field order is not a Go hash encoding.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_hcloud_birth_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r JSONB; b JSONB; w JSONB;
BEGIN
 IF OLD.attempt ? 'hcloud_witness' OR NOT(NEW.attempt ? 'hcloud_witness') THEN RETURN NEW; END IF;
 SELECT record INTO r FROM public.capacity_native_worker_events
  WHERE attempt_id=NEW.id AND revision=NEW.revision;
 b:=r->'birth'; w:=NEW.attempt->'hcloud_witness';
 IF (
   r->'attempt'=NEW.attempt AND jsonb_typeof(b)='object'
   AND b->>'schema'='native_worker_lifecycle_v1'
   AND b->>'attempt_id'=NEW.id::text AND b->>'policy_id'=NEW.policy_id::text
   AND b->'generation'=NEW.attempt->'generation'
   AND b->'fencing_token'=NEW.attempt->'fencing_token'
   AND b->>'pool_uid'=NEW.attempt->>'pool_uid' AND b->'pool_epoch'=NEW.attempt->'pool_epoch'
   AND b->'execution_adapter'=NEW.attempt->'execution'->'adapter'
   AND b->>'execution_scope_sha256'=NEW.attempt->'execution'->>'scope_sha256'
   AND b->>'launch_sha256'=NEW.attempt->>'launch_sha256'
   AND b->'physical'=NEW.attempt->'physical' AND b->'hcloud_witness'=w
   AND b->>'original_acceptance_sha256' ~ '^[a-f0-9]{64}$'
   AND b->>'independent_read_sha256' ~ '^[a-f0-9]{64}$'
   AND b->>'original_request_id'=w->'acceptance'->>'request_id'
   AND b->>'independent_request_id'=(w->'observation'->'reads'->(-1))->>'request_id'
 ) IS NOT TRUE THEN
  RAISE EXCEPTION 'Native HCloud first ACK requires atomic matching birth event';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_hcloud_birth_guard ON public.capacity_native_worker_attempts;
CREATE CONSTRAINT TRIGGER capacity_native_worker_hcloud_birth_guard
AFTER UPDATE ON public.capacity_native_worker_attempts DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_hcloud_birth_guard();

-- +goose Down
-- Never roll back the only guard that understands a retained physical witness.
-- Keep both current rows and immutable event/birth history, including absence.
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.capacity_native_worker_attempts,
   public.capacity_native_worker_events IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_attempts WHERE attempt ? 'hcloud_witness')
   OR EXISTS(SELECT 1 FROM public.capacity_native_worker_events
     WHERE record->'attempt' ? 'hcloud_witness' OR record->'birth' ? 'hcloud_witness')
 THEN RAISE EXCEPTION 'Native HCloud witness history cannot lose its immutable guard'; END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_hcloud_birth_guard ON public.capacity_native_worker_attempts;
DROP FUNCTION IF EXISTS public.capacity_native_worker_hcloud_birth_guard();
-- Restore exactly the schema116 guard when there is no witness history.
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
