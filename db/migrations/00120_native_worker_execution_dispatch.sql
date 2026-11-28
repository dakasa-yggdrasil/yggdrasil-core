-- +goose Up
-- Dispatch is a single-use RPC barrier, not remote success or send absence.
-- The original command114/phase113/network117 remain the mutation authorities.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_execution_dispatches (
 target_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN ('provider_create','registry_phase','network_install')),
 attempt_id uuid NOT NULL REFERENCES public.capacity_native_worker_attempts(id),
 policy_id uuid NOT NULL,
 namespace text NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 fencing_token bigint NOT NULL CHECK(fencing_token>0),
 source_commit text NOT NULL CHECK(source_commit ~ '^[a-f0-9]{40}$'),
 snapshot jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(target_id,operation)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_execution_dispatch_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a record; parent jsonb; target jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Native dispatch custody is immutable'; END IF;
 SELECT * INTO STRICT a FROM public.capacity_native_worker_attempts WHERE id=NEW.attempt_id;
 SELECT intent INTO STRICT parent FROM public.capacity_intents WHERE namespace=a.namespace AND environment=a.environment AND domain=a.domain AND dimension=a.dimension FOR UPDATE;
 SELECT * INTO STRICT a FROM public.capacity_native_worker_attempts WHERE id=NEW.attempt_id FOR UPDATE;
 IF NEW.policy_id<>a.policy_id OR NEW.namespace<>a.namespace OR NEW.generation<>a.generation OR NEW.fencing_token<>a.fencing_token
    OR NEW.source_commit IS DISTINCT FROM a.attempt->>'source_commit'
    OR NEW.snapshot IS DISTINCT FROM a.attempt
    OR parent->>'policy_id' IS DISTINCT FROM a.policy_id::text
    OR parent->>'policy_checksum' IS DISTINCT FROM a.attempt->>'policy_checksum'
    OR parent->>'generation' IS DISTINCT FROM a.generation::text
    OR parent->>'fencing_token' IS DISTINCT FROM a.fencing_token::text
    OR parent->>'phase' IS DISTINCT FROM 'preparing'
    OR COALESCE((parent->>'recovery_only')::boolean,false)
    OR parent#>'{decision,execution_permitted}' IS DISTINCT FROM 'true'::jsonb
    OR parent->>'lease_executor_id' IS NULL OR parent->>'lease_executor_id'=''
    OR parent->>'lease_expires_at' IS NULL OR (parent->>'lease_expires_at')::timestamptz<=clock_timestamp()
    OR NOT EXISTS(SELECT 1 FROM public.manifests m WHERE m.id=a.policy_id AND m.kind='capacity_policy' AND m.active AND m.checksum=a.attempt->>'policy_checksum' AND m.spec#>>'{native_worker_lifecycle_binding,source_commit}'=NEW.source_commit)
 THEN RAISE EXCEPTION 'Native dispatch must join the current original attempt and parent'; END IF;
 IF NEW.operation='provider_create' THEN
   IF NEW.target_id<>a.id OR a.state<>'reserved'
      OR NOT EXISTS(SELECT 1 FROM public.capacity_native_worker_command_contexts WHERE attempt_id=a.id AND record->>'executor_id'=parent->>'lease_executor_id' AND (record->>'expires_at')::timestamptz>clock_timestamp())
   THEN RAISE EXCEPTION 'Native provider dispatch requires unconsumed original command'; END IF;
 ELSIF NEW.operation='registry_phase' THEN
   SELECT record INTO STRICT target FROM public.capacity_native_worker_phase_permits WHERE id=NEW.target_id AND attempt_id=a.id AND policy_id=a.policy_id AND state='issued';
   IF target#>>'{context,intent_generation}' IS DISTINCT FROM a.generation::text OR target#>>'{context,fencing_token}' IS DISTINCT FROM a.fencing_token::text OR (target#>>'{context,expires_at}')::timestamptz<=clock_timestamp()
   THEN RAISE EXCEPTION 'Native registry dispatch differs from its original permission'; END IF;
 ELSE
   SELECT record INTO STRICT target FROM public.capacity_native_worker_network_permits WHERE id=NEW.target_id AND attempt_id=a.id AND policy_id=a.policy_id AND action='install' AND state='issued';
   IF target#>>'{context,intent_generation}' IS DISTINCT FROM a.generation::text OR target#>>'{context,fencing_token}' IS DISTINCT FROM a.fencing_token::text OR (target#>>'{context,expires_at}')::timestamptz<=clock_timestamp()
   THEN RAISE EXCEPTION 'Native network dispatch differs from its original permission'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_execution_dispatch_immutable ON public.capacity_native_worker_execution_dispatches;
CREATE TRIGGER capacity_native_worker_execution_dispatch_immutable BEFORE INSERT OR UPDATE OR DELETE ON public.capacity_native_worker_execution_dispatches FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_execution_dispatch_guard();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.capacity_native_worker_execution_dispatches IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_execution_dispatches) THEN RAISE EXCEPTION 'Native dispatch and possible RPC sends cannot be discarded'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_worker_execution_dispatches;
DROP FUNCTION IF EXISTS public.capacity_native_worker_execution_dispatch_guard();
