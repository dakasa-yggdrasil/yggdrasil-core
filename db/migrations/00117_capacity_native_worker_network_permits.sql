-- +goose Up
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_network_permits (
    id uuid PRIMARY KEY,
    attempt_id uuid NOT NULL REFERENCES public.capacity_native_worker_attempts(id),
    policy_id uuid NOT NULL,
    namespace text NOT NULL,
    action text NOT NULL CHECK (action IN ('install','remove')),
    state text NOT NULL CHECK (state IN ('issued','redeemed','received','unknown','no_effect','observed')),
    revision bigint NOT NULL CHECK (revision > 0),
    record jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_native_worker_network_one_active_action
ON public.capacity_native_worker_network_permits(attempt_id,action)
-- An observed action remains consumed; only proven unsent no_effect may be reissued.
WHERE state<>'no_effect';

CREATE TABLE IF NOT EXISTS public.capacity_native_worker_network_events (
    permit_id uuid NOT NULL REFERENCES public.capacity_native_worker_network_permits(id),
    revision bigint NOT NULL,
    record jsonb NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (permit_id,revision)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_network_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a record;
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'native network authority is retained';
    END IF;
    IF jsonb_typeof(NEW.record) IS DISTINCT FROM 'object'
       OR NEW.record#>>'{context,schema}' IS DISTINCT FROM 'native_worker_network_permit_v1'
       OR NEW.record#>>'{context,permit_id}' IS DISTINCT FROM NEW.id::text
       OR NEW.record#>>'{context,attempt_id}' IS DISTINCT FROM NEW.attempt_id::text
       OR NEW.record#>>'{context,policy_id}' IS DISTINCT FROM NEW.policy_id::text
       OR NEW.record#>>'{attempt,id}' IS DISTINCT FROM NEW.attempt_id::text
       OR NEW.record#>>'{attempt,policy_id}' IS DISTINCT FROM NEW.policy_id::text
       OR NEW.record#>>'{attempt,namespace}' IS DISTINCT FROM NEW.namespace
       OR NEW.record#>>'{context,action}' IS DISTINCT FROM NEW.action
       OR NEW.record#>>'{context,state}' IS DISTINCT FROM NEW.state
       OR NEW.record->'revision' IS DISTINCT FROM to_jsonb(NEW.revision)
       OR NEW.record#>'{context,mutation_permitted}' IS DISTINCT FROM 'false'::jsonb
       OR NEW.record#>'{context,redeemable}' IS DISTINCT FROM 'false'::jsonb
       OR (NEW.record#>>'{context,expires_at}')::timestamptz IS DISTINCT FROM NEW.expires_at
    THEN RAISE EXCEPTION 'native network context or indexed identity differs'; END IF;

    SELECT state,policy_id,namespace INTO a FROM public.capacity_native_worker_attempts
    WHERE id=NEW.attempt_id FOR UPDATE;
    IF NOT FOUND OR a.policy_id IS DISTINCT FROM NEW.policy_id OR a.namespace IS DISTINCT FROM NEW.namespace THEN
        RAISE EXCEPTION 'native network attempt scope differs';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.state<>'issued' OR NEW.revision<>1 OR NEW.record ? 'original'
           OR NEW.record->'original_caller_closed' IS DISTINCT FROM 'false'::jsonb
           OR (NEW.action='install' AND a.state NOT IN ('acknowledged','registered'))
           OR (NEW.action='remove' AND a.state NOT IN ('aborting','draining'))
        THEN RAISE EXCEPTION 'native network issuance is not a fresh eligible command'; END IF;
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id
           OR NEW.policy_id IS DISTINCT FROM OLD.policy_id OR NEW.namespace IS DISTINCT FROM OLD.namespace
           OR NEW.action IS DISTINCT FROM OLD.action OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
           OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.revision<>OLD.revision+1
           OR (NEW.record-'context'-'revision'-'original'-'observation'-'original_caller_closed') IS DISTINCT FROM (OLD.record-'context'-'revision'-'original'-'observation'-'original_caller_closed')
           OR ((NEW.record->'context')-'state') IS DISTINCT FROM ((OLD.record->'context')-'state')
           OR (OLD.record ? 'original' AND NEW.record->'original' IS DISTINCT FROM OLD.record->'original')
        THEN RAISE EXCEPTION 'native network origin or original custody is immutable'; END IF;
        IF jsonb_typeof(NEW.record->'original_caller_closed') IS DISTINCT FROM 'boolean'
           OR (OLD.record->'original_caller_closed'='true'::jsonb AND NEW.record->'original_caller_closed' IS DISTINCT FROM 'true'::jsonb)
           OR (NEW.record->'original_caller_closed' IS DISTINCT FROM OLD.record->'original_caller_closed' AND (OLD.record ? 'original' OR NOT (NEW.record ? 'original')))
        THEN RAISE EXCEPTION 'native network original caller closure is immutable'; END IF;
        IF NOT (
            (OLD.state='issued' AND NEW.state IN ('redeemed','no_effect')) OR
            (OLD.state='redeemed' AND NEW.state IN ('received','unknown','observed')) OR
            (OLD.state IN ('received','unknown') AND NEW.state IN ('unknown','observed')) OR
            (OLD.state='observed' AND NEW.state='observed')
        ) THEN RAISE EXCEPTION 'native network transition cannot reopen a send'; END IF;
        IF NEW.state='redeemed' AND (OLD.record ? 'original' OR
           (NEW.action='install' AND a.state NOT IN ('acknowledged','registered')) OR
           (NEW.action='remove' AND a.state NOT IN ('aborting','draining')))
        THEN RAISE EXCEPTION 'native network redemption lost its original eligible state'; END IF;
        IF NEW.state='observed' AND (NOT (NEW.record ? 'original') OR NEW.record->'original_caller_closed' IS DISTINCT FROM 'true'::jsonb) THEN
            RAISE EXCEPTION 'native network receiving requires original caller custody';
        END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_native_worker_network_guard BEFORE INSERT OR UPDATE OR DELETE
ON public.capacity_native_worker_network_permits FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_network_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_network_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO public.capacity_native_worker_network_events(permit_id,revision,record) VALUES(NEW.id,NEW.revision,NEW.record);
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_native_worker_network_event AFTER INSERT OR UPDATE
ON public.capacity_native_worker_network_permits FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_network_event();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_network_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'native network history is append-only'; END $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_native_worker_network_history_guard BEFORE UPDATE OR DELETE
ON public.capacity_native_worker_network_events FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_network_history_guard();

-- The same locked Attempt arbiters network sends against cleanup and address
-- release. A missing/expired ACK never settles an exposed network command.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_worker_network_attempt_fence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state='aborting' AND OLD.state<>'aborting' THEN
        IF EXISTS(SELECT 1 FROM public.capacity_native_worker_network_permits WHERE attempt_id=NEW.id AND action='install' AND state IN ('redeemed','received','unknown') AND record->'original_caller_closed' IS DISTINCT FROM 'true'::jsonb) THEN
            RAISE EXCEPTION 'native cleanup is fenced by an exposed network send';
        END IF;
        UPDATE public.capacity_native_worker_network_permits
        SET state='no_effect',revision=revision+1,
            record=jsonb_set(jsonb_set(record,'{context,state}','"no_effect"'::jsonb),'{revision}',to_jsonb(revision+1))
        WHERE attempt_id=NEW.id AND action='install' AND state='issued';
    END IF;
    IF NEW.state='absent' AND OLD.state NOT IN ('reserved','absent') THEN
        IF EXISTS(SELECT 1 FROM public.capacity_native_worker_network_permits WHERE attempt_id=NEW.id AND state IN ('issued','redeemed','received','unknown') AND record->'original_caller_closed' IS DISTINCT FROM 'true'::jsonb) THEN
            RAISE EXCEPTION 'native address release is fenced by an unsettled network command';
        END IF;
        IF EXISTS(SELECT 1 FROM public.capacity_native_worker_network_permits WHERE attempt_id=NEW.id AND action='install' AND state NOT IN ('issued','no_effect')) AND
           NOT EXISTS(SELECT 1 FROM public.capacity_native_worker_network_permits WHERE attempt_id=NEW.id AND action='remove' AND state='observed') THEN
            RAISE EXCEPTION 'native address release requires observed owned network removal';
        END IF;
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_native_worker_network_attempt_fence BEFORE UPDATE
ON public.capacity_native_worker_attempts FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_network_attempt_fence();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM public.capacity_native_worker_network_permits) OR EXISTS(SELECT 1 FROM public.capacity_native_worker_network_events) THEN
        RAISE EXCEPTION 'cannot erase retained native network authority';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_native_worker_network_attempt_fence ON public.capacity_native_worker_attempts;
DROP FUNCTION IF EXISTS public.capacity_native_worker_network_attempt_fence();
DROP TRIGGER IF EXISTS capacity_native_worker_network_history_guard ON public.capacity_native_worker_network_events;
DROP FUNCTION IF EXISTS public.capacity_native_worker_network_history_guard();
DROP TRIGGER IF EXISTS capacity_native_worker_network_event ON public.capacity_native_worker_network_permits;
DROP FUNCTION IF EXISTS public.capacity_native_worker_network_event();
DROP TRIGGER IF EXISTS capacity_native_worker_network_guard ON public.capacity_native_worker_network_permits;
DROP FUNCTION IF EXISTS public.capacity_native_worker_network_guard();
DROP TABLE IF EXISTS public.capacity_native_worker_network_events;
DROP TABLE IF EXISTS public.capacity_native_worker_network_permits;
