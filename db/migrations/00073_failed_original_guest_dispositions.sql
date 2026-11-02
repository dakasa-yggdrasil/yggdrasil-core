-- +goose Up
-- A separate accounting terminal for a witnessed, expired original Guest
-- attempt. It is not successful execution, acknowledgment or writer quiescence.
-- Historical grant, accepted settlement, witness, run and dispatch return stay.
CREATE TABLE public.capacity_failed_original_dispositions (
 id uuid PRIMARY KEY,
 grant_id uuid NOT NULL UNIQUE REFERENCES public.capacity_mutation_grants(id),
 preregistration_id uuid NOT NULL UNIQUE REFERENCES public.capacity_vm_provisioning_preregistrations(id),
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
 original_grant_sha256 text NOT NULL CHECK(original_grant_sha256 ~ '^[0-9a-f]{64}$'),
 original_preregistration_sha256 text NOT NULL CHECK(original_preregistration_sha256 ~ '^[0-9a-f]{64}$'),
 original_witness_sha256 text NOT NULL CHECK(original_witness_sha256 ~ '^[0-9a-f]{64}$'),
 original_dispatch_sha256 text NOT NULL CHECK(original_dispatch_sha256 ~ '^[0-9a-f]{64}$'),
 original_run_sha256 text NOT NULL CHECK(original_run_sha256 ~ '^[0-9a-f]{64}$'),
 disposition_sha256 text NOT NULL UNIQUE CHECK(disposition_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 disposition_record jsonb NOT NULL CHECK(jsonb_typeof(disposition_record)='object'),
 recorded_at timestamptz NOT NULL,
 closed_generation bigint NOT NULL CHECK(closed_generation BETWEEN 1 AND 9007199254740991),
 closed_fencing_token bigint NOT NULL CHECK(closed_fencing_token BETWEEN 1 AND 9007199254740991),
 UNIQUE(id,grant_id), UNIQUE(id,job_id),
 CHECK(disposition_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(disposition_sha256=encode(sha256(original_wire),'hex')),
 CHECK((disposition_record->>'schema') IS NOT DISTINCT FROM 'failed_original_guest_terminal_disposition_v1'),
 CHECK((disposition_record->>'id') IS NOT DISTINCT FROM id::text),
 CHECK((disposition_record->>'grant_id') IS NOT DISTINCT FROM grant_id::text),
 CHECK((disposition_record->>'preregistration_id') IS NOT DISTINCT FROM preregistration_id::text),
 CHECK((disposition_record->>'job_id') IS NOT DISTINCT FROM job_id::text),
 CHECK((disposition_record->>'run_id') IS NOT DISTINCT FROM run_id::text),
 CHECK((disposition_record->>'original_grant_sha256') IS NOT DISTINCT FROM original_grant_sha256),
 CHECK((disposition_record->>'original_preregistration_sha256') IS NOT DISTINCT FROM original_preregistration_sha256),
 CHECK((disposition_record->>'original_witness_sha256') IS NOT DISTINCT FROM original_witness_sha256),
 CHECK((disposition_record->>'original_dispatch_sha256') IS NOT DISTINCT FROM original_dispatch_sha256),
 CHECK((disposition_record->>'original_run_sha256') IS NOT DISTINCT FROM original_run_sha256),
 CHECK((disposition_record->>'closed_generation')::bigint IS NOT DISTINCT FROM closed_generation),
 CHECK((disposition_record->>'closed_fencing_token')::bigint IS NOT DISTINCT FROM closed_fencing_token),
 CHECK((disposition_record->>'recorded_at')::timestamptz IS NOT DISTINCT FROM recorded_at),
 CHECK(jsonb_typeof(disposition_record->'issuer') IS NOT DISTINCT FROM 'string'
       AND length(disposition_record->>'issuer') BETWEEN 1 AND 256),
 CHECK((disposition_record->'original_accepted_unchanged') IS NOT DISTINCT FROM 'true'::jsonb),
 CHECK((disposition_record->'original_witness_preserved') IS NOT DISTINCT FROM 'true'::jsonb),
 CHECK((disposition_record->'original_unknown_ACK_preserved') IS NOT DISTINCT FROM 'true'::jsonb),
 CHECK((disposition_record->>'historical_writer_start_state') IS NOT DISTINCT FROM 'unknown'),
 CHECK((disposition_record->'serving_or_business_or_savings_authority') IS NOT DISTINCT FROM 'false'::jsonb)
);
ALTER TABLE public.capacity_mutation_grants ADD COLUMN failed_original_disposition_id uuid;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_failed_disposition_matching_grant_fk
 FOREIGN KEY(failed_original_disposition_id,id) REFERENCES public.capacity_failed_original_dispositions(id,grant_id);
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_dispositions_mutually_exclusive
 CHECK(original_disposition_id IS NULL OR failed_original_disposition_id IS NULL);
ALTER TABLE public.capacity_dispatch_jobs ADD COLUMN failed_original_disposition_id uuid;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_failed_disposition_matching_job_fk
 FOREIGN KEY(failed_original_disposition_id,id) REFERENCES public.capacity_failed_original_dispositions(id,job_id);
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_state_v2_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_lifecycle_v2_check;
ALTER TABLE public.capacity_dispatch_jobs
 ADD CONSTRAINT capacity_dispatch_jobs_state_v3_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed')),
 ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v3_check CHECK(
  (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
  OR (state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
  OR (state='unknown' AND started_at IS NOT NULL)
  OR (state IN('returned','failed_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)),
 ADD CONSTRAINT capacity_dispatch_jobs_failed_disposition_check CHECK(
  (state='failed_disposed' AND failed_original_disposition_id IS NOT NULL AND finalization_ack_at IS NULL)
  OR (state<>'failed_disposed' AND failed_original_disposition_id IS NULL));

-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_original_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; p public.capacity_vm_provisioning_preregistrations;
 w public.capacity_guest_original_create_witnesses; j public.capacity_dispatch_jobs; r public.workflow_runs;
 current_intent jsonb; e jsonb; o jsonb; native_key text; expected_aux jsonb; observed_aux jsonb;
BEGIN
 -- Read a locator, then acquire the same scope/native-slot/dispatch-scope
 -- advisory identities as production, before retaining row locks.
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[g.namespace,g.environment,g.domain,g.dimension])::text,0));
 native_key='["capacity-native-slot",'||to_json(g.integration_instance_id::text)::text||','||
   to_json(g.scope_checksum)::text||','||to_json(g.profile_name)::text||','||g.slot::text||']';
 PERFORM pg_advisory_xact_lock(hashtextextended(native_key,0));
 -- Dispatch scope is deliberately the same compact four-string JSON key.
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[g.namespace,g.environment,g.domain,g.dimension])::text,0));
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id FOR SHARE;
 SELECT * INTO STRICT w FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=p.id FOR SHARE;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT r FROM public.workflow_runs WHERE id=NEW.run_id FOR UPDATE;
 SELECT intent INTO STRICT current_intent FROM public.capacity_intents
 WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension FOR UPDATE;
 e=j.envelope::jsonb; o=NEW.disposition_record->'observation';
 IF g.original_disposition_id IS NOT NULL OR g.failed_original_disposition_id IS NOT NULL
 OR EXISTS(SELECT 1 FROM public.capacity_original_create_dispositions WHERE grant_id=g.id)
 OR g.state<>'settled' OR g.grant_record#>>'{grant,state}' IS DISTINCT FROM 'settled'
 OR g.grant_record#>>'{settlement,outcome}' IS DISTINCT FROM 'accepted'
 OR g.grant_record#>'{settlement,transport_completed}' IS DISTINCT FROM 'true'::jsonb
 OR g.grant_record#>'{settlement,auxiliary_inventory_complete}' IS DISTINCT FROM 'true'::jsonb
 OR jsonb_typeof(g.grant_record#>'{settlement,auxiliary_resources}') IS DISTINCT FROM 'array'
 OR jsonb_array_length(g.grant_record#>'{settlement,auxiliary_resources}') NOT BETWEEN 1 AND 16
 OR g.grant_record->>'event_provider' IS DISTINCT FROM 'hetzner'
 OR g.grant_record#>>'{settlement,original_provider_create_return,provider}' IS DISTINCT FROM 'hetzner'
 OR g.grant_record#>>'{settlement,original_provider_create_return,schema}' IS DISTINCT FROM 'hetzner_original_create_return_v1'
 OR g.grant_record#>'{settlement,original_provider_create_return,response_status}' IS DISTINCT FROM '201'::jsonb
 OR g.grant_record#>>'{settlement,original_provider_create_return,adapter_source_commit}'
    IS DISTINCT FROM g.grant_record#>>'{binding,original_provider_source_commit}'
 OR g.grant_record#>>'{grant,grant_id}' IS DISTINCT FROM g.id::text
 OR g.grant_record#>>'{settlement,grant_id}' IS DISTINCT FROM g.id::text
 OR g.grant_record#>>'{settlement,attempt_id}' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR g.grant_record#>>'{settlement,request_sha256}' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR coalesce(g.grant_record#>>'{settlement,resource_id}','')=''
 OR coalesce(g.grant_record#>>'{settlement,resource_created_at}','')=''
 OR p.create_grant_id<>g.id OR p.original_deadline>=clock_timestamp() OR g.expires_at>=clock_timestamp()
 OR p.original_wire IS NULL OR p.preregistration_record IS DISTINCT FROM convert_from(p.original_wire,'UTF8')::jsonb
 OR p.preregistration_record->>'original_create_grant_id' IS DISTINCT FROM g.id::text
 OR p.preregistration_record->>'original_create_request_sha256' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR p.preregistration_record->>'policy_id' IS DISTINCT FROM g.grant_record->>'policy_id'
 OR p.preregistration_record->>'policy_checksum' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR p.preregistration_record->>'workflow_id' IS DISTINCT FROM g.grant_record->>'workflow_id'
 OR (p.preregistration_record->>'original_deadline')::timestamptz IS DISTINCT FROM p.original_deadline
 OR (p.preregistration_record->>'original_workflow_context_deadline')::timestamptz IS NULL
 OR (p.preregistration_record->>'original_workflow_context_deadline')::timestamptz>=clock_timestamp()
 OR w.original_record IS DISTINCT FROM convert_from(w.original_wire,'UTF8')::jsonb
 OR w.witness_sha256<>encode(sha256(w.original_wire),'hex')
 OR w.original_create_attempt_id::text IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR w.original_record->>'preregistration_id' IS DISTINCT FROM p.id::text
 OR w.original_record->>'original_create_grant_id' IS DISTINCT FROM g.id::text
 OR w.original_record->>'original_create_attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR w.original_record->>'original_create_request_sha256' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR w.original_record#>>'{tuple,provider}' IS DISTINCT FROM 'hetzner'
 OR w.original_record#>>'{tuple,integration_instance_id}' IS DISTINCT FROM g.integration_instance_id::text
 OR w.original_record#>>'{tuple,scope_checksum}' IS DISTINCT FROM g.scope_checksum
 OR w.original_record#>>'{tuple,profile}' IS DISTINCT FROM g.profile_name
 OR (w.original_record#>>'{tuple,slot}')::integer IS DISTINCT FROM g.slot
 OR w.original_record#>>'{tuple,resource_id}' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_id}'
 OR w.original_record#>>'{tuple,resource_created_at}' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_created_at}'
 OR NEW.original_grant_sha256<>encode(sha256(convert_to(g.grant_record::text,'UTF8')),'hex')
 OR NEW.original_preregistration_sha256<>encode(sha256(p.original_wire),'hex')
 OR NEW.original_witness_sha256<>encode(sha256(w.original_wire),'hex')
 THEN RAISE EXCEPTION 'failed original disposition requires exact expired witnessed accepted H original'; END IF;
 IF j.state<>'unknown' OR j.failed_original_disposition_id IS NOT NULL OR j.protocol<>'capacity_dispatch_prestart_v1'
 OR j.run_id<>r.id OR j.started_at IS NULL OR j.returned_at IS NULL OR j.finalization_ack_at IS NOT NULL
 OR j.lease_owner IS NULL OR j.lease_expires_at IS NULL OR j.lease_expires_at>=clock_timestamp()
 OR j.envelope_sha256<>encode(sha256(convert_to(j.envelope,'UTF8')),'hex')
 OR e->>'job_id' IS DISTINCT FROM j.id::text OR e->>'run_id' IS DISTINCT FROM r.id::text
 OR e->>'protocol' IS DISTINCT FROM j.protocol OR e->>'source_tick' IS DISTINCT FROM j.source_tick
 OR (j.realm,j.environment,j.domain,j.dimension) IS DISTINCT FROM (g.namespace,g.environment,g.domain,g.dimension)
 OR e->>'realm' IS DISTINCT FROM j.realm OR e->>'environment' IS DISTINCT FROM j.environment
 OR e->>'domain' IS DISTINCT FROM j.domain OR e->>'dimension' IS DISTINCT FROM j.dimension
 OR e#>>'{policy,id}' IS DISTINCT FROM g.grant_record->>'policy_id'
 OR e#>>'{policy,checksum}' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR e#>>'{workflow,id}' IS DISTINCT FROM g.grant_record->>'workflow_id'
 OR (r.workflow_id IS NOT NULL AND r.workflow_id::text IS DISTINCT FROM g.grant_record->>'workflow_id')
 OR r.workflow_namespace IS DISTINCT FROM e#>>'{workflow,namespace}'
 OR r.workflow_name IS DISTINCT FROM e#>>'{workflow,name}'
 OR r.workflow_version::text IS DISTINCT FROM e#>>'{workflow,version}'
 OR r.inputs IS DISTINCT FROM e->'inputs' OR r.metadata IS DISTINCT FROM e->'metadata'
 OR r.status<>'failed' OR r.started_at IS NULL OR r.finished_at IS NULL
 OR r.result->>'status' IS DISTINCT FROM 'failed'
 OR r.result#>>'{workflow,id}' IS DISTINCT FROM e#>>'{workflow,id}'
 OR r.result#>>'{workflow,namespace}' IS DISTINCT FROM e#>>'{workflow,namespace}'
 OR r.result#>>'{workflow,name}' IS DISTINCT FROM e#>>'{workflow,name}'
 OR r.result#>>'{workflow,version}' IS DISTINCT FROM e#>>'{workflow,version}'
 OR NEW.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')
 OR NEW.original_run_sha256<>encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'failed original disposition requires exact failed run and expired unknown original return without ACK'; END IF;
 IF NEW.closed_generation IS DISTINCT FROM (current_intent->>'generation')::bigint
 OR NEW.closed_fencing_token IS DISTINCT FROM (current_intent->>'fencing_token')::bigint+1
 OR current_intent->>'policy_id' IS DISTINCT FROM g.grant_record->>'policy_id'
 OR current_intent->>'policy_checksum' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR ((current_intent->>'lease_expires_at')::timestamptz IS NOT NULL
     AND (current_intent->>'lease_expires_at')::timestamptz>=clock_timestamp())
 OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 THEN RAISE EXCEPTION 'failed original disposition requires current expired intent and exactly next fence'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=g.id)
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=g.id::text)
 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE
   (integration_instance_id=g.integration_instance_id AND resource_id=g.grant_record#>>'{settlement,resource_id}')
   OR (namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension AND resource_id<>''))
 OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE
   (workflow_id=(g.grant_record->>'workflow_id')::uuid OR (workflow_id IS NULL
    AND workflow_namespace=e#>>'{workflow,namespace}' AND workflow_name=e#>>'{workflow,name}'
    AND workflow_version::text=e#>>'{workflow,version}')) AND status IN('pending','running'))
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE id<>j.id AND realm=j.realm AND environment=j.environment
   AND domain=j.domain AND dimension=j.dimension AND (state IN('queued','started','unknown') OR (state='returned' AND finalization_ack_at IS NULL)))
 THEN RAISE EXCEPTION 'failed original disposition cannot close enrolled serving factory compensation or active work'; END IF;
 IF jsonb_typeof(o) IS DISTINCT FROM 'object'
 OR o->>'schema' IS DISTINCT FROM 'original_accepted_create_disposition_observation_v1'
 OR o->>'provider' IS DISTINCT FROM 'hetzner'
 OR o->>'inventory_basis' IS DISTINCT FROM 'original_accepted_auxiliary_inventory_v1'
 OR o->>'profile' IS DISTINCT FROM g.profile_name OR (o->>'slot')::integer IS DISTINCT FROM g.slot
 OR o->>'grant_id' IS DISTINCT FROM g.id::text OR o->>'attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR o->>'request_sha256' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR o->>'resource_id' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_id}'
 OR o->>'resource_created_at' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_created_at}'
 OR o->>'original_adapter_source_commit' IS DISTINCT FROM g.grant_record#>>'{binding,original_provider_source_commit}'
 OR o->>'resource_state' IS DISTINCT FROM 'absent'
 OR o->'resource_absence_complete' IS DISTINCT FROM 'true'::jsonb
 OR o->'auxiliary_inventory_complete' IS DISTINCT FROM 'true'::jsonb
 OR o->'shared_resources_preserved' IS DISTINCT FROM 'true'::jsonb
 OR o->'native_mutations' IS DISTINCT FROM '0'::jsonb
 OR o->'Guest_admission_or_business_or_savings_authority' IS DISTINCT FROM 'false'::jsonb
 OR jsonb_typeof(o->'native_reads') IS DISTINCT FROM 'array' OR jsonb_array_length(o->'native_reads') NOT BETWEEN 1 AND 64
 OR jsonb_typeof(o->'auxiliary_resources') IS DISTINCT FROM 'array' OR jsonb_array_length(o->'auxiliary_resources') NOT BETWEEN 1 AND 16
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(o->'auxiliary_resources') a WHERE a->'absent' IS DISTINCT FROM 'true'::jsonb)
 THEN RAISE EXCEPTION 'failed original disposition requires separate complete readonly native H absence'; END IF;
 SELECT jsonb_agg(jsonb_build_object('kind',a->'kind','id',a->'id') ORDER BY ord)
 INTO expected_aux FROM jsonb_array_elements(g.grant_record#>'{settlement,auxiliary_resources}') WITH ORDINALITY AS x(a,ord)
 WHERE a->'requires_absence'='true'::jsonb;
 SELECT jsonb_agg(jsonb_build_object('kind',a->'kind','id',a->'id') ORDER BY ord)
 INTO observed_aux FROM jsonb_array_elements(o->'auxiliary_resources') WITH ORDINALITY AS x(a,ord);
 IF expected_aux IS NULL OR observed_aux IS DISTINCT FROM expected_aux
 THEN RAISE EXCEPTION 'failed original disposition must cover exact complete accepted auxiliary inventory'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_original_disposition_insert BEFORE INSERT ON public.capacity_failed_original_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_disposition_insert();

-- +goose StatementBegin
CREATE FUNCTION public.immutable_failed_original_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'failed original disposition is immutable'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_original_disposition_immutable BEFORE UPDATE OR DELETE ON public.capacity_failed_original_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.immutable_failed_original_disposition();
-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_original_grant_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d public.capacity_failed_original_dispositions;
BEGIN
 IF OLD.failed_original_disposition_id IS NOT NULL THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'failed disposed original grant is immutable'; END IF;
 ELSIF NEW.failed_original_disposition_id IS NOT NULL THEN
  IF OLD.original_disposition_id IS NOT NULL OR NEW.original_disposition_id IS NOT NULL
  OR (to_jsonb(NEW)-'failed_original_disposition_id') IS DISTINCT FROM (to_jsonb(OLD)-'failed_original_disposition_id')
  THEN RAISE EXCEPTION 'failed disposition cannot rewrite accepted original'; END IF;
  SELECT * INTO STRICT d FROM public.capacity_failed_original_dispositions WHERE id=NEW.failed_original_disposition_id AND grant_id=OLD.id;
  IF d.original_grant_sha256<>encode(sha256(convert_to(OLD.grant_record::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'failed disposition original grant digest changed'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_original_grant_pointer BEFORE UPDATE ON public.capacity_mutation_grants
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_grant_pointer();

-- +goose StatementBegin
CREATE FUNCTION public.check_failed_original_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE d public.capacity_failed_original_dispositions;
BEGIN
 IF old_row.failed_original_disposition_id IS NOT NULL OR old_row.state='failed_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'failed disposed original dispatch is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'unknown' OR new_row.state<>'failed_disposed' OR new_row.failed_original_disposition_id IS NULL
 OR old_row.started_at IS NULL OR old_row.returned_at IS NULL OR old_row.finalization_ack_at IS NOT NULL
 OR old_row.lease_expires_at IS NULL OR old_row.lease_expires_at>=clock_timestamp()
 OR new_row.finalization_ack_at IS NOT NULL
 OR (to_jsonb(new_row)-ARRAY['state','updated_at','failed_original_disposition_id'])
    IS DISTINCT FROM (to_jsonb(old_row)-ARRAY['state','updated_at','failed_original_disposition_id'])
 THEN RAISE EXCEPTION 'failed disposition requires unchanged expired unknown actual return and NULL original ACK'; END IF;
 SELECT * INTO STRICT d FROM public.capacity_failed_original_dispositions WHERE id=new_row.failed_original_disposition_id AND job_id=old_row.id;
 -- Deferred complete links make a committed unlinked ledger impossible;
 -- immutability makes a prior linked terminal impossible to reopen. Therefore
 -- the first unknown->failed_disposed transition necessarily shares this commit,
 -- including when the insertion used a subtransaction/savepoint.
 IF d.run_id<>old_row.run_id
 OR d.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(old_row)::text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'failed dispatch requires same transaction original snapshot and matching disposition'; END IF;
 RETURN new_row;
END; $$;
-- +goose StatementEnd
-- The replacement below is generated from the exact migration61 function:
-- only the narrow terminal branch precedes its otherwise unchanged body.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state='failed_disposed' OR NEW.state='failed_disposed'
       OR OLD.failed_original_disposition_id IS NOT NULL OR NEW.failed_original_disposition_id IS NOT NULL THEN
        RETURN public.check_failed_original_dispatch_transition(OLD,NEW);
    END IF;
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
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_original_dispatch_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='failed_disposed' OR NEW.failed_original_disposition_id IS NOT NULL
 THEN RAISE EXCEPTION 'failed disposition requires retained original unknown job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_original_dispatch_insert BEFORE INSERT ON public.capacity_dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_dispatch_insert();
-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_original_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD AND EXISTS(SELECT 1 FROM public.capacity_failed_original_dispositions WHERE run_id=OLD.id)
 THEN RAISE EXCEPTION 'failed disposed original workflow history is immutable'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_original_workflow_immutable BEFORE UPDATE ON public.workflow_runs
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_workflow();

-- Ledger first, then both projections and the intent CAS in the SAME commit.
-- +goose StatementBegin
CREATE FUNCTION public.require_failed_original_disposition_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; j public.capacity_dispatch_jobs; i jsonb;
BEGIN
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT intent INTO STRICT i FROM public.capacity_intents
 WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension;
 IF g.failed_original_disposition_id IS DISTINCT FROM NEW.id OR g.original_disposition_id IS NOT NULL
 OR j.failed_original_disposition_id IS DISTINCT FROM NEW.id OR j.state<>'failed_disposed' OR j.finalization_ack_at IS NOT NULL
 OR (i->>'generation')::bigint IS DISTINCT FROM NEW.closed_generation
 OR (i->>'fencing_token')::bigint IS DISTINCT FROM NEW.closed_fencing_token
 OR i->>'phase' IS DISTINCT FROM 'reconciled_failed_floor'
 OR i#>'{decision,execution_permitted}' IS DISTINCT FROM 'false'::jsonb
 OR i->'floor_degraded' IS DISTINCT FROM 'true'::jsonb
 OR i->'recovery_only' IS DISTINCT FROM 'false'::jsonb
 OR coalesce(i->>'lease_owner','')<>'' OR coalesce(i->>'lease_executor_id','')<>'' OR i->>'lease_expires_at' IS NOT NULL
 OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=NEW.preregistration_id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=NEW.preregistration_id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=NEW.preregistration_id)
 OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=NEW.grant_id)
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=NEW.grant_id::text)
 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE namespace=g.namespace AND environment=g.environment
   AND domain=g.domain AND dimension=g.dimension AND resource_id<>'')
 THEN RAISE EXCEPTION 'failed original disposition requires both linked terminal projections and intent fence in same commit'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER failed_original_disposition_complete_links AFTER INSERT ON public.capacity_failed_original_dispositions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_failed_original_disposition_links();

-- A late callback cannot enroll or adopt this expired original after the
-- accounting closure. A distinct next grant/preregistration remains unrelated.
-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_original_late_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target uuid; g public.capacity_mutation_grants; native_key text;
BEGIN
 IF TG_TABLE_NAME='capacity_factory_original_grant_bindings' THEN target=NEW.grant_id;
 ELSE SELECT create_grant_id INTO STRICT target FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id;
 END IF;
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=target;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[g.namespace,g.environment,g.domain,g.dimension])::text,0));
 native_key='["capacity-native-slot",'||to_json(g.integration_instance_id::text)::text||','||
   to_json(g.scope_checksum)::text||','||to_json(g.profile_name)::text||','||g.slot::text||']';
 PERFORM pg_advisory_xact_lock(hashtextextended(native_key,0));
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=target FOR SHARE;
 IF g.failed_original_disposition_id IS NOT NULL
 OR EXISTS(SELECT 1 FROM public.capacity_failed_original_dispositions WHERE grant_id=target)
 THEN RAISE EXCEPTION 'failed disposed original cannot acquire late ownership'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_original_late_enrollment BEFORE INSERT ON public.capacity_vm_original_enrollments
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_late_ownership();
CREATE TRIGGER failed_original_late_installation BEFORE INSERT ON public.capacity_guest_original_installations
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_late_ownership();
CREATE TRIGGER failed_original_late_factory BEFORE INSERT ON public.capacity_factory_original_grant_bindings
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_late_ownership();
CREATE TRIGGER failed_original_late_retirement BEFORE INSERT ON public.capacity_vm_retirement_intents
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_original_late_ownership();

DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled') AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL;
-- Existing dispatch active-scope/claim indexes exclude failed_disposed. Their
-- predicates and the original ACK restriction are intentionally untouched.

-- +goose Down
-- This terminal is a permanent no-replay boundary, including its migration.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'failed original Guest dispositions require retained forward-only schema'; END; $$;
-- +goose StatementEnd
