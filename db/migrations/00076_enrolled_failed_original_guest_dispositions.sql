-- +goose Up
-- A separate production accounting terminal for an enrolled, expired failed
-- original Guest attempt. Existing migrations73/74/75 remain unchanged. It is not successful execution, acknowledgment or writer quiescence.
-- Historical grant, accepted settlement, witness, run and dispatch return stay.
CREATE TABLE public.capacity_enrolled_failed_original_dispositions (
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
 original_registration_sha256 text NOT NULL CHECK(original_registration_sha256 ~ '^[0-9a-f]{64}$'),
 original_receipt_sha256 text NOT NULL CHECK(original_receipt_sha256 ~ '^[0-9a-f]{64}$'),
 original_enrollment_sha256 text NOT NULL CHECK(original_enrollment_sha256 ~ '^[0-9a-f]{64}$'),
 disposition_sha256 text NOT NULL UNIQUE CHECK(disposition_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 disposition_record jsonb NOT NULL CHECK(jsonb_typeof(disposition_record)='object'),
 recorded_at timestamptz NOT NULL,
 closed_generation bigint NOT NULL CHECK(closed_generation BETWEEN 1 AND 9007199254740991),
 closed_fencing_token bigint NOT NULL CHECK(closed_fencing_token BETWEEN 1 AND 9007199254740991),
 UNIQUE(id,grant_id), UNIQUE(id,job_id),
 CHECK(disposition_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(disposition_sha256=encode(sha256(original_wire),'hex')),
 CHECK((disposition_record->>'schema') IS NOT DISTINCT FROM 'enrolled_failed_original_guest_terminal_disposition_v1'),
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
 CHECK(disposition_record->>'original_registration_sha256' IS NOT DISTINCT FROM original_registration_sha256),
 CHECK(disposition_record->>'original_receipt_sha256' IS NOT DISTINCT FROM original_receipt_sha256),
 CHECK(disposition_record->>'original_enrollment_sha256' IS NOT DISTINCT FROM original_enrollment_sha256),
 CHECK(disposition_record->'original_enrollment_preserved' IS NOT DISTINCT FROM 'true'::jsonb),
 CHECK(disposition_record->'Guest_quiescence_proved' IS NOT DISTINCT FROM 'false'::jsonb),
 CHECK(disposition_record->'installation_or_serving_authority' IS NOT DISTINCT FROM 'false'::jsonb),
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
ALTER TABLE public.capacity_mutation_grants ADD COLUMN enrolled_failed_disposition_id uuid;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_enrolled_failed_matching_grant_fk
 FOREIGN KEY(enrolled_failed_disposition_id,id) REFERENCES public.capacity_enrolled_failed_original_dispositions(id,grant_id);
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_enrolled_failed_exclusive
 CHECK(enrolled_failed_disposition_id IS NULL OR (original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL));
ALTER TABLE public.capacity_dispatch_jobs ADD COLUMN enrolled_failed_disposition_id uuid;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_enrolled_failed_matching_job_fk
 FOREIGN KEY(enrolled_failed_disposition_id,id) REFERENCES public.capacity_enrolled_failed_original_dispositions(id,job_id);
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_state_v4_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_lifecycle_v4_check;
ALTER TABLE public.capacity_dispatch_jobs
 ADD CONSTRAINT capacity_dispatch_jobs_state_v5_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed')),
 ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v5_check CHECK(
  (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
  OR (state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
  OR (state='unknown' AND started_at IS NOT NULL)
  OR (state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)),
 ADD CONSTRAINT capacity_dispatch_jobs_enrolled_failed_check CHECK(
  (state='enrolled_failed_disposed' AND enrolled_failed_disposition_id IS NOT NULL AND finalization_ack_at IS NULL)
  OR (state<>'enrolled_failed_disposed' AND enrolled_failed_disposition_id IS NULL));

-- +goose StatementBegin
CREATE FUNCTION public.guard_enrolled_failed_original_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; p public.capacity_vm_provisioning_preregistrations;
 w public.capacity_guest_original_create_witnesses; j public.capacity_dispatch_jobs; r public.workflow_runs;
 current_intent jsonb; e jsonb; o jsonb; native_key text; expected_aux jsonb; observed_aux jsonb;
 en public.capacity_vm_original_enrollments; reg jsonb; receipt jsonb; provider text; native_read jsonb; body bytea; previous_return timestamptz; total bigint=0; server_seen boolean=false; aux_observation jsonb; projected jsonb;
 trail_row jsonb; trail_event jsonb; trail_matches integer; legacy_aws_unknown_aux boolean;
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
 SELECT * INTO STRICT en FROM public.capacity_vm_original_enrollments WHERE preregistration_id=p.id FOR SHARE;
 reg=convert_from(en.registration_wire,'UTF8')::jsonb; receipt=convert_from(en.receipt_wire,'UTF8')::jsonb;
 provider=g.grant_record->>'event_provider';
 -- The owning c34 Settle JSON omits both false and the empty AUX slice.
 -- Derive the legacy mode once, preserving original bytes and refusing JSONnull
 -- or any foreign type/value rather than treating it as an empty inventory.
 legacy_aws_unknown_aux=(provider='aws'
  AND g.grant_record#>>'{binding,original_provider_source_commit}'='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
  AND (NOT ((g.grant_record->'settlement') ? 'auxiliary_inventory_complete')
   OR g.grant_record#>'{settlement,auxiliary_inventory_complete}'='false'::jsonb)
  AND (NOT ((g.grant_record->'settlement') ? 'auxiliary_resources')
   OR g.grant_record#>'{settlement,auxiliary_resources}'='[]'::jsonb)) IS TRUE;
 IF g.original_disposition_id IS NOT NULL OR g.failed_original_disposition_id IS NOT NULL OR g.native_denied_disposition_id IS NOT NULL OR g.enrolled_failed_disposition_id IS NOT NULL
 OR EXISTS(SELECT 1 FROM public.capacity_original_create_dispositions WHERE grant_id=g.id)
 OR g.state<>'settled' OR g.grant_record#>>'{grant,state}' IS DISTINCT FROM 'settled'
 OR g.grant_record#>>'{settlement,outcome}' IS DISTINCT FROM 'accepted'
 OR g.grant_record#>'{settlement,transport_completed}' IS DISTINCT FROM 'true'::jsonb
 OR (
  (provider='hetzner' AND g.grant_record#>>'{binding,original_provider_source_commit}'='6026f78572a0ebfbf1b50984c2d47ff28bdc714d'
   AND g.grant_record#>>'{settlement,original_provider_create_return,schema}'='hetzner_original_create_return_v1'
   AND g.grant_record#>'{settlement,original_provider_create_return,response_status}'='201'::jsonb
   AND g.grant_record#>'{settlement,auxiliary_inventory_complete}'='true'::jsonb
   AND jsonb_typeof(g.grant_record#>'{settlement,auxiliary_resources}')='array'
   AND jsonb_array_length(g.grant_record#>'{settlement,auxiliary_resources}') BETWEEN 1 AND 16)
  OR (provider='aws' AND g.grant_record#>>'{binding,original_provider_source_commit}'='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
   AND g.grant_record#>>'{settlement,original_provider_create_return,schema}'='aws_original_run_instances_return_v1'
   AND g.grant_record#>'{settlement,original_provider_create_return,response_status}'='200'::jsonb
   AND (legacy_aws_unknown_aux
    OR (g.grant_record#>'{settlement,auxiliary_inventory_complete}'='true'::jsonb
     AND CASE WHEN jsonb_typeof(g.grant_record#>'{settlement,auxiliary_resources}')='array'
      THEN jsonb_array_length(g.grant_record#>'{settlement,auxiliary_resources}')=2 ELSE false END)))) IS NOT TRUE
 OR g.grant_record#>>'{settlement,original_provider_create_return,provider}' IS DISTINCT FROM provider
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
 OR w.original_record#>>'{tuple,provider}' IS DISTINCT FROM provider
 OR w.original_record#>>'{tuple,integration_instance_id}' IS DISTINCT FROM g.integration_instance_id::text
 OR w.original_record#>>'{tuple,scope_checksum}' IS DISTINCT FROM g.scope_checksum
 OR w.original_record#>>'{tuple,profile}' IS DISTINCT FROM g.profile_name
 OR (w.original_record#>>'{tuple,slot}')::integer IS DISTINCT FROM g.slot
 OR w.original_record#>>'{tuple,resource_id}' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_id}'
 OR w.original_record#>>'{tuple,resource_created_at}' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_created_at}'
 OR NEW.original_grant_sha256<>encode(sha256(convert_to(g.grant_record::text,'UTF8')),'hex')
 OR NEW.original_preregistration_sha256<>encode(sha256(p.original_wire),'hex')
 OR NEW.original_witness_sha256<>encode(sha256(w.original_wire),'hex')
 THEN RAISE EXCEPTION 'failed original disposition requires exact expired witnessed accepted original'; END IF;
 IF en.registration_wire IS NULL OR en.receipt_wire IS NULL
 OR en.enrollment_record IS DISTINCT FROM receipt->'enrollment'
 OR en.original_provisioning_sha256 IS DISTINCT FROM encode(sha256(en.registration_wire),'hex')
 OR en.original_provisioning_sha256 IS DISTINCT FROM receipt->>'original_provisioning_sha256'
 OR en.enrollment_sha256 IS DISTINCT FROM NEW.original_enrollment_sha256
 OR NEW.original_registration_sha256 IS DISTINCT FROM encode(sha256(en.registration_wire),'hex')
 OR NEW.original_receipt_sha256 IS DISTINCT FROM encode(sha256(en.receipt_wire),'hex')
 OR receipt->>'preregistration_id' IS DISTINCT FROM p.id::text
 OR jsonb_typeof(receipt->'recorded_at') IS DISTINCT FROM 'string'
 OR (receipt->>'recorded_at')::timestamptz IS DISTINCT FROM en.recorded_at
 OR en.recorded_at>=p.original_deadline OR en.recorded_at<(w.original_record->>'observed_at')::timestamptz
 OR reg#>'{result,tuple}' IS DISTINCT FROM w.original_record->'tuple'
 OR reg->'enrollment_statement' IS DISTINCT FROM en.enrollment_record->'statement'
 OR en.enrollment_record#>'{statement,tuple}' IS DISTINCT FROM w.original_record->'tuple'
 OR reg#>>'{result,preregistration_id}' IS DISTINCT FROM p.id::text
 OR reg#>>'{result,original_create_grant_id}' IS DISTINCT FROM g.id::text
 OR reg#>>'{result,original_create_attempt_id}' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR reg#>>'{result,profile_manifest_sha256}' IS DISTINCT FROM p.profile_manifest_sha256
 OR reg#>>'{result,preregistration_nonce_sha256}' IS DISTINCT FROM p.nonce_sha256
 OR jsonb_typeof(reg->'signature') IS DISTINCT FROM 'string' OR length(reg->>'signature') NOT BETWEEN 80 AND 100
 OR jsonb_typeof(en.enrollment_record->'signature') IS DISTINCT FROM 'string' OR length(en.enrollment_record->>'signature') NOT BETWEEN 80 AND 100
 OR reg#>'{result,admission_opened}' IS DISTINCT FROM 'false'::jsonb
 OR reg#>>'{result,schema}' IS DISTINCT FROM 'original_guest_protected_provisioning_v2'
 OR jsonb_typeof(reg#>'{result,production_clock}') IS DISTINCT FROM 'object'
 OR NEW.disposition_record->>'original_binding_sha256' IS DISTINCT FROM encode(sha256(p.binding_wire),'hex')
 OR p.profile_manifest_sha256 IS DISTINCT FROM p.preregistration_record->>'profile_manifest_sha256'
 THEN RAISE EXCEPTION 'enrolled failed disposition requires unchanged complete original signed enrollment and registration'; END IF;
 IF j.state<>'unknown' OR j.enrolled_failed_disposition_id IS NOT NULL OR j.protocol<>'capacity_dispatch_prestart_v1'
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
 IF EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=p.id)
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
 OR o->>'provider' IS DISTINCT FROM provider
 OR (provider='hetzner' AND o->>'inventory_basis' IS DISTINCT FROM 'original_accepted_auxiliary_inventory_v1')
 OR (provider='aws' AND o->>'inventory_basis' IS DISTINCT FROM 'aws_original_enrolled_failed_create_owned_auxiliary_absence_v1')
 OR o->>'profile' IS DISTINCT FROM g.profile_name OR (o->>'slot')::integer IS DISTINCT FROM g.slot
 OR o->>'grant_id' IS DISTINCT FROM g.id::text OR o->>'attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR o->>'request_sha256' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR o->>'resource_id' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_id}'
 OR o->>'resource_created_at' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_created_at}'
 OR o->>'original_adapter_source_commit' IS DISTINCT FROM g.grant_record#>>'{binding,original_provider_source_commit}'
 OR (provider='aws' AND o->>'resource_state' IS DISTINCT FROM 'absent' AND o->>'resource_state' IS DISTINCT FROM 'terminated')
 OR (provider='hetzner' AND o->>'resource_state' IS DISTINCT FROM 'absent')
 OR (provider='hetzner' AND o->>'adapter_source_commit' IS DISTINCT FROM '6026f78572a0ebfbf1b50984c2d47ff28bdc714d')
 OR (provider='aws' AND (o->>'adapter_source_commit' IS NULL OR o->>'adapter_source_commit' !~ '^[a-f0-9]{40}$'))
 OR o->'resource_absence_complete' IS DISTINCT FROM 'true'::jsonb
 OR o->'auxiliary_inventory_complete' IS DISTINCT FROM 'true'::jsonb
 OR o->'shared_resources_preserved' IS DISTINCT FROM 'true'::jsonb
 OR o->'native_mutations' IS DISTINCT FROM '0'::jsonb
 OR o->'Guest_admission_or_business_or_savings_authority' IS DISTINCT FROM 'false'::jsonb
 OR jsonb_typeof(o->'native_reads') IS DISTINCT FROM 'array' OR jsonb_array_length(o->'native_reads') NOT BETWEEN 1 AND 64
 OR jsonb_typeof(o->'auxiliary_resources') IS DISTINCT FROM 'array' OR jsonb_array_length(o->'auxiliary_resources') NOT BETWEEN 1 AND 16
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(o->'auxiliary_resources') a WHERE a->'absent' IS DISTINCT FROM 'true'::jsonb)
 THEN RAISE EXCEPTION 'failed original disposition requires separate complete readonly native absence'; END IF;
 SELECT jsonb_agg(jsonb_build_object('kind',a->'kind','id',a->'id') ORDER BY ord)
 INTO expected_aux FROM jsonb_array_elements(g.grant_record#>'{settlement,auxiliary_resources}') WITH ORDINALITY AS x(a,ord)
 WHERE a->'requires_absence'='true'::jsonb;
 SELECT jsonb_agg(jsonb_build_object('kind',a->'kind','id',a->'id') ORDER BY ord)
 INTO observed_aux FROM jsonb_array_elements(o->'auxiliary_resources') WITH ORDINALITY AS x(a,ord);
 IF g.grant_record#>'{settlement,auxiliary_inventory_complete}'='true'::jsonb AND (expected_aux IS NULL OR observed_aux IS DISTINCT FROM expected_aux)
 THEN RAISE EXCEPTION 'failed original disposition must cover exact complete accepted auxiliary inventory'; END IF;
 IF jsonb_typeof(o->'observation_started_at') IS DISTINCT FROM 'string'
 OR jsonb_typeof(o->'observed_at') IS DISTINCT FROM 'string'
 OR (o->>'observation_started_at')::timestamptz IS NULL OR (o->>'observed_at')::timestamptz IS NULL
 OR (o->>'observed_at')::timestamptz<(o->>'observation_started_at')::timestamptz
 OR (o->>'observed_at')::timestamptz-(o->>'observation_started_at')::timestamptz>interval '60 seconds'
 OR (o->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds'
 OR (o->>'observed_at')::timestamptz<clock_timestamp()-interval '30 seconds'
 THEN RAISE EXCEPTION 'enrolled failed disposition requires bounded fresh original native interval'; END IF;
 FOR native_read IN SELECT value FROM jsonb_array_elements(o->'native_reads') LOOP
  IF jsonb_typeof(native_read->'response_body_base64') IS DISTINCT FROM 'string'
  OR jsonb_typeof(native_read->'response_sha256') IS DISTINCT FROM 'string'
  OR jsonb_typeof(native_read->'response_bytes') IS DISTINCT FROM 'number'
  OR native_read->>'response_sha256' !~ '^[a-f0-9]{64}$'
  OR jsonb_typeof(native_read->'called_at') IS DISTINCT FROM 'string' OR jsonb_typeof(native_read->'returned_at') IS DISTINCT FROM 'string'
  OR (native_read->>'called_at')::timestamptz IS NULL OR (native_read->>'returned_at')::timestamptz IS NULL
  OR (native_read->>'called_at')::timestamptz<(o->>'observation_started_at')::timestamptz
  OR (native_read->>'returned_at')::timestamptz<(native_read->>'called_at')::timestamptz
  OR (native_read->>'returned_at')::timestamptz>(o->>'observed_at')::timestamptz
  OR (previous_return IS NOT NULL AND (native_read->>'called_at')::timestamptz<previous_return)
  OR jsonb_typeof(native_read->'status') IS DISTINCT FROM 'number'
  OR coalesce(native_read->>'operation','')='' OR coalesce(native_read->>'resource_kind','')='' OR coalesce(native_read->>'resource_id','')=''
  THEN RAISE EXCEPTION 'enrolled failed disposition requires complete native read fields and interval'; END IF;
  body=decode(native_read->>'response_body_base64','base64');
  IF body IS NULL OR octet_length(body) NOT BETWEEN 1 AND 65536
  OR octet_length(body) IS DISTINCT FROM (native_read->>'response_bytes')::bigint
  OR encode(sha256(body),'hex') IS DISTINCT FROM native_read->>'response_sha256'
  THEN RAISE EXCEPTION 'enrolled failed disposition requires exact complete native response bytes'; END IF;
  IF provider='aws' AND native_read->>'operation'='LookupEvents'
   AND native_read->>'response_representation' IS DISTINCT FROM 'cloudtrail_lookup_events_userdata_omitted_projection_v1'
  THEN RAISE EXCEPTION 'enrolled failed AWS LookupEvents requires sanitized CloudTrail projection'; END IF;
  IF native_read->>'response_representation'='cloudtrail_lookup_events_userdata_omitted_projection_v1' THEN
   -- PostgreSQL16+ validates original text before JSONB can discard duplicate
   -- keys, including each event encoded as a JSON string inside the response.
   IF (convert_from(body,'UTF8') IS JSON OBJECT WITH UNIQUE KEYS) IS NOT TRUE
   THEN RAISE EXCEPTION 'enrolled failed AWS requires unique-key CloudTrail JSON'; END IF;
   projected=convert_from(body,'UTF8')::jsonb;
   IF provider<>'aws' OR native_read->>'operation'<>'LookupEvents'
   OR projected->>'schema' IS DISTINCT FROM 'cloudtrail_lookup_events_userdata_omitted_projection_v1'
   OR projected->'original_http_body_retained' IS DISTINCT FROM 'false'::jsonb
   OR projected->'original_http_body_hashed' IS DISTINCT FROM 'false'::jsonb
   OR projected->'original_eof_and_close' IS DISTINCT FROM 'true'::jsonb
   OR jsonb_typeof(projected->'user_data_fields_removed') IS DISTINCT FROM 'number'
   OR (projected->>'user_data_fields_removed')::integer<0
   OR jsonb_typeof(projected#>'{response,Events}') IS DISTINCT FROM 'array'
   THEN RAISE EXCEPTION 'enrolled failed AWS requires truthful closed userdata-omitted CloudTrail projection'; END IF;
   -- EventID names the native read; settlement.action_id is the different
   -- original AWS RequestID retained inside the userdata-omitted event.
   IF coalesce(g.grant_record#>>'{settlement,action_id}','') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    OR g.grant_record#>>'{settlement,action_id}'='00000000-0000-0000-0000-000000000000'
    OR coalesce(native_read->>'resource_id','') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    OR native_read->>'resource_id'='00000000-0000-0000-0000-000000000000'
   THEN RAISE EXCEPTION 'enrolled failed AWS CloudTrail event/request identity'; END IF;
   trail_matches=0;
   FOR trail_row IN SELECT value FROM jsonb_array_elements(projected#>'{response,Events}') LOOP
    IF jsonb_typeof(trail_row->'CloudTrailEvent') IS DISTINCT FROM 'string'
    THEN RAISE EXCEPTION 'enrolled failed AWS CloudTrail event/request identity'; END IF;
    IF (trail_row->>'CloudTrailEvent' IS JSON OBJECT WITH UNIQUE KEYS) IS NOT TRUE
    THEN RAISE EXCEPTION 'enrolled failed AWS requires unique-key CloudTrail JSON'; END IF;
    trail_event=(trail_row->>'CloudTrailEvent')::jsonb;
    IF trail_event#>'{requestParameters,userData}' IS NOT NULL
    THEN RAISE EXCEPTION 'enrolled failed AWS requires truthful closed userdata-omitted CloudTrail projection'; END IF;
    IF trail_event->>'requestID' IS NOT DISTINCT FROM g.grant_record#>>'{settlement,action_id}' THEN
     trail_matches=trail_matches+1;
     IF trail_row->>'EventId' IS DISTINCT FROM native_read->>'resource_id'
      OR trail_event->>'eventID' IS DISTINCT FROM native_read->>'resource_id'
     THEN RAISE EXCEPTION 'enrolled failed AWS CloudTrail event/request identity'; END IF;
    END IF;
   END LOOP;
   IF trail_matches<>1 THEN RAISE EXCEPTION 'enrolled failed AWS CloudTrail event/request identity'; END IF;
  ELSIF native_read->>'response_representation' NOT IN('raw_http_body_v1','canonical_provider_SDK_result_v1') OR native_read->>'response_representation' IS NULL THEN
   RAISE EXCEPTION 'enrolled failed native response representation';
  END IF;
  total=total+octet_length(body); previous_return=(native_read->>'returned_at')::timestamptz;
  IF total>1048576 THEN RAISE EXCEPTION 'enrolled failed native aggregate cap'; END IF;
  IF provider='hetzner' AND native_read->>'resource_kind'='server' AND native_read->>'resource_id'=o->>'resource_id' AND (native_read->>'status')::integer=404 THEN server_seen=true; END IF;
  IF provider='aws' AND native_read->>'resource_kind'='aws_ec2_instance' AND native_read->>'resource_id'=o->>'resource_id' AND (native_read->>'status')::integer IN(200,400) THEN server_seen=true; END IF;
 END LOOP;
 IF NOT server_seen THEN RAISE EXCEPTION 'enrolled failed disposition requires exact original resource native read'; END IF;
 FOR aux_observation IN SELECT value FROM jsonb_array_elements(o->'auxiliary_resources') LOOP
  IF jsonb_typeof(aux_observation->'observed_at') IS DISTINCT FROM 'string'
  OR (aux_observation->>'observed_at')::timestamptz IS NULL
  OR (aux_observation->>'observed_at')::timestamptz NOT BETWEEN (o->>'observation_started_at')::timestamptz AND (o->>'observed_at')::timestamptz
  OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(o->'native_reads') rr WHERE rr->>'resource_kind'=aux_observation->>'kind' AND rr->>'resource_id'=aux_observation->>'id')
  THEN RAISE EXCEPTION 'enrolled failed disposition requires exact complete auxiliary read coverage'; END IF;
 END LOOP;
 IF legacy_aws_unknown_aux THEN
  IF jsonb_array_length(o->'auxiliary_resources')<>2 OR jsonb_array_length(o->'native_reads')<>6
  OR o#>>'{auxiliary_resources,0,kind}' IS DISTINCT FROM 'aws_ebs_snapshot_descendants'
  OR coalesce(o#>>'{auxiliary_resources,0,id}','') !~ '^snap-[a-f0-9]{8,17}$'
  OR o#>>'{auxiliary_resources,1,kind}' IS DISTINCT FROM 'aws_network_interface'
  OR coalesce(o#>>'{auxiliary_resources,1,id}','') !~ '^eni-[a-f0-9]{8,17}$'
  OR (SELECT count(DISTINCT rr->>'operation') FROM jsonb_array_elements(o->'native_reads') rr)<>6
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(o->'native_reads') rr WHERE
   NOT ((rr->>'operation'='GetCallerIdentity' AND rr->>'resource_kind'='aws_account' AND (rr->>'status')::integer=200)
    OR(rr->>'operation'='DescribeInstances' AND rr->>'resource_kind'='aws_ec2_instance' AND rr->>'resource_id'=o->>'resource_id' AND (rr->>'status')::integer IN(200,400))
    OR(rr->>'operation'='LookupEvents' AND rr->>'resource_kind'='aws_cloudtrail_event' AND (rr->>'status')::integer=200)
    OR(rr->>'operation'='DescribeImages' AND rr->>'resource_kind'='aws_ami' AND (rr->>'status')::integer=200)
    OR(rr->>'operation'='DescribeVolumes' AND rr->>'resource_kind'='aws_ebs_snapshot_descendants' AND rr->>'resource_id'=o#>>'{auxiliary_resources,0,id}' AND (rr->>'status')::integer=200)
    OR(rr->>'operation'='DescribeNetworkInterfaces' AND rr->>'resource_kind'='aws_network_interface' AND rr->>'resource_id'=o#>>'{auxiliary_resources,1,id}' AND (rr->>'status')::integer=400)))
  THEN RAISE EXCEPTION 'enrolled failed AWS missing inventory requires six distinct owning reads'; END IF;
 END IF;


 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER enrolled_failed_original_disposition_insert BEFORE INSERT ON public.capacity_enrolled_failed_original_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_disposition_insert();

-- +goose StatementBegin
CREATE FUNCTION public.immutable_enrolled_failed_original_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'failed original disposition is immutable'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER enrolled_failed_original_disposition_immutable BEFORE UPDATE OR DELETE ON public.capacity_enrolled_failed_original_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.immutable_enrolled_failed_original_disposition();
-- +goose StatementBegin
CREATE FUNCTION public.guard_enrolled_failed_original_grant_pointer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d public.capacity_enrolled_failed_original_dispositions;
BEGIN
 IF OLD.enrolled_failed_disposition_id IS NOT NULL THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'failed disposed original grant is immutable'; END IF;
 ELSIF NEW.enrolled_failed_disposition_id IS NOT NULL THEN
  IF OLD.original_disposition_id IS NOT NULL OR NEW.original_disposition_id IS NOT NULL
  OR (to_jsonb(NEW)-'enrolled_failed_disposition_id') IS DISTINCT FROM (to_jsonb(OLD)-'enrolled_failed_disposition_id')
  THEN RAISE EXCEPTION 'failed disposition cannot rewrite accepted original'; END IF;
  SELECT * INTO STRICT d FROM public.capacity_enrolled_failed_original_dispositions WHERE id=NEW.enrolled_failed_disposition_id AND grant_id=OLD.id;
  IF d.original_grant_sha256<>encode(sha256(convert_to(OLD.grant_record::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'failed disposition original grant digest changed'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER enrolled_failed_original_grant_pointer BEFORE UPDATE ON public.capacity_mutation_grants
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_grant_pointer();

-- +goose StatementBegin
CREATE FUNCTION public.check_enrolled_failed_original_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE d public.capacity_enrolled_failed_original_dispositions;
BEGIN
 IF old_row.enrolled_failed_disposition_id IS NOT NULL OR old_row.state='enrolled_failed_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'failed disposed original dispatch is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'unknown' OR new_row.state<>'enrolled_failed_disposed' OR new_row.enrolled_failed_disposition_id IS NULL
 OR old_row.started_at IS NULL OR old_row.returned_at IS NULL OR old_row.finalization_ack_at IS NOT NULL
 OR old_row.lease_expires_at IS NULL OR old_row.lease_expires_at>=clock_timestamp()
 OR new_row.finalization_ack_at IS NOT NULL
 OR (to_jsonb(new_row)-ARRAY['state','updated_at','enrolled_failed_disposition_id'])
    IS DISTINCT FROM (to_jsonb(old_row)-ARRAY['state','updated_at','enrolled_failed_disposition_id'])
 THEN RAISE EXCEPTION 'failed disposition requires unchanged expired unknown actual return and NULL original ACK'; END IF;
 SELECT * INTO STRICT d FROM public.capacity_enrolled_failed_original_dispositions WHERE id=new_row.enrolled_failed_disposition_id AND job_id=old_row.id;
 -- Deferred complete links make a committed unlinked ledger impossible;
 -- immutability makes a prior linked terminal impossible to reopen. Therefore
 -- the first unknown->enrolled_failed_disposed transition necessarily shares this commit,
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
    IF OLD.state='enrolled_failed_disposed' OR NEW.state='enrolled_failed_disposed'
       OR OLD.enrolled_failed_disposition_id IS NOT NULL OR NEW.enrolled_failed_disposition_id IS NOT NULL THEN
        RETURN public.check_enrolled_failed_original_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='native_denied_disposed' OR NEW.state='native_denied_disposed'
       OR OLD.native_denied_disposition_id IS NOT NULL OR NEW.native_denied_disposition_id IS NOT NULL THEN
        RETURN public.check_native_denied_dispatch_transition(OLD,NEW);
    END IF;
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
CREATE FUNCTION public.guard_enrolled_failed_original_dispatch_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='enrolled_failed_disposed' OR NEW.enrolled_failed_disposition_id IS NOT NULL
 THEN RAISE EXCEPTION 'failed disposition requires retained original unknown job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER enrolled_failed_original_dispatch_insert BEFORE INSERT ON public.capacity_dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_dispatch_insert();
-- +goose StatementBegin
CREATE FUNCTION public.guard_enrolled_failed_original_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD AND EXISTS(SELECT 1 FROM public.capacity_enrolled_failed_original_dispositions WHERE run_id=OLD.id)
 THEN RAISE EXCEPTION 'failed disposed original workflow history is immutable'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER enrolled_failed_original_workflow_immutable BEFORE UPDATE ON public.workflow_runs
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_workflow();

-- Ledger first, then both projections and the intent CAS in the SAME commit.
-- +goose StatementBegin
CREATE FUNCTION public.require_enrolled_failed_original_disposition_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; j public.capacity_dispatch_jobs; i jsonb;
BEGIN
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT intent INTO STRICT i FROM public.capacity_intents
 WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension;
 IF g.enrolled_failed_disposition_id IS DISTINCT FROM NEW.id OR g.original_disposition_id IS NOT NULL OR g.failed_original_disposition_id IS NOT NULL OR g.native_denied_disposition_id IS NOT NULL
 OR j.enrolled_failed_disposition_id IS DISTINCT FROM NEW.id OR j.state<>'enrolled_failed_disposed' OR j.finalization_ack_at IS NOT NULL
 OR (i->>'generation')::bigint IS DISTINCT FROM NEW.closed_generation
 OR (i->>'fencing_token')::bigint IS DISTINCT FROM NEW.closed_fencing_token
 OR i->>'phase' IS DISTINCT FROM 'reconciled_failed_floor'
 OR i#>'{decision,execution_permitted}' IS DISTINCT FROM 'false'::jsonb
 OR i->'floor_degraded' IS DISTINCT FROM 'true'::jsonb
 OR i->'recovery_only' IS DISTINCT FROM 'false'::jsonb
 OR coalesce(i->>'lease_owner','')<>'' OR coalesce(i->>'lease_executor_id','')<>'' OR i->>'lease_expires_at' IS NOT NULL
 OR NOT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments e WHERE e.preregistration_id=NEW.preregistration_id AND e.enrollment_sha256=NEW.original_enrollment_sha256 AND encode(sha256(e.registration_wire),'hex')=NEW.original_registration_sha256 AND encode(sha256(e.receipt_wire),'hex')=NEW.original_receipt_sha256)
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
CREATE CONSTRAINT TRIGGER enrolled_failed_original_disposition_complete_links AFTER INSERT ON public.capacity_enrolled_failed_original_dispositions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_enrolled_failed_original_disposition_links();

-- A late callback cannot enroll or adopt this expired original after the
-- accounting closure. A distinct next grant/preregistration remains unrelated.
-- +goose StatementBegin
CREATE FUNCTION public.guard_enrolled_failed_original_late_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
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
 IF g.enrolled_failed_disposition_id IS NOT NULL
 OR EXISTS(SELECT 1 FROM public.capacity_enrolled_failed_original_dispositions WHERE grant_id=target)
 THEN RAISE EXCEPTION 'failed disposed original cannot acquire late ownership'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER enrolled_failed_original_late_enrollment BEFORE INSERT ON public.capacity_vm_original_enrollments
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_late_ownership();
CREATE TRIGGER enrolled_failed_original_late_installation BEFORE INSERT ON public.capacity_guest_original_installations
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_late_ownership();
CREATE TRIGGER enrolled_failed_original_late_factory BEFORE INSERT ON public.capacity_factory_original_grant_bindings
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_late_ownership();
CREATE TRIGGER enrolled_failed_original_late_retirement BEFORE INSERT ON public.capacity_vm_retirement_intents
 FOR EACH ROW EXECUTE FUNCTION public.guard_enrolled_failed_original_late_ownership();

DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled') AND original_disposition_id IS NULL AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL AND enrolled_failed_disposition_id IS NULL;
-- Existing dispatch active-scope/claim indexes exclude enrolled_failed_disposed. Their
-- predicates and the original ACK restriction are intentionally untouched.

-- +goose Down
-- This terminal is a permanent no-replay boundary, including its migration.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'failed original Guest dispositions require retained forward-only schema'; END; $$;
-- +goose StatementEnd
