-- +goose Up
-- Extend only new INSERT admission. Existing H rows, triggers, original wires,
-- pointer foreign keys, ACKs, leases and historical migration73 stay unchanged.
-- The existing1657 observer supplies native absence only, never enrollment.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_failed_original_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; p public.capacity_vm_provisioning_preregistrations;
 w public.capacity_guest_original_create_witnesses; j public.capacity_dispatch_jobs; r public.workflow_runs;
 current_intent jsonb; e jsonb; o jsonb; native_key text; expected_aux jsonb; observed_aux jsonb;
 witnessed_unenrolled_aws boolean; provider text; native_read jsonb; body bytea; previous_return timestamptz; total bigint=0; server_seen boolean=false; aux_observation jsonb; projected jsonb; trail_row jsonb; trail_event jsonb; trail_matches integer; legacy_aws_unknown_aux boolean;
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
 witnessed_unenrolled_aws=coalesce(g.grant_record->>'event_provider'='aws'
  AND g.grant_record#>>'{binding,original_provider_source_commit}'='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
  AND g.grant_record#>>'{settlement,original_provider_create_return,provider}'='aws'
  AND g.grant_record#>>'{settlement,original_provider_create_return,adapter_source_commit}'='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
  AND g.grant_record#>>'{settlement,original_provider_create_return,schema}'='aws_original_run_instances_return_v1'
  AND g.grant_record#>'{settlement,original_provider_create_return,response_status}'='200'::jsonb
  AND(g.grant_record#>'{settlement,auxiliary_inventory_complete}' IS NULL OR g.grant_record#>'{settlement,auxiliary_inventory_complete}'='false'::jsonb)
  AND(g.grant_record#>'{settlement,auxiliary_resources}' IS NULL OR g.grant_record#>'{settlement,auxiliary_resources}'='[]'::jsonb),false);
 provider=CASE WHEN witnessed_unenrolled_aws THEN 'aws' ELSE 'hetzner' END;
 IF g.original_disposition_id IS NOT NULL OR g.failed_original_disposition_id IS NOT NULL
 OR EXISTS(SELECT 1 FROM public.capacity_original_create_dispositions WHERE grant_id=g.id)
 OR g.state<>'settled' OR g.grant_record#>>'{grant,state}' IS DISTINCT FROM 'settled'
 OR g.grant_record#>>'{settlement,outcome}' IS DISTINCT FROM 'accepted'
 OR g.grant_record#>'{settlement,transport_completed}' IS DISTINCT FROM 'true'::jsonb
 OR (NOT witnessed_unenrolled_aws AND (
    g.grant_record#>'{settlement,auxiliary_inventory_complete}' IS DISTINCT FROM 'true'::jsonb
 OR jsonb_typeof(g.grant_record#>'{settlement,auxiliary_resources}') IS DISTINCT FROM 'array'
 OR jsonb_array_length(g.grant_record#>'{settlement,auxiliary_resources}') NOT BETWEEN 1 AND 16
 OR g.grant_record->>'event_provider' IS DISTINCT FROM 'hetzner'
 OR g.grant_record#>>'{settlement,original_provider_create_return,provider}' IS DISTINCT FROM 'hetzner'
 OR g.grant_record#>>'{settlement,original_provider_create_return,schema}' IS DISTINCT FROM 'hetzner_original_create_return_v1'
 OR g.grant_record#>'{settlement,original_provider_create_return,response_status}' IS DISTINCT FROM '201'::jsonb))
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
 OR o->>'provider' IS DISTINCT FROM provider
 OR (NOT witnessed_unenrolled_aws AND o->>'inventory_basis' IS DISTINCT FROM 'original_accepted_auxiliary_inventory_v1')
 OR (witnessed_unenrolled_aws AND (o->>'inventory_basis' IS DISTINCT FROM 'aws_original_enrolled_failed_create_owned_auxiliary_absence_v1' OR o->>'adapter_source_commit' IS DISTINCT FROM '2f2273391775ff0c8c1c65db6708a59bcc747018'))
 OR o->>'profile' IS DISTINCT FROM g.profile_name OR (o->>'slot')::integer IS DISTINCT FROM g.slot
 OR o->>'grant_id' IS DISTINCT FROM g.id::text OR o->>'attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR o->>'request_sha256' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR o->>'resource_id' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_id}'
 OR o->>'resource_created_at' IS DISTINCT FROM g.grant_record#>>'{settlement,resource_created_at}'
 OR o->>'original_adapter_source_commit' IS DISTINCT FROM g.grant_record#>>'{binding,original_provider_source_commit}'
 OR (o->>'resource_state' IS DISTINCT FROM 'absent' AND (NOT witnessed_unenrolled_aws OR o->>'resource_state' IS DISTINCT FROM 'terminated'))
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
 IF NOT witnessed_unenrolled_aws AND (expected_aux IS NULL OR observed_aux IS DISTINCT FROM expected_aux)
 THEN RAISE EXCEPTION 'failed original disposition must cover exact complete accepted auxiliary inventory'; END IF;
 IF witnessed_unenrolled_aws THEN
  legacy_aws_unknown_aux=true;
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
  IF coalesce(w.original_record#>>'{provider_native_identity,image_id}','') !~ '^ami-[a-f0-9]{8,17}$'
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(o->'native_reads') rr WHERE rr->>'operation'='DescribeImages' AND rr->>'resource_id' IS DISTINCT FROM w.original_record#>>'{provider_native_identity,image_id}')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(o->'native_reads') rr WHERE rr->>'operation'='GetCallerIdentity' AND rr->>'resource_id' IS DISTINCT FROM w.original_record#>>'{provider_native_identity,account_id}')
  THEN RAISE EXCEPTION 'witnessed unenrolled AWS native AMI must match immutable create witness'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- H fragment for the SINGLE new migration82; do not run independently.
-- No row is rewritten or retrofilled; all SQL1..81 bytes remain unchanged.
-- +goose StatementBegin
DO $$
DECLARE target text; matches integer;
BEGIN
 SELECT count(*), min(conname) INTO matches,target FROM pg_constraint
 WHERE conrelid='public.capacity_guest_failed_installed_disposals'::regclass
 AND contype='c' AND pg_get_constraintdef(oid) LIKE '%original_record - ARRAY[%'
 AND pg_get_constraintdef(oid) LIKE '%terminal_issuer%';
 IF matches<>1 THEN RAISE EXCEPTION 'exact original failed-installed closed-key constraint required'; END IF;
 EXECUTE format('ALTER TABLE public.capacity_guest_failed_installed_disposals DROP CONSTRAINT %I',target);
END $$;
-- +goose StatementEnd
ALTER TABLE public.capacity_guest_failed_installed_disposals
 ADD CONSTRAINT failed_installed_disposal_closed_keys_v2 CHECK ((original_record - ARRAY['schema','id','stage','namespace','environment','domain','dimension','preregistration_id','issuer','actual_core_source','original_intent','original_run','last_failed_run','installation_sha256','enrollment_sha256','blocked_guest_source','blocked_profile_sha256','useful_capacity_before','business_effects_preserved','retirement_mode','admission_sha256','claimed_intent','retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer','replacement_mode','original_failed_issuer_core_source','replacement_core_source'])='{}'::jsonb),
 ADD CONSTRAINT failed_installed_core_replacement_v1 CHECK ((
 CASE WHEN NOT(original_record ?| ARRAY['replacement_mode','original_failed_issuer_core_source','replacement_core_source']) THEN true ELSE
 original_record ?& ARRAY['replacement_mode','original_failed_issuer_core_source','replacement_core_source'] AND
 original_record->>'replacement_mode'='original_canary_core_bound_v1' AND
 original_record->>'retirement_mode'='original_production_v2' AND
 original_record->>'original_failed_issuer_core_source' ~ '^[0-9a-f]{40}$' AND
 original_record->>'replacement_core_source' ~ '^[0-9a-f]{40}$' AND
 original_record->>'replacement_core_source'=original_record->>'actual_core_source' AND
 original_record->>'replacement_core_source'<>original_record->>'original_failed_issuer_core_source'
 END) IS TRUE);
-- Down intentionally retains this append-only admission format, like prior
-- Guest lifecycle migrations; application rollback cannot erase provenance.

-- +goose Down
-- Never make retained modern AWS terminal history unsupported by a downgrade.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_failed_original_dispositions WHERE disposition_record#>>'{observation,provider}'='aws')
 THEN RAISE EXCEPTION 'retain witnessed AWS terminal history; downgrade refused'; END IF;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_failed_original_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
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
