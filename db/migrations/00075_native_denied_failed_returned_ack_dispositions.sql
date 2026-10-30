-- +goose Up
-- Preserve the complete migration74 ledger and V1 unknown/NULL-ACK meaning.
-- A failed workflow can have an observed original return ACK while its provider
-- settlement remains uncertain. V2 closes that exact returned/ACK lane without
-- changing the ACK, original run, settlement, native identities or evidence.
-- Anonymous predecessor checks are identified by table AND their exact parsed
-- expression, with cardinality one, rather than a guessed generated name.
-- +goose StatementBegin
DO $$
DECLARE row record; target_oid oid; expected text; names text[];
BEGIN
 CREATE TEMP TABLE native_denied75_constraint_probe (
  disposition_record jsonb,finalization_ack_at timestamptz,state text,returned_at timestamptz,
  CONSTRAINT probe75_schema CHECK(disposition_record->>'schema' IS NOT DISTINCT FROM 'original_native_authorization_denied_terminal_disposition_v1'),
  CONSTRAINT probe75_unknown_ack CHECK(disposition_record->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb),
  CONSTRAINT probe75_dispatch_ack CHECK(finalization_ack_at IS NULL OR(state='returned' AND returned_at IS NOT NULL))
 ) ON COMMIT DROP;
 FOR row IN SELECT * FROM (VALUES
  ('public.capacity_native_denied_dispositions','probe75_schema'),
  ('public.capacity_native_denied_dispositions','probe75_unknown_ack'),
  ('public.capacity_dispatch_jobs','probe75_dispatch_ack')
 ) AS checks(table_name,probe_name) LOOP
  target_oid=to_regclass(row.table_name);
  SELECT pg_get_expr(conbin,conrelid) INTO STRICT expected FROM pg_constraint
   WHERE conrelid='pg_temp.native_denied75_constraint_probe'::regclass AND conname=row.probe_name AND contype='c';
  SELECT array_agg(conname::text ORDER BY conname) INTO names FROM pg_constraint
   WHERE conrelid=target_oid AND contype='c' AND convalidated AND pg_get_expr(conbin,conrelid)=expected;
  IF coalesce(cardinality(names),0)<>1 THEN RAISE EXCEPTION 'migration75 exact predecessor CHECK must occur once: % %',row.table_name,row.probe_name;END IF;
  EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',target_oid::regclass,names[1]);
 END LOOP;
 DROP TABLE pg_temp.native_denied75_constraint_probe;
END;$$;
-- +goose StatementEnd
ALTER TABLE public.capacity_native_denied_dispositions ADD CONSTRAINT capacity_native_denied_original_ack_v2_check CHECK(
 CASE disposition_record->>'schema'
 WHEN 'original_native_authorization_denied_terminal_disposition_v1' THEN
  disposition_record->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb
  AND NOT(disposition_record ?| ARRAY['original_dispatch_state','original_finalization_ack_at','original_failed_workflow_ACK_preserved'])
 WHEN 'original_native_authorization_denied_failed_returned_ack_terminal_disposition_v2' THEN
  disposition_record->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'false'::jsonb
  AND disposition_record->>'original_dispatch_state' IS NOT DISTINCT FROM 'returned'
  AND disposition_record->'original_failed_workflow_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb
  AND jsonb_typeof(disposition_record->'original_finalization_ack_at') IS NOT DISTINCT FROM 'string'
  AND (disposition_record->>'original_finalization_ack_at')::timestamptz IS NOT NULL
 ELSE false END IS TRUE);
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_original_ack_v2_check CHECK(
 finalization_ack_at IS NULL OR(state IN('returned','native_denied_disposed') AND returned_at IS NOT NULL));
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_native_denied_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_native_denied_check CHECK(
 (state='native_denied_disposed' AND native_denied_disposition_id IS NOT NULL AND failed_original_disposition_id IS NULL)
 OR(state<>'native_denied_disposed' AND native_denied_disposition_id IS NULL));

-- +goose StatementBegin
CREATE FUNCTION public.native_denied_original_ack_matches(d jsonb,original_state text,ack timestamptz,returned timestamptz,lease_end timestamptz,return_status text)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT coalesce(CASE d->>'schema'
 WHEN 'original_native_authorization_denied_terminal_disposition_v1' THEN
  original_state='unknown' AND ack IS NULL
  AND d->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb
  AND NOT(d ?| ARRAY['original_dispatch_state','original_finalization_ack_at','original_failed_workflow_ACK_preserved'])
 WHEN 'original_native_authorization_denied_failed_returned_ack_terminal_disposition_v2' THEN
  original_state='returned' AND ack IS NOT NULL AND returned IS NOT NULL AND lease_end IS NOT NULL
  AND ack>=returned AND ack<lease_end AND return_status='failed'
  AND d->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'false'::jsonb
  AND d->>'original_dispatch_state' IS NOT DISTINCT FROM 'returned'
  AND d->'original_failed_workflow_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb
  AND jsonb_typeof(d->'original_finalization_ack_at') IS NOT DISTINCT FROM 'string'
  AND (d->>'original_finalization_ack_at')::timestamptz IS NOT DISTINCT FROM ack
 ELSE false END,false);
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_native_denied_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; p public.capacity_vm_provisioning_preregistrations;
 j public.capacity_dispatch_jobs; r public.workflow_runs; intent jsonb; e jsonb; o jsonb; q jsonb;
 s jsonb; k text; rr jsonb; body bytea; page jsonb; event jsonb; item jsonb; seen integer=0; total integer=0; idx integer=0; n integer; xdoc xml; previous_return timestamptz; instance_phase boolean=false; trail_pages integer=0; instance_pages integer=0; next_ec2 text; next_op text; trail_tokens text[]=ARRAY[]::text[]; instance_tokens text[]=ARRAY[]::text[];
BEGIN
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[g.namespace,g.environment,g.domain,g.dimension])::text,0));
 k='["capacity-native-slot",'||to_json(g.integration_instance_id::text)::text||','||to_json(g.scope_checksum)::text||','||to_json(g.profile_name)::text||','||g.slot::text||']';
 PERFORM pg_advisory_xact_lock(hashtextextended(k,0));
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id FOR SHARE;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT r FROM public.workflow_runs WHERE id=NEW.run_id FOR UPDATE;
 SELECT i.intent INTO STRICT intent FROM public.capacity_intents i WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension FOR UPDATE;
 e=j.envelope::jsonb;s=g.grant_record->'settlement';o=NEW.disposition_record->'observation';q=o->'request';
 IF g.original_disposition_id IS NOT NULL OR g.failed_original_disposition_id IS NOT NULL OR g.native_denied_disposition_id IS NOT NULL
 OR g.state<>'settled' OR g.grant_record#>>'{grant,state}' IS DISTINCT FROM 'settled'
 OR g.grant_record->>'event_provider' IS DISTINCT FROM 'aws'
 OR g.grant_record#>>'{binding,original_provider_source_commit}' IS DISTINCT FROM 'd6af60729dee334c2be9bee45a0ba2dd02b7ec51'
 OR g.grant_record#>>'{grant,capability}' IS DISTINCT FROM g.grant_record#>>'{binding,ensure_capability}'
 OR coalesce(g.grant_record#>>'{grant,compensation_of}','')<>''
 OR coalesce(s->>'provider_error_code','')<>'' OR coalesce((s->>'provider_status_code')::integer,0)<>0 OR coalesce(g.grant_record#>>'{grant,expected_resource_id}','')<>'' OR coalesce(g.grant_record#>>'{grant,expected_resource_created_at}','')<>''
 OR s->>'outcome' IS DISTINCT FROM 'uncertain' OR s->'transport_completed' IS DISTINCT FROM 'true'::jsonb
 OR coalesce(s->>'resource_id','')<>'' OR coalesce(s->>'resource_created_at','')<>'' OR coalesce(s->>'action_id','')<>''
 OR coalesce(s->'next_action_ids','[]'::jsonb)<>'[]'::jsonb OR coalesce(s->'auxiliary_resources','[]'::jsonb)<>'[]'::jsonb
 OR coalesce(s->'auxiliary_inventory_complete','false'::jsonb)<>'false'::jsonb
 OR coalesce(s->'original_provider_create_return','null'::jsonb)<>'null'::jsonb
 OR coalesce(s->'original_provider_destroy_return','null'::jsonb)<>'null'::jsonb
 OR s->>'grant_id' IS DISTINCT FROM g.id::text OR s->>'attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR s->>'request_sha256' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR p.create_grant_id<>g.id OR p.original_deadline>=clock_timestamp() OR g.expires_at>=clock_timestamp()
 OR p.original_wire IS NULL OR p.preregistration_record IS DISTINCT FROM convert_from(p.original_wire,'UTF8')::jsonb
 OR p.preregistration_record->>'original_create_request_sha256' IS DISTINCT FROM s->>'request_sha256'
 OR p.preregistration_record->>'policy_id' IS DISTINCT FROM g.grant_record->>'policy_id'
 OR p.preregistration_record->>'policy_checksum' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR p.preregistration_record->>'workflow_id' IS DISTINCT FROM g.grant_record->>'workflow_id'
 OR NEW.original_grant_sha256<>encode(sha256(convert_to(g.grant_record::text,'UTF8')),'hex')
 OR NEW.original_preregistration_sha256<>encode(sha256(p.original_wire),'hex')
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=g.id)
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=g.id::text)
 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension AND resource_id<>'')
 THEN RAISE EXCEPTION 'native denied disposition requires exact expired uncertain empty original without witness';END IF;
 IF NOT public.native_denied_original_ack_matches(NEW.disposition_record,j.state,j.finalization_ack_at,j.returned_at,j.lease_expires_at,j.return_status)
 OR j.native_denied_disposition_id IS NOT NULL OR j.failed_original_disposition_id IS NOT NULL
 OR j.protocol<>'capacity_dispatch_prestart_v1' OR j.run_id<>r.id OR j.started_at IS NULL OR j.returned_at IS NULL
 OR j.lease_expires_at IS NULL OR j.lease_expires_at>=clock_timestamp()
 OR (j.realm,j.environment,j.domain,j.dimension) IS DISTINCT FROM (g.namespace,g.environment,g.domain,g.dimension)
 OR j.envelope_sha256<>encode(sha256(convert_to(j.envelope,'UTF8')),'hex')
 OR e#>>'{policy,id}' IS DISTINCT FROM g.grant_record->>'policy_id' OR e#>>'{policy,checksum}' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR e#>>'{workflow,id}' IS DISTINCT FROM g.grant_record->>'workflow_id'
 OR (r.workflow_id IS NOT NULL AND r.workflow_id::text IS DISTINCT FROM e#>>'{workflow,id}')
 OR r.workflow_namespace IS DISTINCT FROM e#>>'{workflow,namespace}' OR r.workflow_name IS DISTINCT FROM e#>>'{workflow,name}' OR r.workflow_version::text IS DISTINCT FROM e#>>'{workflow,version}'
 OR r.inputs IS DISTINCT FROM e->'inputs' OR r.metadata IS DISTINCT FROM e->'metadata'
 OR r.status<>'failed' OR r.started_at IS DISTINCT FROM j.started_at OR r.finished_at IS DISTINCT FROM j.returned_at
 OR r.result->>'status' IS DISTINCT FROM 'failed' OR r.result#>>'{workflow,id}' IS DISTINCT FROM e#>>'{workflow,id}'
 OR r.result#>>'{workflow,namespace}' IS DISTINCT FROM e#>>'{workflow,namespace}' OR r.result#>>'{workflow,name}' IS DISTINCT FROM e#>>'{workflow,name}' OR r.result#>>'{workflow,version}' IS DISTINCT FROM e#>>'{workflow,version}'
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(r.result->'steps') v WHERE v->>'id'=p.preregistration_record->>'original_workflow_step_id' AND v->>'status'='failed' AND v#>>'{metadata,original_guest_refusal_predicate}'='original-guest-step-25')
 OR NEW.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex') OR NEW.original_run_sha256<>encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex')
 OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE (workflow_id=(g.grant_record->>'workflow_id')::uuid OR(workflow_id IS NULL AND workflow_namespace=r.workflow_namespace AND workflow_name=r.workflow_name AND workflow_version=r.workflow_version)) AND status IN('pending','running'))
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE id<>j.id AND realm=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension AND(state IN('queued','started','unknown') OR(state='returned' AND finalization_ack_at IS NULL)))
 THEN RAISE EXCEPTION 'native denied disposition requires exact failed Create run and closed original ACK lane';END IF;
 IF coalesce(NEW.disposition_record->>'issuer','') !~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR intent#>>'{decision,reason}' IS DISTINCT FROM 'protected_floor_recovery' OR (intent#>>'{baseline_snapshot,units}')::integer IS DISTINCT FROM 0 OR (intent#>>'{assessment,snapshot,units}')::integer IS DISTINCT FROM 0
 OR intent->>'policy_id' IS DISTINCT FROM g.grant_record->>'policy_id' OR intent->>'policy_checksum' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR (intent->>'generation')::bigint IS DISTINCT FROM g.generation
 OR NEW.closed_generation IS DISTINCT FROM (intent->>'generation')::bigint OR NEW.closed_fencing_token IS DISTINCT FROM (intent->>'fencing_token')::bigint+1
 OR (intent->>'lease_expires_at')::timestamptz>=clock_timestamp() OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 THEN RAISE EXCEPTION 'native denied disposition requires current expired intent and next fence';END IF;
 IF o->>'schema' IS DISTINCT FROM 'aws_original_authorization_denied_observation_v1' OR o->>'decision' IS DISTINCT FROM 'authorization_denied'
 OR coalesce(o->>'adapter_source_commit','') !~ '^[0-9a-f]{40}$'
 OR coalesce(o->>'event_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR coalesce(o->>'request_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR NOT EXISTS(SELECT 1 FROM public.manifests m,jsonb_array_elements(m.spec->'profiles') profile WHERE m.id=(g.grant_record->>'policy_id')::uuid AND profile->>'name'=g.profile_name AND profile->>'provider'='aws' AND profile->>'region'=o->>'region')
 OR o->'historical_profile_request_matched' IS DISTINCT FROM 'true'::jsonb OR o->'same_token_instances_empty' IS DISTINCT FROM 'true'::jsonb
 OR o->'original_HTTP_response_available' IS DISTINCT FROM 'false'::jsonb OR o->'native_mutations' IS DISTINCT FROM '0'::jsonb OR o->'Guest_admission_or_business_or_savings_authority' IS DISTINCT FROM 'false'::jsonb
 OR q->>'schema' IS DISTINCT FROM 'aws_original_authorization_denied_read_request_v1' OR q->>'grant_id' IS DISTINCT FROM g.id::text OR q->>'attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR q->>'request_sha256' IS DISTINCT FROM s->>'request_sha256' OR q->>'scope_checksum' IS DISTINCT FROM g.scope_checksum OR q->>'profile' IS DISTINCT FROM g.profile_name OR (q->>'slot')::integer IS DISTINCT FROM g.slot
 OR q->>'original_adapter_source_commit' IS DISTINCT FROM g.grant_record#>>'{binding,original_provider_source_commit}'
 OR (q->>'grant_created_at')::timestamptz IS DISTINCT FROM (g.grant_record->>'created_at')::timestamptz
 OR (q->>'settlement_observed_at')::timestamptz IS DISTINCT FROM (s->>'observed_at')::timestamptz
 OR (q->>'original_deadline')::timestamptz IS DISTINCT FROM p.original_deadline
 OR o->>'client_token' IS DISTINCT FROM encode(sha256(convert_to(g.id::text||':'||(s->>'request_sha256'),'UTF8')),'hex')
 OR (q->>'grant_created_at')::timestamptz>(q->>'settlement_observed_at')::timestamptz OR (q->>'settlement_observed_at')::timestamptz>=(q->>'original_deadline')::timestamptz
 OR jsonb_typeof(o->'observation_started_at') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'observed_at') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'denied_at') IS DISTINCT FROM 'string'
 OR (o->>'observation_started_at')::timestamptz IS NULL OR (o->>'observed_at')::timestamptz IS NULL OR (o->>'denied_at')::timestamptz IS NULL
 OR (o->>'observed_at')::timestamptz-(o->>'observation_started_at')::timestamptz>interval '60 seconds'
 OR (o->>'observation_started_at')::timestamptz>(o->>'observed_at')::timestamptz OR (o->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR (o->>'observed_at')::timestamptz<clock_timestamp()-interval '30 seconds'
 OR coalesce(o->>'account_id','') !~ '^[0-9]{12}$' OR o->>'principal_arn' IS DISTINCT FROM 'arn:aws:iam::'||(o->>'account_id')||':user/scopedcapacity-provider-aws-20261021'
 OR (o->>'denied_at')::timestamptz<date_trunc('second',(q->>'grant_created_at')::timestamptz)
 OR (o->>'denied_at')::timestamptz>=date_trunc('second',(q->>'settlement_observed_at')::timestamptz)+interval '1 second'
 OR jsonb_typeof(o->'native_reads') IS DISTINCT FROM 'array' OR jsonb_array_length(o->'native_reads') NOT BETWEEN 3 AND 33
 THEN RAISE EXCEPTION 'native denied disposition requires typed read-only decision evidence';END IF;
 n=jsonb_array_length(o->'native_reads');
 FOR rr IN SELECT value FROM jsonb_array_elements(o->'native_reads') LOOP
  IF jsonb_typeof(rr->'called_at') IS DISTINCT FROM 'string' OR jsonb_typeof(rr->'returned_at') IS DISTINCT FROM 'string'
   OR (rr->>'called_at')::timestamptz IS NULL OR (rr->>'returned_at')::timestamptz IS NULL
   OR (rr->>'called_at')::timestamptz<(o->>'observation_started_at')::timestamptz OR (rr->>'returned_at')::timestamptz<(rr->>'called_at')::timestamptz OR (rr->>'returned_at')::timestamptz>(o->>'observed_at')::timestamptz OR (previous_return IS NOT NULL AND (rr->>'called_at')::timestamptz<previous_return) THEN RAISE EXCEPTION 'native denied HTTP time ordering';END IF;
  previous_return=(rr->>'returned_at')::timestamptz;
  IF jsonb_typeof(rr->'response_body_base64') IS DISTINCT FROM 'string'
   OR jsonb_typeof(rr->'response_bytes') IS DISTINCT FROM 'number'
   OR jsonb_typeof(rr->'response_sha256') IS DISTINCT FROM 'string'
   OR coalesce(rr->>'response_sha256','') !~ '^[0-9a-f]{64}$'
  THEN RAISE EXCEPTION 'native denied evidence requires typed body and digest';END IF;
  body=decode(rr->>'response_body_base64','base64');total=total+octet_length(body);
  IF body IS NULL OR total IS NULL OR rr->'status' IS DISTINCT FROM '200'::jsonb OR octet_length(body) NOT BETWEEN 2 AND 65536 OR total>1048576
   OR (rr->>'response_bytes')::integer IS DISTINCT FROM octet_length(body) OR rr->>'response_sha256' IS DISTINCT FROM encode(sha256(body),'hex')
  THEN RAISE EXCEPTION 'native denied evidence requires complete original bounded HTTP bodies';END IF;
  IF idx=0 THEN
   IF rr->>'response_representation' IS DISTINCT FROM 'raw_http_body_v1' OR rr->>'operation' IS DISTINCT FROM 'GetCallerIdentity' OR rr->>'resource_kind' IS DISTINCT FROM 'aws_account' OR rr->>'resource_id' IS DISTINCT FROM o->>'account_id' THEN RAISE EXCEPTION 'native denied STS evidence missing';END IF;
   xdoc=xmlparse(document convert_from(body,'UTF8'));
   IF cardinality(xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Account/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))<>1 OR (xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Account/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))[1]::text IS DISTINCT FROM o->>'account_id'
    OR cardinality(xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Arn/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))<>1 OR (xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Arn/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))[1]::text IS DISTINCT FROM o->>'principal_arn' THEN RAISE EXCEPTION 'native denied STS principal/account mismatch';END IF;
  ELSIF rr->>'operation'='DescribeInstances' THEN
   instance_phase=true;instance_pages=instance_pages+1;IF trail_pages=0 OR instance_pages>16 THEN RAISE EXCEPTION 'native denied EC2 page sequence';END IF;
   IF rr->>'response_representation' IS DISTINCT FROM 'raw_http_body_v1' OR rr->>'operation' IS DISTINCT FROM 'DescribeInstances' OR rr->>'resource_kind' IS DISTINCT FROM 'aws_ec2_instance' OR rr->>'resource_id' IS DISTINCT FROM o->>'client_token' THEN RAISE EXCEPTION 'native denied token read missing';END IF;
   xdoc=xmlparse(document convert_from(body,'UTF8'));
   IF cardinality(xpath('/e:DescribeInstancesResponse/e:reservationSet',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']]))<>1 OR xpath_exists('/e:DescribeInstancesResponse/e:reservationSet/*',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']])  THEN RAISE EXCEPTION 'native denied token instances not explicitly empty complete';END IF;
   next_ec2=coalesce((xpath('/e:DescribeInstancesResponse/e:nextToken/text()',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']]))[1]::text,'');
   IF cardinality(xpath('/e:DescribeInstancesResponse/e:nextToken',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']]))>1 OR length(next_ec2)>4096 OR(next_ec2<>'' AND next_ec2=ANY(instance_tokens)) OR(next_ec2<>'') IS DISTINCT FROM(idx<n-1) THEN RAISE EXCEPTION 'native denied EC2 pagination incomplete';END IF;IF next_ec2<>'' THEN instance_tokens=array_append(instance_tokens,next_ec2);END IF;
  ELSE
   trail_pages=trail_pages+1;IF instance_phase OR trail_pages>16 THEN RAISE EXCEPTION 'native denied CloudTrail page sequence';END IF;
   IF rr->>'response_representation' IS DISTINCT FROM 'cloudtrail_lookup_events_userdata_omitted_projection_v1' OR rr->>'operation' IS DISTINCT FROM 'LookupEvents' OR rr->>'resource_kind' IS DISTINCT FROM 'aws_cloudtrail_event' OR rr->>'resource_id' IS DISTINCT FROM o->>'client_token' THEN RAISE EXCEPTION 'native denied CloudTrail evidence missing';END IF;
   page=convert_from(body,'UTF8')::jsonb;
   IF page->>'schema' IS DISTINCT FROM 'cloudtrail_lookup_events_userdata_omitted_projection_v1' OR page->'original_http_body_retained' IS DISTINCT FROM 'false'::jsonb OR page->'original_http_body_hashed' IS DISTINCT FROM 'false'::jsonb OR page->'original_eof_and_close' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(page->'user_data_fields_removed') IS DISTINCT FROM 'number' OR (page->>'user_data_fields_removed')::integer NOT BETWEEN 0 AND 50 THEN RAISE EXCEPTION 'native denied CloudTrail projection provenance missing';END IF;
   page=page->'response';
   IF jsonb_typeof(page->'Events') IS DISTINCT FROM 'array' OR jsonb_array_length(page->'Events')>50 OR(coalesce(page->>'NextToken','')<>'' AND (page->>'NextToken')=ANY(trail_tokens)) OR(coalesce(page->>'NextToken','')<>'') IS DISTINCT FROM (o->'native_reads'->(idx+1)->>'operation'='LookupEvents') THEN RAISE EXCEPTION 'native denied CloudTrail pagination incomplete';END IF;IF coalesce(page->>'NextToken','')<>'' THEN trail_tokens=array_append(trail_tokens,page->>'NextToken');END IF;
   FOR item IN SELECT value FROM jsonb_array_elements(page->'Events') LOOP
    event=(item->>'CloudTrailEvent')::jsonb; IF (event->'requestParameters')?'userData' THEN RAISE EXCEPTION 'private userdata cannot enter native denied ledger';END IF;
    IF event#>>'{requestParameters,clientToken}'=o->>'client_token' THEN
     seen=seen+1;
     IF event->>'eventSource' IS DISTINCT FROM 'ec2.amazonaws.com' OR event->>'eventName' IS DISTINCT FROM 'RunInstances' OR event->>'errorCode' IS DISTINCT FROM 'Client.UnauthorizedOperation'
      OR event->'responseElements' IS DISTINCT FROM 'null'::jsonb OR coalesce(event->'resources','null'::jsonb) NOT IN('null'::jsonb,'[]'::jsonb)
      OR event->>'eventID' IS DISTINCT FROM o->>'event_id' OR item->>'EventId' IS DISTINCT FROM o->>'event_id' OR event->>'requestID' IS DISTINCT FROM o->>'request_id'
      OR event->>'recipientAccountId' IS DISTINCT FROM o->>'account_id' OR event#>>'{userIdentity,accountId}' IS DISTINCT FROM o->>'account_id' OR event#>>'{userIdentity,arn}' IS DISTINCT FROM o->>'principal_arn'
      OR event->>'awsRegion' IS DISTINCT FROM o->>'region' OR (event->>'eventTime')::timestamptz IS DISTINCT FROM (o->>'denied_at')::timestamptz
     THEN RAISE EXCEPTION 'native denied CloudTrail event is foreign ambiguous or not denied';END IF;
    END IF;
   END LOOP;
  END IF;
  idx=idx+1;
 END LOOP;
 IF seen<>1 OR instance_pages=0 THEN RAISE EXCEPTION 'native denied requires exactly one original token event';END IF;
 RETURN NEW;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_native_denied_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs) RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE d public.capacity_native_denied_dispositions;
BEGIN
 IF old_row.native_denied_disposition_id IS NOT NULL OR old_row.state='native_denied_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'native denied dispatch immutable';END IF;RETURN new_row;
 END IF;
 IF new_row.state<>'native_denied_disposed' OR new_row.native_denied_disposition_id IS NULL
 OR old_row.started_at IS NULL OR old_row.returned_at IS NULL OR new_row.finalization_ack_at IS DISTINCT FROM old_row.finalization_ack_at
 OR old_row.lease_expires_at IS NULL OR old_row.lease_expires_at>=clock_timestamp()
 OR(to_jsonb(new_row)-ARRAY['state','updated_at','native_denied_disposition_id']) IS DISTINCT FROM(to_jsonb(old_row)-ARRAY['state','updated_at','native_denied_disposition_id'])
 THEN RAISE EXCEPTION 'native denied terminal requires unchanged expired actual return and original ACK';END IF;
 SELECT * INTO STRICT d FROM public.capacity_native_denied_dispositions WHERE id=new_row.native_denied_disposition_id AND job_id=old_row.id;
 IF NOT public.native_denied_original_ack_matches(d.disposition_record,old_row.state,old_row.finalization_ack_at,old_row.returned_at,old_row.lease_expires_at,old_row.return_status)
 OR d.run_id<>old_row.run_id OR d.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(old_row)::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'native denied dispatch snapshot changed';END IF;RETURN new_row;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_native_denied_complete_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants;j public.capacity_dispatch_jobs;i jsonb;
BEGIN
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT intent INTO STRICT i FROM public.capacity_intents WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension;
 IF g.native_denied_disposition_id IS DISTINCT FROM NEW.id OR j.native_denied_disposition_id IS DISTINCT FROM NEW.id OR j.state<>'native_denied_disposed'
 OR NOT public.native_denied_original_ack_matches(NEW.disposition_record,CASE WHEN NEW.disposition_record->>'schema'='original_native_authorization_denied_terminal_disposition_v1' THEN 'unknown' ELSE 'returned' END,j.finalization_ack_at,j.returned_at,j.lease_expires_at,j.return_status)
 OR i->>'phase' IS DISTINCT FROM 'reconciled_failed_floor' OR i->'floor_degraded' IS DISTINCT FROM 'true'::jsonb OR i#>'{decision,execution_permitted}' IS DISTINCT FROM 'false'::jsonb
 OR(i->>'fencing_token')::bigint IS DISTINCT FROM NEW.closed_fencing_token OR(i->>'generation')::bigint IS DISTINCT FROM NEW.closed_generation
 THEN RAISE EXCEPTION 'native denied disposition requires atomic complete links and failed floor fence';END IF;RETURN NEW;
END;$$;
-- +goose StatementEnd

-- +goose Down
-- V2 is admitted history and may never be relabelled as the V1 unknown lane.
-- +goose StatementBegin
DO $$BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_native_denied_dispositions WHERE disposition_record->>'schema' IS DISTINCT FROM 'original_native_authorization_denied_terminal_disposition_v1')
 THEN RAISE EXCEPTION 'returned-ACK native denial history cannot be removed';END IF;
END;$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_native_denied_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants; p public.capacity_vm_provisioning_preregistrations;
 j public.capacity_dispatch_jobs; r public.workflow_runs; intent jsonb; e jsonb; o jsonb; q jsonb;
 s jsonb; k text; rr jsonb; body bytea; page jsonb; event jsonb; item jsonb; seen integer=0; total integer=0; idx integer=0; n integer; xdoc xml; previous_return timestamptz; instance_phase boolean=false; trail_pages integer=0; instance_pages integer=0; next_ec2 text; next_op text; trail_tokens text[]=ARRAY[]::text[]; instance_tokens text[]=ARRAY[]::text[];
BEGIN
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[g.namespace,g.environment,g.domain,g.dimension])::text,0));
 k='["capacity-native-slot",'||to_json(g.integration_instance_id::text)::text||','||to_json(g.scope_checksum)::text||','||to_json(g.profile_name)::text||','||g.slot::text||']';
 PERFORM pg_advisory_xact_lock(hashtextextended(k,0));
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id FOR SHARE;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT r FROM public.workflow_runs WHERE id=NEW.run_id FOR UPDATE;
 SELECT i.intent INTO STRICT intent FROM public.capacity_intents i WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension FOR UPDATE;
 e=j.envelope::jsonb;s=g.grant_record->'settlement';o=NEW.disposition_record->'observation';q=o->'request';
 IF g.original_disposition_id IS NOT NULL OR g.failed_original_disposition_id IS NOT NULL OR g.native_denied_disposition_id IS NOT NULL
 OR g.state<>'settled' OR g.grant_record#>>'{grant,state}' IS DISTINCT FROM 'settled'
 OR g.grant_record->>'event_provider' IS DISTINCT FROM 'aws'
 OR g.grant_record#>>'{binding,original_provider_source_commit}' IS DISTINCT FROM 'd6af60729dee334c2be9bee45a0ba2dd02b7ec51'
 OR g.grant_record#>>'{grant,capability}' IS DISTINCT FROM g.grant_record#>>'{binding,ensure_capability}'
 OR coalesce(g.grant_record#>>'{grant,compensation_of}','')<>''
 OR coalesce(s->>'provider_error_code','')<>'' OR coalesce((s->>'provider_status_code')::integer,0)<>0 OR coalesce(g.grant_record#>>'{grant,expected_resource_id}','')<>'' OR coalesce(g.grant_record#>>'{grant,expected_resource_created_at}','')<>''
 OR s->>'outcome' IS DISTINCT FROM 'uncertain' OR s->'transport_completed' IS DISTINCT FROM 'true'::jsonb
 OR coalesce(s->>'resource_id','')<>'' OR coalesce(s->>'resource_created_at','')<>'' OR coalesce(s->>'action_id','')<>''
 OR coalesce(s->'next_action_ids','[]'::jsonb)<>'[]'::jsonb OR coalesce(s->'auxiliary_resources','[]'::jsonb)<>'[]'::jsonb
 OR coalesce(s->'auxiliary_inventory_complete','false'::jsonb)<>'false'::jsonb
 OR coalesce(s->'original_provider_create_return','null'::jsonb)<>'null'::jsonb
 OR coalesce(s->'original_provider_destroy_return','null'::jsonb)<>'null'::jsonb
 OR s->>'grant_id' IS DISTINCT FROM g.id::text OR s->>'attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR s->>'request_sha256' IS DISTINCT FROM g.grant_record#>>'{grant,request_sha256}'
 OR p.create_grant_id<>g.id OR p.original_deadline>=clock_timestamp() OR g.expires_at>=clock_timestamp()
 OR p.original_wire IS NULL OR p.preregistration_record IS DISTINCT FROM convert_from(p.original_wire,'UTF8')::jsonb
 OR p.preregistration_record->>'original_create_request_sha256' IS DISTINCT FROM s->>'request_sha256'
 OR p.preregistration_record->>'policy_id' IS DISTINCT FROM g.grant_record->>'policy_id'
 OR p.preregistration_record->>'policy_checksum' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR p.preregistration_record->>'workflow_id' IS DISTINCT FROM g.grant_record->>'workflow_id'
 OR NEW.original_grant_sha256<>encode(sha256(convert_to(g.grant_record::text,'UTF8')),'hex')
 OR NEW.original_preregistration_sha256<>encode(sha256(p.original_wire),'hex')
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=p.id)
 OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=g.id)
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=g.id::text)
 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension AND resource_id<>'')
 THEN RAISE EXCEPTION 'native denied disposition requires exact expired uncertain empty original without witness';END IF;
 IF j.state<>'unknown' OR j.native_denied_disposition_id IS NOT NULL OR j.failed_original_disposition_id IS NOT NULL
 OR j.protocol<>'capacity_dispatch_prestart_v1' OR j.run_id<>r.id OR j.started_at IS NULL OR j.returned_at IS NULL OR j.finalization_ack_at IS NOT NULL
 OR j.lease_expires_at IS NULL OR j.lease_expires_at>=clock_timestamp()
 OR (j.realm,j.environment,j.domain,j.dimension) IS DISTINCT FROM (g.namespace,g.environment,g.domain,g.dimension)
 OR j.envelope_sha256<>encode(sha256(convert_to(j.envelope,'UTF8')),'hex')
 OR e#>>'{policy,id}' IS DISTINCT FROM g.grant_record->>'policy_id' OR e#>>'{policy,checksum}' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR e#>>'{workflow,id}' IS DISTINCT FROM g.grant_record->>'workflow_id'
 OR (r.workflow_id IS NOT NULL AND r.workflow_id::text IS DISTINCT FROM e#>>'{workflow,id}')
 OR r.workflow_namespace IS DISTINCT FROM e#>>'{workflow,namespace}' OR r.workflow_name IS DISTINCT FROM e#>>'{workflow,name}' OR r.workflow_version::text IS DISTINCT FROM e#>>'{workflow,version}'
 OR r.inputs IS DISTINCT FROM e->'inputs' OR r.metadata IS DISTINCT FROM e->'metadata'
 OR r.status<>'failed' OR r.started_at IS DISTINCT FROM j.started_at OR r.finished_at IS DISTINCT FROM j.returned_at
 OR r.result->>'status' IS DISTINCT FROM 'failed' OR r.result#>>'{workflow,id}' IS DISTINCT FROM e#>>'{workflow,id}'
 OR r.result#>>'{workflow,namespace}' IS DISTINCT FROM e#>>'{workflow,namespace}' OR r.result#>>'{workflow,name}' IS DISTINCT FROM e#>>'{workflow,name}' OR r.result#>>'{workflow,version}' IS DISTINCT FROM e#>>'{workflow,version}'
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(r.result->'steps') v WHERE v->>'id'=p.preregistration_record->>'original_workflow_step_id' AND v->>'status'='failed' AND v#>>'{metadata,original_guest_refusal_predicate}'='original-guest-step-25')
 OR NEW.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex') OR NEW.original_run_sha256<>encode(sha256(convert_to(to_jsonb(r)::text,'UTF8')),'hex')
 OR EXISTS(SELECT 1 FROM public.workflow_runs WHERE (workflow_id=(g.grant_record->>'workflow_id')::uuid OR(workflow_id IS NULL AND workflow_namespace=r.workflow_namespace AND workflow_name=r.workflow_name AND workflow_version=r.workflow_version)) AND status IN('pending','running'))
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE id<>j.id AND realm=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension AND(state IN('queued','started','unknown') OR(state='returned' AND finalization_ack_at IS NULL)))
 THEN RAISE EXCEPTION 'native denied disposition requires exact failed Create run and closed unknown original ACK';END IF;
 IF coalesce(NEW.disposition_record->>'issuer','') !~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR intent#>>'{decision,reason}' IS DISTINCT FROM 'protected_floor_recovery' OR (intent#>>'{baseline_snapshot,units}')::integer IS DISTINCT FROM 0 OR (intent#>>'{assessment,snapshot,units}')::integer IS DISTINCT FROM 0
 OR intent->>'policy_id' IS DISTINCT FROM g.grant_record->>'policy_id' OR intent->>'policy_checksum' IS DISTINCT FROM g.grant_record->>'policy_checksum'
 OR (intent->>'generation')::bigint IS DISTINCT FROM g.generation
 OR NEW.closed_generation IS DISTINCT FROM (intent->>'generation')::bigint OR NEW.closed_fencing_token IS DISTINCT FROM (intent->>'fencing_token')::bigint+1
 OR (intent->>'lease_expires_at')::timestamptz>=clock_timestamp() OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 THEN RAISE EXCEPTION 'native denied disposition requires current expired intent and next fence';END IF;
 IF o->>'schema' IS DISTINCT FROM 'aws_original_authorization_denied_observation_v1' OR o->>'decision' IS DISTINCT FROM 'authorization_denied'
 OR coalesce(o->>'adapter_source_commit','') !~ '^[0-9a-f]{40}$'
 OR coalesce(o->>'event_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR coalesce(o->>'request_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR NOT EXISTS(SELECT 1 FROM public.manifests m,jsonb_array_elements(m.spec->'profiles') profile WHERE m.id=(g.grant_record->>'policy_id')::uuid AND profile->>'name'=g.profile_name AND profile->>'provider'='aws' AND profile->>'region'=o->>'region')
 OR o->'historical_profile_request_matched' IS DISTINCT FROM 'true'::jsonb OR o->'same_token_instances_empty' IS DISTINCT FROM 'true'::jsonb
 OR o->'original_HTTP_response_available' IS DISTINCT FROM 'false'::jsonb OR o->'native_mutations' IS DISTINCT FROM '0'::jsonb OR o->'Guest_admission_or_business_or_savings_authority' IS DISTINCT FROM 'false'::jsonb
 OR q->>'schema' IS DISTINCT FROM 'aws_original_authorization_denied_read_request_v1' OR q->>'grant_id' IS DISTINCT FROM g.id::text OR q->>'attempt_id' IS DISTINCT FROM g.grant_record->>'attempt_id'
 OR q->>'request_sha256' IS DISTINCT FROM s->>'request_sha256' OR q->>'scope_checksum' IS DISTINCT FROM g.scope_checksum OR q->>'profile' IS DISTINCT FROM g.profile_name OR (q->>'slot')::integer IS DISTINCT FROM g.slot
 OR q->>'original_adapter_source_commit' IS DISTINCT FROM g.grant_record#>>'{binding,original_provider_source_commit}'
 OR (q->>'grant_created_at')::timestamptz IS DISTINCT FROM (g.grant_record->>'created_at')::timestamptz
 OR (q->>'settlement_observed_at')::timestamptz IS DISTINCT FROM (s->>'observed_at')::timestamptz
 OR (q->>'original_deadline')::timestamptz IS DISTINCT FROM p.original_deadline
 OR o->>'client_token' IS DISTINCT FROM encode(sha256(convert_to(g.id::text||':'||(s->>'request_sha256'),'UTF8')),'hex')
 OR (q->>'grant_created_at')::timestamptz>(q->>'settlement_observed_at')::timestamptz OR (q->>'settlement_observed_at')::timestamptz>=(q->>'original_deadline')::timestamptz
 OR jsonb_typeof(o->'observation_started_at') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'observed_at') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'denied_at') IS DISTINCT FROM 'string'
 OR (o->>'observation_started_at')::timestamptz IS NULL OR (o->>'observed_at')::timestamptz IS NULL OR (o->>'denied_at')::timestamptz IS NULL
 OR (o->>'observed_at')::timestamptz-(o->>'observation_started_at')::timestamptz>interval '60 seconds'
 OR (o->>'observation_started_at')::timestamptz>(o->>'observed_at')::timestamptz OR (o->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR (o->>'observed_at')::timestamptz<clock_timestamp()-interval '30 seconds'
 OR coalesce(o->>'account_id','') !~ '^[0-9]{12}$' OR o->>'principal_arn' IS DISTINCT FROM 'arn:aws:iam::'||(o->>'account_id')||':user/scopedcapacity-provider-aws-20261021'
 OR (o->>'denied_at')::timestamptz<date_trunc('second',(q->>'grant_created_at')::timestamptz)
 OR (o->>'denied_at')::timestamptz>=date_trunc('second',(q->>'settlement_observed_at')::timestamptz)+interval '1 second'
 OR jsonb_typeof(o->'native_reads') IS DISTINCT FROM 'array' OR jsonb_array_length(o->'native_reads') NOT BETWEEN 3 AND 33
 THEN RAISE EXCEPTION 'native denied disposition requires typed read-only decision evidence';END IF;
 n=jsonb_array_length(o->'native_reads');
 FOR rr IN SELECT value FROM jsonb_array_elements(o->'native_reads') LOOP
  IF jsonb_typeof(rr->'called_at') IS DISTINCT FROM 'string' OR jsonb_typeof(rr->'returned_at') IS DISTINCT FROM 'string'
   OR (rr->>'called_at')::timestamptz IS NULL OR (rr->>'returned_at')::timestamptz IS NULL
   OR (rr->>'called_at')::timestamptz<(o->>'observation_started_at')::timestamptz OR (rr->>'returned_at')::timestamptz<(rr->>'called_at')::timestamptz OR (rr->>'returned_at')::timestamptz>(o->>'observed_at')::timestamptz OR (previous_return IS NOT NULL AND (rr->>'called_at')::timestamptz<previous_return) THEN RAISE EXCEPTION 'native denied HTTP time ordering';END IF;
  previous_return=(rr->>'returned_at')::timestamptz;
  IF jsonb_typeof(rr->'response_body_base64') IS DISTINCT FROM 'string'
   OR jsonb_typeof(rr->'response_bytes') IS DISTINCT FROM 'number'
   OR jsonb_typeof(rr->'response_sha256') IS DISTINCT FROM 'string'
   OR coalesce(rr->>'response_sha256','') !~ '^[0-9a-f]{64}$'
  THEN RAISE EXCEPTION 'native denied evidence requires typed body and digest';END IF;
  body=decode(rr->>'response_body_base64','base64');total=total+octet_length(body);
  IF body IS NULL OR total IS NULL OR rr->'status' IS DISTINCT FROM '200'::jsonb OR octet_length(body) NOT BETWEEN 2 AND 65536 OR total>1048576
   OR (rr->>'response_bytes')::integer IS DISTINCT FROM octet_length(body) OR rr->>'response_sha256' IS DISTINCT FROM encode(sha256(body),'hex')
  THEN RAISE EXCEPTION 'native denied evidence requires complete original bounded HTTP bodies';END IF;
  IF idx=0 THEN
   IF rr->>'response_representation' IS DISTINCT FROM 'raw_http_body_v1' OR rr->>'operation' IS DISTINCT FROM 'GetCallerIdentity' OR rr->>'resource_kind' IS DISTINCT FROM 'aws_account' OR rr->>'resource_id' IS DISTINCT FROM o->>'account_id' THEN RAISE EXCEPTION 'native denied STS evidence missing';END IF;
   xdoc=xmlparse(document convert_from(body,'UTF8'));
   IF cardinality(xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Account/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))<>1 OR (xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Account/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))[1]::text IS DISTINCT FROM o->>'account_id'
    OR cardinality(xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Arn/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))<>1 OR (xpath('/s:GetCallerIdentityResponse/s:GetCallerIdentityResult/s:Arn/text()',xdoc,ARRAY[ARRAY['s','https://sts.amazonaws.com/doc/2011-06-15/']]))[1]::text IS DISTINCT FROM o->>'principal_arn' THEN RAISE EXCEPTION 'native denied STS principal/account mismatch';END IF;
  ELSIF rr->>'operation'='DescribeInstances' THEN
   instance_phase=true;instance_pages=instance_pages+1;IF trail_pages=0 OR instance_pages>16 THEN RAISE EXCEPTION 'native denied EC2 page sequence';END IF;
   IF rr->>'response_representation' IS DISTINCT FROM 'raw_http_body_v1' OR rr->>'operation' IS DISTINCT FROM 'DescribeInstances' OR rr->>'resource_kind' IS DISTINCT FROM 'aws_ec2_instance' OR rr->>'resource_id' IS DISTINCT FROM o->>'client_token' THEN RAISE EXCEPTION 'native denied token read missing';END IF;
   xdoc=xmlparse(document convert_from(body,'UTF8'));
   IF cardinality(xpath('/e:DescribeInstancesResponse/e:reservationSet',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']]))<>1 OR xpath_exists('/e:DescribeInstancesResponse/e:reservationSet/*',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']])  THEN RAISE EXCEPTION 'native denied token instances not explicitly empty complete';END IF;
   next_ec2=coalesce((xpath('/e:DescribeInstancesResponse/e:nextToken/text()',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']]))[1]::text,'');
   IF cardinality(xpath('/e:DescribeInstancesResponse/e:nextToken',xdoc,ARRAY[ARRAY['e','http://ec2.amazonaws.com/doc/2016-11-15/']]))>1 OR length(next_ec2)>4096 OR(next_ec2<>'' AND next_ec2=ANY(instance_tokens)) OR(next_ec2<>'') IS DISTINCT FROM(idx<n-1) THEN RAISE EXCEPTION 'native denied EC2 pagination incomplete';END IF;IF next_ec2<>'' THEN instance_tokens=array_append(instance_tokens,next_ec2);END IF;
  ELSE
   trail_pages=trail_pages+1;IF instance_phase OR trail_pages>16 THEN RAISE EXCEPTION 'native denied CloudTrail page sequence';END IF;
   IF rr->>'response_representation' IS DISTINCT FROM 'cloudtrail_lookup_events_userdata_omitted_projection_v1' OR rr->>'operation' IS DISTINCT FROM 'LookupEvents' OR rr->>'resource_kind' IS DISTINCT FROM 'aws_cloudtrail_event' OR rr->>'resource_id' IS DISTINCT FROM o->>'client_token' THEN RAISE EXCEPTION 'native denied CloudTrail evidence missing';END IF;
   page=convert_from(body,'UTF8')::jsonb;
   IF page->>'schema' IS DISTINCT FROM 'cloudtrail_lookup_events_userdata_omitted_projection_v1' OR page->'original_http_body_retained' IS DISTINCT FROM 'false'::jsonb OR page->'original_http_body_hashed' IS DISTINCT FROM 'false'::jsonb OR page->'original_eof_and_close' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(page->'user_data_fields_removed') IS DISTINCT FROM 'number' OR (page->>'user_data_fields_removed')::integer NOT BETWEEN 0 AND 50 THEN RAISE EXCEPTION 'native denied CloudTrail projection provenance missing';END IF;
   page=page->'response';
   IF jsonb_typeof(page->'Events') IS DISTINCT FROM 'array' OR jsonb_array_length(page->'Events')>50 OR(coalesce(page->>'NextToken','')<>'' AND (page->>'NextToken')=ANY(trail_tokens)) OR(coalesce(page->>'NextToken','')<>'') IS DISTINCT FROM (o->'native_reads'->(idx+1)->>'operation'='LookupEvents') THEN RAISE EXCEPTION 'native denied CloudTrail pagination incomplete';END IF;IF coalesce(page->>'NextToken','')<>'' THEN trail_tokens=array_append(trail_tokens,page->>'NextToken');END IF;
   FOR item IN SELECT value FROM jsonb_array_elements(page->'Events') LOOP
    event=(item->>'CloudTrailEvent')::jsonb; IF (event->'requestParameters')?'userData' THEN RAISE EXCEPTION 'private userdata cannot enter native denied ledger';END IF;
    IF event#>>'{requestParameters,clientToken}'=o->>'client_token' THEN
     seen=seen+1;
     IF event->>'eventSource' IS DISTINCT FROM 'ec2.amazonaws.com' OR event->>'eventName' IS DISTINCT FROM 'RunInstances' OR event->>'errorCode' IS DISTINCT FROM 'Client.UnauthorizedOperation'
      OR event->'responseElements' IS DISTINCT FROM 'null'::jsonb OR coalesce(event->'resources','null'::jsonb) NOT IN('null'::jsonb,'[]'::jsonb)
      OR event->>'eventID' IS DISTINCT FROM o->>'event_id' OR item->>'EventId' IS DISTINCT FROM o->>'event_id' OR event->>'requestID' IS DISTINCT FROM o->>'request_id'
      OR event->>'recipientAccountId' IS DISTINCT FROM o->>'account_id' OR event#>>'{userIdentity,accountId}' IS DISTINCT FROM o->>'account_id' OR event#>>'{userIdentity,arn}' IS DISTINCT FROM o->>'principal_arn'
      OR event->>'awsRegion' IS DISTINCT FROM o->>'region' OR (event->>'eventTime')::timestamptz IS DISTINCT FROM (o->>'denied_at')::timestamptz
     THEN RAISE EXCEPTION 'native denied CloudTrail event is foreign ambiguous or not denied';END IF;
    END IF;
   END LOOP;
  END IF;
  idx=idx+1;
 END LOOP;
 IF seen<>1 OR instance_pages=0 THEN RAISE EXCEPTION 'native denied requires exactly one original token event';END IF;
 RETURN NEW;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_native_denied_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs) RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE d public.capacity_native_denied_dispositions;
BEGIN
 IF old_row.native_denied_disposition_id IS NOT NULL OR old_row.state='native_denied_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'native denied dispatch immutable';END IF;RETURN new_row;
 END IF;
 IF old_row.state<>'unknown' OR new_row.state<>'native_denied_disposed' OR new_row.native_denied_disposition_id IS NULL
 OR old_row.started_at IS NULL OR old_row.returned_at IS NULL OR old_row.finalization_ack_at IS NOT NULL OR new_row.finalization_ack_at IS NOT NULL
 OR old_row.lease_expires_at IS NULL OR old_row.lease_expires_at>=clock_timestamp()
 OR(to_jsonb(new_row)-ARRAY['state','updated_at','native_denied_disposition_id']) IS DISTINCT FROM(to_jsonb(old_row)-ARRAY['state','updated_at','native_denied_disposition_id'])
 THEN RAISE EXCEPTION 'native denied terminal requires unchanged expired unknown actual return';END IF;
 SELECT * INTO STRICT d FROM public.capacity_native_denied_dispositions WHERE id=new_row.native_denied_disposition_id AND job_id=old_row.id;
 IF d.run_id<>old_row.run_id OR d.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(old_row)::text,'UTF8')),'hex') THEN RAISE EXCEPTION 'native denied dispatch snapshot changed';END IF;RETURN new_row;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_native_denied_complete_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE g public.capacity_mutation_grants;j public.capacity_dispatch_jobs;i jsonb;
BEGIN
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.grant_id;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT intent INTO STRICT i FROM public.capacity_intents WHERE namespace=g.namespace AND environment=g.environment AND domain=g.domain AND dimension=g.dimension;
 IF g.native_denied_disposition_id IS DISTINCT FROM NEW.id OR j.native_denied_disposition_id IS DISTINCT FROM NEW.id OR j.state<>'native_denied_disposed' OR j.finalization_ack_at IS NOT NULL
 OR i->>'phase' IS DISTINCT FROM 'reconciled_failed_floor' OR i->'floor_degraded' IS DISTINCT FROM 'true'::jsonb OR i#>'{decision,execution_permitted}' IS DISTINCT FROM 'false'::jsonb
 OR(i->>'fencing_token')::bigint IS DISTINCT FROM NEW.closed_fencing_token OR(i->>'generation')::bigint IS DISTINCT FROM NEW.closed_generation
 THEN RAISE EXCEPTION 'native denied disposition requires atomic complete links and failed floor fence';END IF;RETURN NEW;
END;$$;
-- +goose StatementEnd

DROP FUNCTION public.native_denied_original_ack_matches(jsonb,text,timestamptz,timestamptz,timestamptz,text);
ALTER TABLE public.capacity_native_denied_dispositions DROP CONSTRAINT capacity_native_denied_original_ack_v2_check;
ALTER TABLE public.capacity_native_denied_dispositions ADD CONSTRAINT capacity_native_denied_schema_v1_check CHECK(disposition_record->>'schema' IS NOT DISTINCT FROM 'original_native_authorization_denied_terminal_disposition_v1');
ALTER TABLE public.capacity_native_denied_dispositions ADD CONSTRAINT capacity_native_denied_unknown_ack_v1_check CHECK(disposition_record->'original_unknown_ACK_preserved' IS NOT DISTINCT FROM 'true'::jsonb);
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_original_ack_v2_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_original_ack_v1_check CHECK(finalization_ack_at IS NULL OR(state='returned' AND returned_at IS NOT NULL));
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_native_denied_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_native_denied_check CHECK(
 (state='native_denied_disposed' AND native_denied_disposition_id IS NOT NULL AND failed_original_disposition_id IS NULL AND finalization_ack_at IS NULL)
 OR(state<>'native_denied_disposed' AND native_denied_disposition_id IS NULL));
