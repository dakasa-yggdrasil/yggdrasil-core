-- +goose Up
-- ADR-0117: retain an expired prepared-only maintenance nonce acquisition failure.
-- Existing nine-field M87 API, 17-column receipt and terminal remain unchanged.
-- No original ACK, provider quiescence, replay or useful-capacity claim is created.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_nonce_acquire_result_valid105(result jsonb,generation text,fence text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT COALESCE(jsonb_typeof(result)='object' AND result->>'status'='failed'
 AND jsonb_typeof(result->'steps')='array' AND jsonb_array_length(result->'steps')=7
 AND NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(result->'steps') WITH ORDINALITY x(s,n)
  JOIN (VALUES
   (1,'plan-original-guest','capacity.plan_original_guest','succeeded'),
   (2,'provision-original-notify','capacity.provision_original_guest','skipped'),
   (3,'retire-original-guest','capacity.retire_original_guest','skipped'),
   (4,'refresh-original-membership','capacity.complete_original_guest','failed'),
   (5,'complete-original-provision','capacity.complete_original_guest','skipped'),
   (6,'finish-original-retirement','capacity.finish_original_guest_retirement','skipped'),
   (7,'complete-original-retirement','capacity.complete_original_guest','skipped')
  ) e(n,id,op,status) ON e.n=x.n
  WHERE (s->>'id',s->>'kind',s->>'operation',s->>'capability',s->>'status')
    IS DISTINCT FROM (e.id,'yggdrasil',e.op,e.op,e.status)
    OR (e.n NOT IN(1,4) AND COALESCE(s->>'attempts','0')<>'0')
    OR s ? 'integration_instance' OR s ? 'integration_type')
 AND result#>>'{steps,0,attempts}'='1'
 AND result#>>'{steps,0,metadata,mode}'='refresh'
 AND result#>>'{steps,0,metadata,slot}'='0'
 AND result#>>'{steps,0,metadata,reason}'='capacity_boundary'
 AND result#>>'{steps,0,metadata,generation}'=generation
 AND result#>>'{steps,0,metadata,fencing_token}'=fence
 AND result#>>'{steps,0,metadata,lease_owner}'=''
 AND result#>>'{steps,0,metadata,preregistration_id}'=''
 AND NOT (result#>'{steps,0,metadata}' ? 'request_id')
 AND result#>>'{steps,3,attempts}'='1'
 AND result#>>'{steps,3,error}'='original Guest reconciliation held'
 AND result#>>'{steps,3,metadata,original_guest_reconcile_refusal_stage}'='fresh_original_canary'
 AND result#>>'{steps,3,metadata,original_guest_notify_refusal_stage}' ='nonce_acquire'
 AND result#>'{steps,3,metadata,original_guest_notify_nonce_http_status}'='0'::jsonb
 AND (result#>'{steps,3,metadata}')-ARRAY['original_guest_reconcile_refusal_stage','original_guest_notify_refusal_stage','original_guest_notify_nonce_http_status']='{}'::jsonb
 AND (result#>'{steps,0,metadata}')-ARRAY['mode','slot','reason','generation','fencing_token','lease_owner','preregistration_id']='{}'::jsonb
 AND result#>'{steps,0,metadata,slot}'='0'::jsonb
 AND jsonb_typeof(result#>'{steps,0,metadata,generation}')='number'
 AND jsonb_typeof(result#>'{steps,0,metadata,fencing_token}')='number',false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_nonce_acquire_proof_valid105(proof jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET timezone='UTC' AS $$
DECLARE
 j public.capacity_dispatch_jobs; w public.workflow_runs; p public.manifests;
 sl public.capacity_resource_slots; g public.capacity_mutation_grants;
 pr public.capacity_vm_provisioning_preregistrations; en public.capacity_vm_original_enrollments;
 ins public.capacity_guest_original_installations; c public.capacity_guest_notify_canary_challenges;
 ai public.capacity_guest_authority_issues; it jsonb; body jsonb; issue jsonb; tuple jsonb; line jsonb;
 issued_text text; deadline_text text; base_time timestamptz; issued_ns numeric; deadline_ns numeric;
 empty_lifetime jsonb; empty_nonce jsonb; owner_hash bytea; expected_owner text; binding jsonb; registration jsonb; receipt jsonb;
BEGIN
 IF (jsonb_typeof(proof)='object' AND octet_length(proof::text) BETWEEN 1 AND 1048576
  AND proof ?& ARRAY['schema','dispatch','run','policy','intent','membership','challenge','authority_issue','policy_lineage']
  AND proof-ARRAY['schema','dispatch','run','policy','intent','membership','challenge','authority_issue','policy_lineage']='{}'::jsonb
  AND proof->>'schema'='unknown_nonce_acquire_prepared_only_v1'
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(proof) z WHERE z.key NOT IN('schema','policy_lineage') AND jsonb_typeof(z.value)<>'object')
  AND jsonb_typeof(proof->'policy_lineage')='array' AND jsonb_array_length(proof->'policy_lineage') BETWEEN 1 AND 4096
  AND proof->'membership' ?& ARRAY['slot','grant','preregistration','enrollment','installation']
  AND (proof->'membership')-ARRAY['slot','grant','preregistration','enrollment','installation']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(proof->'membership') z WHERE jsonb_typeof(z.value)<>'object')) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO j FROM jsonb_populate_record(NULL::public.capacity_dispatch_jobs,proof->'dispatch');
 SELECT * INTO w FROM jsonb_populate_record(NULL::public.workflow_runs,proof->'run');
 SELECT * INTO p FROM jsonb_populate_record(NULL::public.manifests,proof->'policy');
 SELECT * INTO sl FROM jsonb_populate_record(NULL::public.capacity_resource_slots,proof#>'{membership,slot}');
 SELECT * INTO g FROM jsonb_populate_record(NULL::public.capacity_mutation_grants,proof#>'{membership,grant}');
 SELECT * INTO pr FROM jsonb_populate_record(NULL::public.capacity_vm_provisioning_preregistrations,proof#>'{membership,preregistration}');
 SELECT * INTO en FROM jsonb_populate_record(NULL::public.capacity_vm_original_enrollments,proof#>'{membership,enrollment}');
 SELECT * INTO ins FROM jsonb_populate_record(NULL::public.capacity_guest_original_installations,proof#>'{membership,installation}');
 SELECT * INTO c FROM jsonb_populate_record(NULL::public.capacity_guest_notify_canary_challenges,proof->'challenge');
 SELECT * INTO ai FROM jsonb_populate_record(NULL::public.capacity_guest_authority_issues,proof->'authority_issue');
 it=proof->'intent'; body=convert_from(c.original_wire,'UTF8')::jsonb; issue=convert_from(ai.original_wire,'UTF8')::jsonb;
 binding=convert_from(pr.binding_wire,'UTF8')::jsonb; registration=convert_from(en.registration_wire,'UTF8')::jsonb; receipt=convert_from(en.receipt_wire,'UTF8')::jsonb;
 tuple=en.enrollment_record#>'{statement,tuple}';
 owner_hash=digest(uuid_send('04321c5b-fb9b-5087-9636-068fa7072abd'::uuid)||uuid_send(c.executor_id::uuid),'sha1');
 owner_hash=set_byte(owner_hash,6,(get_byte(owner_hash,6)&15)|80);
 owner_hash=set_byte(owner_hash,8,(get_byte(owner_hash,8)&63)|128);
 expected_owner=(encode(substring(owner_hash FROM 1 FOR 16),'hex')::uuid)::text;
 -- Core context clocks retain exact nanoseconds; PG recorded_at clocks remain separate.
 issued_text=body->>'issued_at'; deadline_text=body->>'original_deadline';
 IF issued_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{0,8}[1-9])?Z$'
  OR deadline_text !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{0,8}[1-9])?Z$'
 THEN RETURN false; END IF;
 base_time=(left(issued_text,19)||'Z')::timestamptz;
 IF to_char(base_time,'YYYY-MM-DD"T"HH24:MI:SS')<>left(issued_text,19) THEN RETURN false; END IF;
 issued_ns=extract(epoch FROM base_time)*1000000000+COALESCE(NULLIF(rpad(substring(issued_text FROM '\.([0-9]+)Z$'),9,'0'),''),'0')::numeric;
 base_time=(left(deadline_text,19)||'Z')::timestamptz;
 IF to_char(base_time,'YYYY-MM-DD"T"HH24:MI:SS')<>left(deadline_text,19) THEN RETURN false; END IF;
 deadline_ns=extract(epoch FROM base_time)*1000000000+COALESCE(NULLIF(rpad(substring(deadline_text FROM '\.([0-9]+)Z$'),9,'0'),''),'0')::numeric;
 empty_lifetime=jsonb_build_object('boot_id','','process_nonce_sha256','','pid',0,'start_ticks',0,'source_commit','','binary_sha256','','service_invocation_id','');
 empty_nonce=jsonb_build_object('schema','','challenge_id','','phase','','preflight_sha256','','enrollment_sha256','','actor',empty_lifetime,'runtime',empty_lifetime,'writer',jsonb_build_object('id','','lifetime',empty_lifetime),'nonce_sha256','','issued_monotonic_ns',0,'expires_monotonic_ns',0,'signature','');
 IF (j.id IS NOT NULL AND j.id<>'00000000-0000-0000-0000-000000000000'::uuid AND j.run_id=w.id
  AND j.realm='dakasa-production' AND j.environment='production' AND j.domain='notify'
  AND j.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND j.protocol='capacity_dispatch_prestart_v1' AND j.state='unknown' AND j.fencing_token>0
  AND j.lease_owner IS NOT NULL AND j.started_at IS NOT NULL AND j.started_at<j.returned_at AND j.returned_at<j.lease_expires_at
  AND j.return_status='failed' AND j.return_error='capacity dispatch original deadline exceeded'
  AND j.finalization_ack_at IS NULL AND j.finalization_error IS NULL
  AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0
  AND j.envelope_sha256=encode(sha256(convert_to(j.envelope,'UTF8')),'hex')
  AND w.status='failed' AND w.error=j.return_error AND w.started_at=j.started_at AND w.finished_at=j.returned_at
  AND w.workflow_namespace=j.envelope::jsonb#>>'{workflow,namespace}' AND w.workflow_name=j.envelope::jsonb#>>'{workflow,name}'
  AND w.workflow_version::text=j.envelope::jsonb#>>'{workflow,version}'
  AND (w.workflow_id IS NULL OR w.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}')
  AND w.inputs=j.envelope::jsonb->'inputs' AND w.metadata=j.envelope::jsonb->'metadata'
  AND p.id::text=j.envelope::jsonb#>>'{policy,id}' AND p.kind='capacity_policy' AND p.active
  AND p.namespace=j.envelope::jsonb#>>'{policy,namespace}' AND p.name=j.envelope::jsonb#>>'{policy,name}'
  AND p.version::text=j.envelope::jsonb#>>'{policy,version}' AND p.checksum=j.envelope::jsonb#>>'{policy,checksum}'
  AND p.spec->>'environment'=j.environment AND p.spec->>'domain'=j.domain AND p.spec->>'dimension'=j.dimension
  AND p.spec#>>'{guest_notify_reconcile_binding,mode}'='original_guest_notify_reconcile_v1'
  AND it->>'policy_id'=p.id::text AND it->>'policy_checksum'=p.checksum
  AND it->>'phase' IN('promoted','reconciled','reconciled_partial')
  AND COALESCE(it->>'lease_owner','')='' AND COALESCE(it->>'lease_executor_id','')=''
  AND COALESCE(jsonb_typeof(it->'lease_expires_at'),'null')='null'
  AND COALESCE(it->'recovery_only','false'::jsonb)='false'::jsonb AND COALESCE(it->'floor_degraded','false'::jsonb)='false'::jsonb
  AND COALESCE(jsonb_typeof(it->'failed_installed_disposal'),'null')='null'
  AND COALESCE(jsonb_typeof(it->'installed_guest_reconcile'),'null')='null'
  AND COALESCE(jsonb_typeof(it->'original_notify_window'),'null')='null'
  AND COALESCE(jsonb_typeof(it->'retirement_forward'),'null')='null'
  AND it#>>'{decision,action}'='hold' AND it#>'{decision,execution_permitted}'='false'::jsonb
  AND it#>>'{decision,reason}'='capacity_boundary' AND it#>'{decision,units}'='1'::jsonb
  AND it#>'{assessment,snapshot,units}'='1'::jsonb
  AND public.unknown_maintenance_nonce_acquire_result_valid105(w.result,it->>'generation',it->>'fencing_token')
  AND w.result#>>'{workflow,id}'=j.envelope::jsonb#>>'{workflow,id}' AND w.result#>>'{workflow,kind}'='workflow'
  AND w.result#>>'{workflow,namespace}'=j.envelope::jsonb#>>'{workflow,namespace}'
  AND w.result#>>'{workflow,name}'=j.envelope::jsonb#>>'{workflow,name}' AND w.result#>>'{workflow,version}'=j.envelope::jsonb#>>'{workflow,version}'
  AND sl.namespace=j.realm AND sl.environment=j.environment AND sl.domain=j.domain AND sl.dimension=j.dimension AND sl.slot=1
  AND NOT(sl.slot_record ? 'authority_kind') AND COALESCE(sl.slot_record->'tombstone','false'::jsonb)='false'::jsonb
  AND octet_length(sl.resource_id) BETWEEN 1 AND 256 AND position(chr(10) in sl.resource_id)=0 AND position(chr(13) in sl.resource_id)=0
  AND btrim(sl.resource_id,U&'\0009\000a\000b\000c\000d\0020\0085\00a0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200a\2028\2029\202f\205f\3000')=sl.resource_id
  AND g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension
  AND g.slot=sl.slot AND g.integration_instance_id=sl.integration_instance_id AND g.scope_checksum=sl.scope_checksum AND g.profile_name=sl.profile_name
  AND g.state='confirmed' AND NOT(g.grant_record ? 'authority_kind')
  AND num_nonnulls(g.original_disposition_id,g.failed_original_disposition_id,g.native_denied_disposition_id,g.enrolled_failed_disposition_id)=0
  AND g.grant_record#>>'{grant,capability}'=g.grant_record#>>'{binding,ensure_capability}'
  AND pr.create_grant_id=g.id AND pr.preregistration_record->>'original_create_grant_id'=g.id::text
  AND pr.preregistration_record->>'original_create_request_sha256'=g.grant_record#>>'{grant,request_sha256}'
  AND pr.preregistration_record->>'generation'=g.generation::text
  AND pr.preregistration_record->>'fence'=g.grant_record->>'fencing_token'
  AND pr.preregistration_record->>'slot'='1' AND pr.id=en.preregistration_id AND pr.id=ins.preregistration_id
  AND pr.preregistration_record->>'workflow_id'=j.envelope::jsonb#>>'{workflow,id}'
  AND pr.preregistration_record->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'
  AND pr.created_at<j.started_at-interval '30 seconds' AND en.recorded_at<j.started_at-interval '30 seconds' AND ins.recorded_at<j.started_at-interval '30 seconds'
  AND pr.preregistration_record=convert_from(pr.original_wire,'UTF8')::jsonb AND octet_length(pr.original_wire) BETWEEN 1 AND 65536
  AND binding->>'profile_manifest_sha256'=pr.profile_manifest_sha256
  AND encode(sha256(convert_to((convert_from(pr.binding_wire,'UTF8')::json->'profile_manifest')::text,'UTF8')),'hex')=pr.profile_manifest_sha256
  AND binding=(proof#>'{policy_lineage,0,spec,guest_retirement_binding}')
  AND binding->>'core_authority_source_commit'=body->>'core_source_commit'
  AND receipt->>'preregistration_id'=pr.id::text AND receipt->>'original_provisioning_sha256'=en.original_provisioning_sha256
  AND receipt->'enrollment'=en.enrollment_record AND (receipt->>'recorded_at')::timestamptz=en.recorded_at
  AND encode(sha256(convert_to((convert_from(en.receipt_wire,'UTF8')::json->'enrollment')::text,'UTF8')),'hex')=en.enrollment_sha256
  AND encode(sha256(en.registration_wire),'hex')=en.original_provisioning_sha256
  AND registration->'enrollment_statement'=en.enrollment_record->'statement'
  AND encode(sha256(convert_to((convert_from(en.registration_wire,'UTF8')::json#>'{enrollment_statement,tuple}')::text,'UTF8')),'hex')=en.resource_tuple_sha256
  AND encode(sha256(ins.original_wire),'hex')=ins.confirmation_sha256
  AND tuple->>'resource_id'=sl.resource_id AND tuple->>'resource_created_at'=sl.slot_record->>'resource_created_at'
  AND tuple->>'integration_instance_id'=sl.integration_instance_id::text AND tuple->>'scope_checksum'=sl.scope_checksum
  AND tuple->>'profile'=sl.profile_name AND tuple->'slot'='1'::jsonb
  AND tuple->>'provider'=CASE j.dimension WHEN 'original_notify_aws_vm_members' THEN 'aws' ELSE 'hetzner' END
  AND body= c.original_record AND body=convert_from(c.original_wire,'UTF8')::jsonb
  AND c.challenge_sha256=encode(sha256(c.original_wire),'hex') AND octet_length(c.original_wire) BETWEEN 1 AND 65536
  AND (SELECT count(*) FROM json_each(convert_from(c.original_wire,'UTF8')::json))=(SELECT count(*) FROM jsonb_each(body))
  AND body ?& ARRAY['schema','purpose','challenge_id','nonce_sha256','usage_class','record_challenge_id','binding_name','slot','preregistration_id','preregistration_nonce_sha256','original_registration_sha256','original_create_witness_sha256','enrollment_sha256','profile_manifest_sha256','tuple','policy_id','policy_checksum','workflow_id','workflow_checksum','generation','fence','lease_owner','core_source_commit','issued_at','original_deadline','guest_nonce','signature']
  AND body-ARRAY['schema','purpose','challenge_id','nonce_sha256','usage_class','record_challenge_id','binding_name','slot','preregistration_id','preregistration_nonce_sha256','original_registration_sha256','original_create_witness_sha256','enrollment_sha256','profile_manifest_sha256','tuple','policy_id','policy_checksum','workflow_id','workflow_checksum','generation','fence','lease_owner','core_source_commit','issued_at','original_deadline','guest_nonce','signature']='{}'::jsonb
  AND body->>'schema'='guest_notify_business_canary_publish_challenge_v1' AND body->>'purpose'='create_notify_original_canary_once'
  AND c.phase='publish' AND c.id=c.record_challenge_id AND body->>'challenge_id'=c.id::text AND body->>'record_challenge_id'=c.id::text
  AND c.preregistration_id=pr.id AND body->>'preregistration_id'=pr.id::text AND body->>'usage_class'='steady_useful_membership'
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(body) z WHERE z.key NOT IN('slot','generation','fence','tuple','guest_nonce') AND jsonb_typeof(z.value)<>'string')
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['nonce_sha256','preregistration_nonce_sha256','original_registration_sha256','original_create_witness_sha256','enrollment_sha256','profile_manifest_sha256','policy_checksum','workflow_checksum']) k WHERE COALESCE(body->>k,'') !~ '^[a-f0-9]{64}$')
  AND body->'slot'='1'::jsonb AND body->'tuple'=tuple AND body->'guest_nonce'=empty_nonce
  AND tuple ?& ARRAY['provider','integration_instance_id','instance_checksum','integration_type_id','type_checksum','scope_checksum','profile_checksum','profile','slot','resource_id','resource_created_at']
  AND tuple-ARRAY['provider','integration_instance_id','instance_checksum','integration_type_id','type_checksum','scope_checksum','profile_checksum','profile','slot','resource_id','resource_created_at']='{}'::jsonb
  AND (SELECT count(*) FROM json_each(convert_from(c.original_wire,'UTF8')::json->'tuple'))=11
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(tuple) z WHERE z.key<>'slot' AND jsonb_typeof(z.value)<>'string')
  AND body->>'binding_name'=pr.preregistration_record->>'binding_name'
  AND body->>'preregistration_nonce_sha256'=pr.nonce_sha256 AND body->>'profile_manifest_sha256'=pr.profile_manifest_sha256
  AND body->>'original_registration_sha256'=en.original_provisioning_sha256
  AND body->>'enrollment_sha256'=en.enrollment_sha256
  AND body->>'core_source_commit'=en.enrollment_record#>>'{statement,core_authority_source_commit}'
  AND c.policy_id=p.id AND body->>'policy_id'=p.id::text AND body->>'policy_checksum'=p.checksum
  AND c.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}' AND body->>'workflow_id'=c.workflow_id::text AND body->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'
  AND c.generation BETWEEN 1 AND 9007199254740991 AND c.fence BETWEEN 1 AND 9007199254740991
  AND c.generation::text=it->>'generation' AND c.fence::text=it->>'fencing_token'
  AND body->>'generation'=c.generation::text AND body->>'fence'=c.fence::text
  AND jsonb_typeof(body->'generation')='number' AND (body->'generation')::text ~ '^[1-9][0-9]*$'
  AND jsonb_typeof(body->'fence')='number' AND (body->'fence')::text ~ '^[1-9][0-9]*$'
  AND c.executor_id~'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
  AND c.executor_id=(c.executor_id::uuid)::text AND c.lease_owner=expected_owner AND body->>'lease_owner'=c.lease_owner
  AND body->>'nonce_sha256'=c.nonce_sha256 AND c.nonce_sha256~'^[a-f0-9]{64}$'
  AND body->>'signature'~'^[A-Za-z0-9+/]{86}==$' AND body->>'core_source_commit'~'^[a-f0-9]{40}$'
  AND deadline_ns>issued_ns AND deadline_ns-issued_ns<=5000000000
  AND deadline_ns<=extract(epoch FROM j.lease_expires_at)*1000000000
  AND deadline_ns<=extract(epoch FROM w.updated_at)*1000000000 AND c.original_deadline=deadline_text::timestamptz
  AND c.recorded_at>=j.started_at AND c.recorded_at<=w.updated_at AND c.recorded_at<j.lease_expires_at
  AND ai.issue_kind='canary_challenge' AND ai.issue_id=c.id AND ai.policy_id=c.policy_id AND ai.workflow_id=c.workflow_id AND ai.executor_id=c.executor_id
  AND ai.issued_wire_sha256=c.challenge_sha256 AND ai.protocol_authority_source_commit=body->>'core_source_commit'
  AND ai.issuer_actual_source_commit~'^[a-f0-9]{40}$' AND ai.compatibility_map_sha256~'^[a-f0-9]{64}$' AND ai.profile=sl.profile_name
  AND ai.original_record=issue AND issue->>'schema'='guest_authority_issue_v1'
  AND issue=jsonb_build_object('schema','guest_authority_issue_v1','issue_kind',ai.issue_kind,'issue_id',ai.issue_id,'issuer_actual_source_commit',ai.issuer_actual_source_commit,'protocol_authority_source_commit',ai.protocol_authority_source_commit,'compatibility_map_sha256',ai.compatibility_map_sha256,'profile',ai.profile,'policy_id',ai.policy_id,'workflow_id',ai.workflow_id,'executor_id',ai.executor_id,'issued_wire_sha256',ai.issued_wire_sha256)
  AND (SELECT count(*) FROM json_each(convert_from(ai.original_wire,'UTF8')::json))=11
  AND ai.recorded_at>=c.recorded_at AND ai.recorded_at<=w.updated_at) IS NOT TRUE THEN RETURN false; END IF;
 -- The whole live lineage was archived once. These checks never read manifests.
 line=proof->'policy_lineage';
 RETURN (line->(jsonb_array_length(line)-1)=proof->'policy'
  AND line#>>'{0,id}'=pr.preregistration_record->>'policy_id'
  AND line#>>'{0,checksum}'=pr.preregistration_record->>'policy_checksum'
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(line) v WHERE jsonb_typeof(v)<>'object'
   OR (v->>'kind',v->>'namespace',v->>'name') IS DISTINCT FROM (p.kind,p.namespace,p.name)
   OR public.http_maintenance_dispatch_policy_projection(v->'spec') IS DISTINCT FROM public.http_maintenance_dispatch_policy_projection(p.spec))
  AND public.http_maintenance_dispatch_policy_projection(p.spec) IS NOT NULL
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(line) WITH ORDINALITY q(v,n) WHERE n>1
   AND (v->>'version')::bigint<=(line->(n::int-2)->>'version')::bigint)
  AND (line->0->>'version')::bigint<=p.version) IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan87_legacy105(job uuid)
RETURNS jsonb LANGUAGE sql STABLE AS $$
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 w AS (SELECT w.* FROM public.workflow_runs w,j WHERE w.id=j.run_id),
 it AS (SELECT i.intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm
  AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),
 mem AS (SELECT public.unknown_maintenance_dispatch_members(job) AS members),
 candidates AS (
 SELECT c.* FROM public.capacity_guest_notify_canary_challenges c
 JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=c.preregistration_id
 JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id CROSS JOIN j
 WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension
 AND (c.recorded_at>=j.started_at-interval '30 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces n WHERE n.challenge_id=c.id AND n.recorded_at>=j.started_at-interval '30 seconds')
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=c.id AND (s.recorded_at>=j.started_at-interval '30 seconds' OR s.possible_send_at>=j.started_at-interval '30 seconds'))
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.started_at-interval '30 seconds'))),
 epoch AS (SELECT COALESCE(
  j.environment='production' AND j.domain='notify' AND j.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND it.intent->>'policy_id'=j.envelope::jsonb#>>'{policy,id}'
  AND it.intent->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND it.intent->>'phase' IN('promoted','reconciled','reconciled_partial')
  AND COALESCE(it.intent->>'lease_owner','')='' AND COALESCE(it.intent->>'lease_executor_id','')=''
  AND COALESCE(jsonb_typeof(it.intent->'lease_expires_at'),'null')='null'
  AND COALESCE(it.intent->>'recovery_only','false')='false' AND COALESCE(it.intent->>'floor_degraded','false')='false'
  AND COALESCE(jsonb_typeof(it.intent->'failed_installed_disposal'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'installed_guest_reconcile'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'original_notify_window'),'null')='null'
  AND it.intent#>>'{decision,action}'='hold' AND COALESCE(it.intent#>>'{decision,execution_permitted}','false')='false'
  AND EXISTS(SELECT 1 FROM public.manifests p WHERE p.id::text=j.envelope::jsonb#>>'{policy,id}' AND p.kind='capacity_policy'
   AND p.active AND p.checksum=j.envelope::jsonb#>>'{policy,checksum}'
   AND p.spec#>>'{guest_notify_reconcile_binding,mode}'='original_guest_notify_reconcile_v1'
   AND p.spec#>>'{environment}'=j.environment AND p.spec#>>'{domain}'=j.domain AND p.spec#>>'{dimension}'=j.dimension)
  AND EXISTS(SELECT 1 FROM public.manifests wf WHERE wf.id::text=j.envelope::jsonb#>>'{workflow,id}' AND wf.kind='workflow'
   AND wf.active AND wf.checksum=j.envelope::jsonb#>>'{workflow,checksum}'),false) AS valid FROM j,w,it)
SELECT jsonb_build_object('schema','unknown_maintenance_dispatch_effect_scan_v1',
 'base',public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at),
 'current_members',(SELECT members FROM mem),
 'current_members_sha256',encode(sha256(convert_to((SELECT members FROM mem)::text,'UTF8')),'hex'),
 'current_member_count',jsonb_array_length((SELECT members FROM mem)),
 'policy_epoch_valid',COALESCE((SELECT valid FROM epoch),false),
 'refresh_only_result',COALESCE((SELECT public.unknown_maintenance_dispatch_result_valid(w.result,it.intent->>'generation',it.intent->>'fencing_token')
  AND w.result#>>'{workflow,id}'=j.envelope::jsonb#>>'{workflow,id}'
  AND w.result#>>'{workflow,kind}'='workflow'
  AND w.result#>>'{workflow,namespace}'=j.envelope::jsonb#>>'{workflow,namespace}'
  AND w.result#>>'{workflow,name}'=j.envelope::jsonb#>>'{workflow,name}'
  AND w.result#>>'{workflow,version}'=j.envelope::jsonb#>>'{workflow,version}' FROM w,it),false),
 'invalid_maintenance_canary_rows',(SELECT count(*) FROM candidates c WHERE NOT COALESCE(
  c.original_record->>'usage_class'='steady_useful_membership'
  AND c.policy_id::text=j.envelope::jsonb#>>'{policy,id}' AND c.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}'
  AND c.generation::text=(SELECT intent->>'generation' FROM it) AND c.fence::text=(SELECT intent->>'fencing_token' FROM it)
  AND c.original_record->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND c.original_record->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'
  AND c.original_deadline<=j.lease_expires_at AND c.original_deadline<statement_timestamp()
  AND EXISTS(SELECT 1 FROM jsonb_array_elements((SELECT members FROM mem)) m WHERE m->>'preregistration_id'=c.preregistration_id::text)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=c.id
    AND (s.possible_send_at>=c.original_deadline OR s.original_deadline IS DISTINCT FROM c.original_deadline OR s.recorded_at>=j.lease_expires_at))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces n WHERE n.challenge_id=c.id AND n.recorded_at>=j.lease_expires_at)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.lease_expires_at),false)))
FROM j
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_scan_tolerable87_legacy105(scan jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT COALESCE(jsonb_typeof(scan)='object' AND scan->>'schema'='unknown_maintenance_dispatch_effect_scan_v1'
 AND scan->'policy_epoch_valid'='true'::jsonb AND scan->'refresh_only_result'='true'::jsonb
 AND scan->'invalid_maintenance_canary_rows'='0'::jsonb
 AND jsonb_typeof(scan->'current_members')='array' AND jsonb_array_length(scan->'current_members') BETWEEN 1 AND 8
 AND scan->'current_member_count'=to_jsonb(jsonb_array_length(scan->'current_members'))
 AND scan->>'current_members_sha256'=encode(sha256(convert_to((scan->'current_members')::text,'UTF8')),'hex')
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan->'base') e WHERE e.key IN('canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start')
   AND (jsonb_typeof(e.value)<>'number' OR (e.value::text)::numeric<0 OR trunc((e.value::text)::numeric)<>(e.value::text)::numeric))
 AND public.finalization_lost_dispatch_effect_scan_tolerable((scan->'base') || jsonb_build_object(
  'canary_challenges_since_start',0,'canary_nonces_since_start',0,'canary_possible_sends_since_start',0,'canary_returns_since_start',0)),false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_nonce_acquire_effect_scan105(job uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs; p public.manifests; it jsonb;
 membership jsonb; lineage jsonb; member jsonb; proof jsonb; scan jsonb; ids uuid[];
 c public.capacity_guest_notify_canary_challenges; ai public.capacity_guest_authority_issues;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=job;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=j.run_id;
 SELECT * INTO STRICT p FROM public.manifests WHERE id::text=j.envelope::jsonb#>>'{policy,id}' AND kind='capacity_policy' AND active
  AND namespace=j.envelope::jsonb#>>'{policy,namespace}' AND name=j.envelope::jsonb#>>'{policy,name}'
  AND version::text=j.envelope::jsonb#>>'{policy,version}' AND checksum=j.envelope::jsonb#>>'{policy,checksum}';
 IF EXISTS(SELECT 1 FROM public.manifests later WHERE later.kind=p.kind AND later.namespace=p.namespace AND later.name=p.name
  AND ((later.active AND later.id<>p.id) OR later.version>p.version)) THEN RETURN NULL; END IF;
 IF EXISTS(SELECT 1 FROM(VALUES('workflow',j.envelope::jsonb->'workflow'),('rbac',j.envelope::jsonb->'rbac'),('policy',j.envelope::jsonb->'authorization_policy')) pins(kind,pin)
  WHERE pin IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.manifests m WHERE m.id::text=pin->>'id' AND m.kind=pins.kind AND m.active
   AND m.namespace=pin->>'namespace' AND m.name=pin->>'name' AND m.version::text=pin->>'version' AND m.checksum=pin->>'checksum')) THEN RETURN NULL; END IF;
 SELECT intent INTO STRICT it FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension;
 IF (SELECT count(*) FROM public.capacity_resource_slots s WHERE s.namespace=j.realm AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension
  AND s.resource_id<>'' AND COALESCE(s.slot_record->'tombstone','false'::jsonb)='false'::jsonb)<>1 THEN RETURN NULL; END IF;
 SELECT jsonb_build_object('slot',to_jsonb(s),'grant',to_jsonb(g),'preregistration',to_jsonb(pr),'enrollment',to_jsonb(en),'installation',to_jsonb(ins)) INTO STRICT membership
 FROM public.capacity_resource_slots s
 JOIN public.capacity_mutation_grants g ON g.namespace=s.namespace AND g.environment=s.environment AND g.domain=s.domain AND g.dimension=s.dimension
  AND g.slot=s.slot AND g.integration_instance_id=s.integration_instance_id AND g.scope_checksum=s.scope_checksum AND g.profile_name=s.profile_name AND g.state='confirmed'
 JOIN public.capacity_vm_provisioning_preregistrations pr ON pr.create_grant_id=g.id
 JOIN public.capacity_vm_original_enrollments en ON en.preregistration_id=pr.id
  AND en.enrollment_record#>>'{statement,tuple,resource_id}'=s.resource_id
  AND en.enrollment_record#>>'{statement,tuple,resource_created_at}'=s.slot_record->>'resource_created_at'
  AND en.enrollment_record#>>'{statement,tuple,integration_instance_id}'=s.integration_instance_id::text
  AND en.enrollment_record#>>'{statement,tuple,scope_checksum}'=s.scope_checksum
  AND en.enrollment_record#>>'{statement,tuple,profile}'=s.profile_name
  AND en.enrollment_record#>>'{statement,tuple,slot}'=s.slot::text
 JOIN public.capacity_guest_original_installations ins ON ins.preregistration_id=pr.id
 WHERE s.namespace=j.realm AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension AND s.slot=1
  AND s.resource_id<>'' AND COALESCE(s.slot_record->'tombstone','false'::jsonb)='false'::jsonb AND NOT(s.slot_record ? 'authority_kind')
  AND public.http_maintenance_dispatch_policy_continuous((pr.preregistration_record->>'policy_id')::uuid,pr.preregistration_record->>'policy_checksum',p.id,p.checksum)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents ri WHERE ri.preregistration_id=pr.id);
 SELECT jsonb_agg(to_jsonb(h) ORDER BY h.version) INTO lineage FROM public.manifests h
 JOIN public.manifests birth ON birth.id::text=membership#>>'{preregistration,preregistration_record,policy_id}'
 WHERE h.kind=p.kind AND h.namespace=p.namespace AND h.name=p.name AND h.version BETWEEN birth.version AND p.version;
 SELECT array_agg(cc.id ORDER BY cc.id) INTO ids FROM public.capacity_guest_notify_canary_challenges cc
 JOIN public.capacity_vm_provisioning_preregistrations pr ON pr.id=cc.preregistration_id JOIN public.capacity_mutation_grants g ON g.id=pr.create_grant_id
 WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension
  AND (cc.recorded_at>=j.started_at-interval '30 seconds'
   OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces n WHERE n.challenge_id=cc.id AND n.recorded_at>=j.started_at-interval '30 seconds')
   OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=cc.id AND (s.recorded_at>=j.started_at-interval '30 seconds' OR s.possible_send_at>=j.started_at-interval '30 seconds'))
   OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=cc.id AND r.recorded_at>=j.started_at-interval '30 seconds'));
 IF cardinality(ids) IS DISTINCT FROM 1 THEN RETURN NULL; END IF;
 SELECT * INTO STRICT c FROM public.capacity_guest_notify_canary_challenges WHERE id=ids[1];
 SELECT * INTO STRICT ai FROM public.capacity_guest_authority_issues WHERE issue_kind='canary_challenge' AND issue_id=c.id;
 IF c.original_deadline>=statement_timestamp()
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces WHERE challenge_id=c.id)
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends WHERE challenge_id=c.id)
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=c.id) THEN RETURN NULL; END IF;
 proof=jsonb_build_object('schema','unknown_nonce_acquire_prepared_only_v1','dispatch',to_jsonb(j),'run',to_jsonb(w),'policy',to_jsonb(p),'intent',it,
  'membership',membership,'challenge',to_jsonb(c),'authority_issue',to_jsonb(ai),'policy_lineage',lineage);
 IF public.unknown_maintenance_nonce_acquire_proof_valid105(proof) IS NOT TRUE THEN RETURN NULL; END IF;
 member=jsonb_build_object('slot',1,'resource_id',membership#>>'{slot,resource_id}','preregistration_id',membership#>>'{preregistration,id}',
  'policy_id',membership#>>'{preregistration,preregistration_record,policy_id}','policy_checksum',membership#>>'{preregistration,preregistration_record,policy_checksum}',
  'enrollment_sha256',membership#>>'{enrollment,enrollment_sha256}','installation_sha256',membership#>>'{installation,confirmation_sha256}',
  'slot_sha256',encode(sha256(convert_to(jsonb_build_object('record',membership#>'{slot,slot_record}','revision',membership#>'{slot,revision}','updated_at',membership#>'{slot,updated_at}')::text,'UTF8')),'hex'));
 scan=jsonb_build_object('schema','unknown_maintenance_dispatch_effect_scan_v1',
  'base',public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at),
  'current_members',jsonb_build_array(member),'current_members_sha256',encode(sha256(convert_to(jsonb_build_array(member)::text,'UTF8')),'hex'),'current_member_count',1,
  'policy_epoch_valid',true,'refresh_only_result',true,'invalid_maintenance_canary_rows',0,'nonce_acquire_prepared_only',proof);
 RETURN scan;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_nonce_acquire_scan_tolerable105(scan jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET timezone='UTC' AS $$
DECLARE b jsonb=scan->'base'; proof jsonb=scan->'nonce_acquire_prepared_only'; member jsonb=scan#>'{current_members,0}'; expected_member jsonb;
BEGIN
 IF public.unknown_maintenance_nonce_acquire_proof_valid105(proof) IS NOT TRUE THEN RETURN false; END IF;
 expected_member=jsonb_build_object('slot',1,'resource_id',proof#>>'{membership,slot,resource_id}','preregistration_id',proof#>>'{membership,preregistration,id}',
  'policy_id',proof#>>'{membership,preregistration,preregistration_record,policy_id}','policy_checksum',proof#>>'{membership,preregistration,preregistration_record,policy_checksum}',
  'enrollment_sha256',proof#>>'{membership,enrollment,enrollment_sha256}','installation_sha256',proof#>>'{membership,installation,confirmation_sha256}',
  'slot_sha256',encode(sha256(convert_to(jsonb_build_object('record',proof#>'{membership,slot,slot_record}','revision',proof#>'{membership,slot,revision}','updated_at',proof#>'{membership,slot,updated_at}')::text,'UTF8')),'hex'));
 RETURN (jsonb_typeof(scan)='object' AND octet_length(scan::text)<=2097152
  AND scan ?& ARRAY['schema','base','current_members','current_members_sha256','current_member_count','policy_epoch_valid','refresh_only_result','invalid_maintenance_canary_rows','nonce_acquire_prepared_only']
  AND scan-ARRAY['schema','base','current_members','current_members_sha256','current_member_count','policy_epoch_valid','refresh_only_result','invalid_maintenance_canary_rows','nonce_acquire_prepared_only']='{}'::jsonb
  AND scan->>'schema'='unknown_maintenance_dispatch_effect_scan_v1' AND scan->'policy_epoch_valid'='true'::jsonb AND scan->'refresh_only_result'='true'::jsonb
  AND scan->'invalid_maintenance_canary_rows'='0'::jsonb AND scan->>'invalid_maintenance_canary_rows'='0'
  AND scan->'current_member_count'='1'::jsonb AND scan->>'current_member_count'='1' AND scan->'current_members'=jsonb_build_array(expected_member)
  AND scan->>'current_members_sha256'=encode(sha256(convert_to((scan->'current_members')::text,'UTF8')),'hex')
  AND b ?& ARRAY['authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','base_schema','caller_possible_sends_since_start','caller_returns_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','clock_skew_margin_seconds','create_witnesses_since_start','enrollments_since_start','executor_activity_updated_since_start','grants_created_or_updated_since_start','installations_since_start','intent_events_since_start','intents_updated_since_start','native_commands_since_start','native_lifetime_archives_since_start','native_lifetimes_updated_since_start','native_pod_checkpoints_since_start','native_poweroff_reads_since_start','notify_window_markers_for_job','observation_refresh_slot_updates','open_undisposed_grants','partial_nativeoff_reads_since_start','partial_nativeoff_reconciliations_since_start','prejournal_refusal_recoveries_since_start','preregistrations_since_start','presend_retirement_recoveries_since_start','provider_quiescence_proved','provider_read_performed','pure_assessment_intent_updates','qualification_native_source_returns_since_start','qualification_probe_challenges_since_start','resource_slots_updated_since_start','retirement_contexts_since_start','retirement_delete_bindings_since_start','retirement_intents_since_start','retirement_native_readbacks_since_start','retirement_original_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','schema','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start'] AND b-ARRAY['authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','base_schema','caller_possible_sends_since_start','caller_returns_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','clock_skew_margin_seconds','create_witnesses_since_start','enrollments_since_start','executor_activity_updated_since_start','grants_created_or_updated_since_start','installations_since_start','intent_events_since_start','intents_updated_since_start','native_commands_since_start','native_lifetime_archives_since_start','native_lifetimes_updated_since_start','native_pod_checkpoints_since_start','native_poweroff_reads_since_start','notify_window_markers_for_job','observation_refresh_slot_updates','open_undisposed_grants','partial_nativeoff_reads_since_start','partial_nativeoff_reconciliations_since_start','prejournal_refusal_recoveries_since_start','preregistrations_since_start','presend_retirement_recoveries_since_start','provider_quiescence_proved','provider_read_performed','pure_assessment_intent_updates','qualification_native_source_returns_since_start','qualification_probe_challenges_since_start','resource_slots_updated_since_start','retirement_contexts_since_start','retirement_delete_bindings_since_start','retirement_intents_since_start','retirement_native_readbacks_since_start','retirement_original_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','schema','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(b) z WHERE z.key NOT IN('schema','base_schema','provider_read_performed','provider_quiescence_proved')
   AND (jsonb_typeof(z.value)<>'number' OR z.value::text !~ '^(0|[1-9][0-9]*)$'))
  AND b->'canary_challenges_since_start'='1'::jsonb AND b->'canary_nonces_since_start'='0'::jsonb
  AND b->'canary_possible_sends_since_start'='0'::jsonb AND b->'canary_returns_since_start'='0'::jsonb
  AND b->'pure_assessment_intent_updates'='1'::jsonb AND b->'observation_refresh_slot_updates'='1'::jsonb
  AND public.finalization_lost_dispatch_effect_scan_tolerable(b||jsonb_build_object('canary_challenges_since_start',0)) IS TRUE) IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan(job uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE candidate jsonb;
BEGIN
 candidate=public.unknown_maintenance_nonce_acquire_effect_scan105(job);
 IF candidate IS NOT NULL THEN RETURN candidate; END IF;
 RETURN public.unknown_maintenance_dispatch_effect_scan87_legacy105(job);
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan_tolerable(scan jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF scan ? 'nonce_acquire_prepared_only' THEN RETURN public.unknown_maintenance_nonce_acquire_scan_tolerable105(scan); END IF;
 RETURN public.unknown_maintenance_dispatch_scan_tolerable87_legacy105(scan);
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_nonce_acquire_receipt_valid105(d public.capacity_dispatch_unknown_maintenance_dispositions)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET timezone='UTC' AS $$
DECLARE proof jsonb=d.provider_mutation_evidence->'nonce_acquire_prepared_only'; j jsonb=proof->'dispatch'; w jsonb=proof->'run';
BEGIN
 RETURN (public.unknown_maintenance_nonce_acquire_scan_tolerable105(d.provider_mutation_evidence)
  AND d.job_id::text=j->>'id' AND d.run_id::text=j->>'run_id' AND d.run_id::text=w->>'id'
  AND d.original_dispatch_sha256=encode(sha256(convert_to(j::text,'UTF8')),'hex')
  AND d.original_run_sha256=encode(sha256(convert_to(w::text,'UTF8')),'hex')
  AND d.original_returned_at=(j->>'returned_at')::timestamptz
  AND d.current_members_sha256=d.provider_mutation_evidence->>'current_members_sha256'
  AND d.executor_barrier='disposing_core_process_started_after_lease_expiry_v1'
  AND d.disposing_core_process_started_at>(j->>'lease_expires_at')::timestamptz
  AND d.disposing_core_process_started_at<=d.recorded_at AND d.recorded_at>=(j->>'lease_expires_at')::timestamptz+interval '15 minutes'
  AND d.reason='unknown_failed_maintenance_dispatch_disposed' AND d.historical_return='unknown') IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_unknown_maintenance_nonce_acquire_receipt105() RETURNS trigger
LANGUAGE plpgsql SET timezone='UTC' AS $$
BEGIN
 IF NEW.provider_mutation_evidence ? 'nonce_acquire_prepared_only' AND public.unknown_maintenance_nonce_acquire_receipt_valid105(NEW) IS NOT TRUE
 THEN RAISE EXCEPTION 'prepared-only nonce maintenance requires exact immutable receipt proof'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_unknown_maintenance_nonce_acquire_canary105() RETURNS trigger
LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE realm text; environment_name text; domain_name text; dimension_name text;
BEGIN
 SELECT g.namespace,g.environment,g.domain,g.dimension INTO realm,environment_name,domain_name,dimension_name
 FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_vm_provisioning_preregistrations pr ON pr.id=c.preregistration_id
 JOIN public.capacity_mutation_grants g ON g.id=pr.create_grant_id WHERE c.id=NEW.challenge_id;
 IF NOT FOUND THEN RETURN NEW; END IF;
 IF (realm='dakasa-production' AND environment_name='production' AND domain_name='notify'
  AND dimension_name IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')) IS NOT TRUE THEN RETURN NEW; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[realm,environment_name,domain_name,dimension_name]) value WHERE value IS NULL OR value !~ '^[ -~]+$' OR value ~ '[<>&]')
 THEN RAISE EXCEPTION 'prepared-only nonce maintenance requires exact scope encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[realm,environment_name,domain_name,dimension_name])::text,0));
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_unknown_maintenance_dispositions d
  WHERE d.provider_mutation_evidence#>>'{nonce_acquire_prepared_only,challenge,id}'=NEW.challenge_id::text)
 THEN RAISE EXCEPTION 'prepared-only nonce maintenance challenge is permanently closed'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_unknown_maintenance_dispositions'::regclass AND tgname='unknown_maintenance_nonce_acquire_receipt105') THEN
  CREATE TRIGGER unknown_maintenance_nonce_acquire_receipt105 BEFORE INSERT ON public.capacity_dispatch_unknown_maintenance_dispositions FOR EACH ROW EXECUTE FUNCTION public.guard_unknown_maintenance_nonce_acquire_receipt105();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_dispatch_unknown_maintenance_dispositions'::regclass AND conname='unknown_maintenance_nonce_acquire_proof105') THEN
  ALTER TABLE public.capacity_dispatch_unknown_maintenance_dispositions ADD CONSTRAINT unknown_maintenance_nonce_acquire_proof105
  CHECK((NOT(provider_mutation_evidence ? 'nonce_acquire_prepared_only') OR public.unknown_maintenance_nonce_acquire_proof_valid105(provider_mutation_evidence->'nonce_acquire_prepared_only')) IS TRUE);
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_guest_notify_canary_nonces'::regclass AND tgname='unknown_nonce_acquire_nonces105') THEN
  CREATE TRIGGER unknown_nonce_acquire_nonces105 BEFORE INSERT ON public.capacity_guest_notify_canary_nonces FOR EACH ROW EXECUTE FUNCTION public.guard_unknown_maintenance_nonce_acquire_canary105();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_guest_notify_canary_sends'::regclass AND tgname='unknown_nonce_acquire_sends105') THEN
  CREATE TRIGGER unknown_nonce_acquire_sends105 BEFORE INSERT ON public.capacity_guest_notify_canary_sends FOR EACH ROW EXECUTE FUNCTION public.guard_unknown_maintenance_nonce_acquire_canary105();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_guest_notify_canary_returns'::regclass AND tgname='unknown_nonce_acquire_returns105') THEN
  CREATE TRIGGER unknown_nonce_acquire_returns105 BEFORE INSERT ON public.capacity_guest_notify_canary_returns FOR EACH ROW EXECUTE FUNCTION public.guard_unknown_maintenance_nonce_acquire_canary105();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_unknown_maintenance_dispositions WHERE provider_mutation_evidence ? 'nonce_acquire_prepared_only')
 THEN RAISE EXCEPTION 'used prepared-only nonce maintenance proof is permanent provenance'; END IF;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS unknown_nonce_acquire_nonces105 ON public.capacity_guest_notify_canary_nonces;
DROP TRIGGER IF EXISTS unknown_nonce_acquire_sends105 ON public.capacity_guest_notify_canary_sends;
DROP TRIGGER IF EXISTS unknown_nonce_acquire_returns105 ON public.capacity_guest_notify_canary_returns;
DROP TRIGGER IF EXISTS unknown_maintenance_nonce_acquire_receipt105 ON public.capacity_dispatch_unknown_maintenance_dispositions;
ALTER TABLE public.capacity_dispatch_unknown_maintenance_dispositions DROP CONSTRAINT IF EXISTS unknown_maintenance_nonce_acquire_proof105;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan(job uuid)
RETURNS jsonb LANGUAGE sql STABLE AS $$
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 w AS (SELECT w.* FROM public.workflow_runs w,j WHERE w.id=j.run_id),
 it AS (SELECT i.intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm
  AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),
 mem AS (SELECT public.unknown_maintenance_dispatch_members(job) AS members),
 candidates AS (
 SELECT c.* FROM public.capacity_guest_notify_canary_challenges c
 JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=c.preregistration_id
 JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id CROSS JOIN j
 WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension
 AND (c.recorded_at>=j.started_at-interval '30 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces n WHERE n.challenge_id=c.id AND n.recorded_at>=j.started_at-interval '30 seconds')
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=c.id AND (s.recorded_at>=j.started_at-interval '30 seconds' OR s.possible_send_at>=j.started_at-interval '30 seconds'))
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.started_at-interval '30 seconds'))),
 epoch AS (SELECT COALESCE(
  j.environment='production' AND j.domain='notify' AND j.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND it.intent->>'policy_id'=j.envelope::jsonb#>>'{policy,id}'
  AND it.intent->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND it.intent->>'phase' IN('promoted','reconciled','reconciled_partial')
  AND COALESCE(it.intent->>'lease_owner','')='' AND COALESCE(it.intent->>'lease_executor_id','')=''
  AND COALESCE(jsonb_typeof(it.intent->'lease_expires_at'),'null')='null'
  AND COALESCE(it.intent->>'recovery_only','false')='false' AND COALESCE(it.intent->>'floor_degraded','false')='false'
  AND COALESCE(jsonb_typeof(it.intent->'failed_installed_disposal'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'installed_guest_reconcile'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'original_notify_window'),'null')='null'
  AND it.intent#>>'{decision,action}'='hold' AND COALESCE(it.intent#>>'{decision,execution_permitted}','false')='false'
  AND EXISTS(SELECT 1 FROM public.manifests p WHERE p.id::text=j.envelope::jsonb#>>'{policy,id}' AND p.kind='capacity_policy'
   AND p.active AND p.checksum=j.envelope::jsonb#>>'{policy,checksum}'
   AND p.spec#>>'{guest_notify_reconcile_binding,mode}'='original_guest_notify_reconcile_v1'
   AND p.spec#>>'{environment}'=j.environment AND p.spec#>>'{domain}'=j.domain AND p.spec#>>'{dimension}'=j.dimension)
  AND EXISTS(SELECT 1 FROM public.manifests wf WHERE wf.id::text=j.envelope::jsonb#>>'{workflow,id}' AND wf.kind='workflow'
   AND wf.active AND wf.checksum=j.envelope::jsonb#>>'{workflow,checksum}'),false) AS valid FROM j,w,it)
SELECT jsonb_build_object('schema','unknown_maintenance_dispatch_effect_scan_v1',
 'base',public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at),
 'current_members',(SELECT members FROM mem),
 'current_members_sha256',encode(sha256(convert_to((SELECT members FROM mem)::text,'UTF8')),'hex'),
 'current_member_count',jsonb_array_length((SELECT members FROM mem)),
 'policy_epoch_valid',COALESCE((SELECT valid FROM epoch),false),
 'refresh_only_result',COALESCE((SELECT public.unknown_maintenance_dispatch_result_valid(w.result,it.intent->>'generation',it.intent->>'fencing_token')
  AND w.result#>>'{workflow,id}'=j.envelope::jsonb#>>'{workflow,id}'
  AND w.result#>>'{workflow,kind}'='workflow'
  AND w.result#>>'{workflow,namespace}'=j.envelope::jsonb#>>'{workflow,namespace}'
  AND w.result#>>'{workflow,name}'=j.envelope::jsonb#>>'{workflow,name}'
  AND w.result#>>'{workflow,version}'=j.envelope::jsonb#>>'{workflow,version}' FROM w,it),false),
 'invalid_maintenance_canary_rows',(SELECT count(*) FROM candidates c WHERE NOT COALESCE(
  c.original_record->>'usage_class'='steady_useful_membership'
  AND c.policy_id::text=j.envelope::jsonb#>>'{policy,id}' AND c.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}'
  AND c.generation::text=(SELECT intent->>'generation' FROM it) AND c.fence::text=(SELECT intent->>'fencing_token' FROM it)
  AND c.original_record->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND c.original_record->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'
  AND c.original_deadline<=j.lease_expires_at AND c.original_deadline<statement_timestamp()
  AND EXISTS(SELECT 1 FROM jsonb_array_elements((SELECT members FROM mem)) m WHERE m->>'preregistration_id'=c.preregistration_id::text)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=c.id
    AND (s.possible_send_at>=c.original_deadline OR s.original_deadline IS DISTINCT FROM c.original_deadline OR s.recorded_at>=j.lease_expires_at))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces n WHERE n.challenge_id=c.id AND n.recorded_at>=j.lease_expires_at)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.lease_expires_at),false)))
FROM j
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan_tolerable(scan jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT COALESCE(jsonb_typeof(scan)='object' AND scan->>'schema'='unknown_maintenance_dispatch_effect_scan_v1'
 AND scan->'policy_epoch_valid'='true'::jsonb AND scan->'refresh_only_result'='true'::jsonb
 AND scan->'invalid_maintenance_canary_rows'='0'::jsonb
 AND jsonb_typeof(scan->'current_members')='array' AND jsonb_array_length(scan->'current_members') BETWEEN 1 AND 8
 AND scan->'current_member_count'=to_jsonb(jsonb_array_length(scan->'current_members'))
 AND scan->>'current_members_sha256'=encode(sha256(convert_to((scan->'current_members')::text,'UTF8')),'hex')
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan->'base') e WHERE e.key IN('canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start')
   AND (jsonb_typeof(e.value)<>'number' OR (e.value::text)::numeric<0 OR trunc((e.value::text)::numeric)<>(e.value::text)::numeric))
 AND public.finalization_lost_dispatch_effect_scan_tolerable((scan->'base') || jsonb_build_object(
  'canary_challenges_since_start',0,'canary_nonces_since_start',0,'canary_possible_sends_since_start',0,'canary_returns_since_start',0)),false)
$$;
-- +goose StatementEnd

DROP FUNCTION IF EXISTS public.guard_unknown_maintenance_nonce_acquire_receipt105();
DROP FUNCTION IF EXISTS public.guard_unknown_maintenance_nonce_acquire_canary105();
DROP FUNCTION IF EXISTS public.unknown_maintenance_nonce_acquire_receipt_valid105(public.capacity_dispatch_unknown_maintenance_dispositions);
DROP FUNCTION IF EXISTS public.unknown_maintenance_nonce_acquire_scan_tolerable105(jsonb);
DROP FUNCTION IF EXISTS public.unknown_maintenance_nonce_acquire_effect_scan105(uuid);
DROP FUNCTION IF EXISTS public.unknown_maintenance_dispatch_effect_scan87_legacy105(uuid);
DROP FUNCTION IF EXISTS public.unknown_maintenance_dispatch_scan_tolerable87_legacy105(jsonb);
DROP FUNCTION IF EXISTS public.unknown_maintenance_nonce_acquire_proof_valid105(jsonb);
DROP FUNCTION IF EXISTS public.unknown_maintenance_nonce_acquire_result_valid105(jsonb,text,text);
