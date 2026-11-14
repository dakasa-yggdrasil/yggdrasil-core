-- +goose Up
-- A separate terminal for one failed, original readonly PUB/READ dispatch.
-- Equivalent policy identity is proved, never reactivated. No original ACK,
-- canary return, provider effect, replay or useful-capacity credit is created.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_result_valid(result jsonb,generation text,fence text)
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
 AND result#>>'{steps,0,metadata,reason}'='down_window_pending'
 AND result#>>'{steps,0,metadata,generation}'=generation
 AND result#>>'{steps,0,metadata,fencing_token}'=fence
 AND result#>>'{steps,0,metadata,lease_owner}'=''
 AND result#>>'{steps,0,metadata,preregistration_id}'=''
 AND NOT (result#>'{steps,0,metadata}' ? 'request_id')
 AND result#>>'{steps,3,attempts}'='1'
 AND result#>>'{steps,3,error}'='original Guest reconciliation held'
 AND result#>>'{steps,3,metadata,original_guest_reconcile_refusal_stage}'='fresh_original_canary'
 AND result#>>'{steps,3,metadata,original_guest_notify_refusal_stage}' ='original_HTTP_or_return',false)
$$;
-- +goose StatementEnd

-- Birth generation/fence belong to the immutable enrollment, not the later
-- maintenance epoch. ADR-0094 continuity authenticates that birth through the
-- active, whole-spec-equivalent replacement. All native tuple joins remain.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_members(job uuid)
RETURNS jsonb LANGUAGE sql STABLE SET timezone='UTC' AS $$
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 replacement AS (SELECT c.* FROM public.manifests c JOIN public.manifests old_policy ON c.kind=old_policy.kind AND c.namespace=old_policy.namespace AND c.name=old_policy.name CROSS JOIN j
  WHERE old_policy.id::text=j.envelope::jsonb#>>'{policy,id}' AND old_policy.kind='capacity_policy' AND NOT old_policy.active AND c.active
  AND c.version>old_policy.version AND c.checksum=old_policy.checksum AND c.spec=old_policy.spec
  AND NOT EXISTS(SELECT 1 FROM public.manifests later WHERE later.kind=c.kind AND later.namespace=c.namespace AND later.name=c.name AND ((later.active AND later.id<>c.id) OR later.version>c.version))),
 all_sl AS (SELECT s.* FROM public.capacity_resource_slots s,j WHERE s.namespace=j.realm
  AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension
  AND s.resource_id<>'' AND COALESCE(s.slot_record->>'tombstone','false')='false'
 ), sl AS (SELECT * FROM all_sl WHERE NOT(slot_record ? 'authority_kind')),
 joined AS (
 SELECT s.slot,s.resource_id,s.slot_record,s.revision,s.updated_at,p.id AS preregistration_id,
  e.enrollment_sha256,n.confirmation_sha256,p.preregistration_record
 FROM sl s CROSS JOIN j CROSS JOIN replacement current_policy
 JOIN public.capacity_mutation_grants g ON g.namespace=j.realm AND g.environment=j.environment
  AND g.domain=j.domain AND g.dimension=j.dimension AND g.slot=s.slot
  AND g.integration_instance_id=s.integration_instance_id AND g.scope_checksum=s.scope_checksum
  AND g.profile_name=s.profile_name AND g.state='confirmed'
  AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL
  AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL
 JOIN public.capacity_vm_provisioning_preregistrations p ON p.create_grant_id=g.id
  AND p.preregistration_record->>'slot'=s.slot::text
  AND public.http_maintenance_dispatch_policy_continuous((p.preregistration_record->>'policy_id')::uuid,p.preregistration_record->>'policy_checksum',current_policy.id,current_policy.checksum)
  AND p.preregistration_record->>'workflow_id'=j.envelope::jsonb#>>'{workflow,id}'
  AND p.preregistration_record->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'

 JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=p.id
  AND e.enrollment_record#>>'{statement,tuple,resource_id}'=s.resource_id
  AND e.enrollment_record#>>'{statement,tuple,resource_created_at}'=s.slot_record->>'resource_created_at'
  AND e.enrollment_record#>>'{statement,tuple,integration_instance_id}'=s.integration_instance_id::text
  AND e.enrollment_record#>>'{statement,tuple,scope_checksum}'=s.scope_checksum
  AND e.enrollment_record#>>'{statement,tuple,profile}'=s.profile_name
  AND e.enrollment_record#>>'{statement,tuple,slot}'=s.slot::text
  AND p.preregistration_record->>'generation'=g.generation::text
 JOIN public.capacity_guest_original_installations n ON n.preregistration_id=p.id
  AND encode(sha256(n.original_wire),'hex')=n.confirmation_sha256
 WHERE p.created_at<j.started_at-interval '30 seconds' AND e.recorded_at<j.started_at-interval '30 seconds'
  AND n.recorded_at<j.started_at-interval '30 seconds'
  AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents ri WHERE ri.preregistration_id=p.id)
 )
SELECT CASE WHEN (SELECT count(*) FROM sl)=1 AND (SELECT min(slot) FROM sl)=1
 AND (SELECT count(*) FROM sl)=(SELECT count(*) FROM all_sl)
 AND (SELECT count(*) FROM joined)=(SELECT count(*) FROM sl)
 AND (SELECT count(DISTINCT slot) FROM joined)=(SELECT count(*) FROM sl)
 THEN (SELECT jsonb_agg(jsonb_build_object('slot',slot,'resource_id',resource_id,
  'preregistration_id',preregistration_id,'policy_id',preregistration_record->>'policy_id','policy_checksum',preregistration_record->>'policy_checksum','enrollment_sha256',enrollment_sha256,
  'installation_sha256',confirmation_sha256,
  'slot_sha256',encode(sha256(convert_to(jsonb_build_object('record',slot_record,'revision',revision,'updated_at',updated_at)::text,'UTF8')),'hex'))
  ORDER BY slot) FROM joined)
 ELSE '[]'::jsonb END
$$;
-- +goose StatementEnd

-- A missing READ return is retained as missing. The accepted PUB is not a
-- successful joined business READ and cannot be counted as useful capacity.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_canary_pair(job uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE
 original_job public.capacity_dispatch_jobs; original_run public.workflow_runs; current_intent jsonb; members jsonb; ids uuid[];
 publication public.capacity_guest_notify_canary_challenges; reader public.capacity_guest_notify_canary_challenges;
 challenge public.capacity_guest_notify_canary_challenges; nonce_row public.capacity_guest_notify_canary_nonces;
 send_row public.capacity_guest_notify_canary_sends; publication_return public.capacity_guest_notify_canary_returns;
 final_record jsonb; nonce_record jsonb; pub_body jsonb; transport jsonb;
BEGIN
 SELECT * INTO STRICT original_job FROM public.capacity_dispatch_jobs WHERE id=job;
 SELECT * INTO STRICT original_run FROM public.workflow_runs WHERE id=original_job.run_id;
 SELECT intent INTO STRICT current_intent FROM public.capacity_intents
  WHERE namespace=original_job.realm AND environment=original_job.environment AND domain=original_job.domain AND dimension=original_job.dimension;
 members=public.superseded_http_maintenance_dispatch_members(job);
 IF jsonb_array_length(members)<>1 THEN RETURN NULL; END IF;
 SELECT array_agg(cc.id ORDER BY cc.id) INTO ids
 FROM public.capacity_guest_notify_canary_challenges cc
 JOIN public.capacity_vm_provisioning_preregistrations pr ON pr.id=cc.preregistration_id
 JOIN public.capacity_mutation_grants grant_row ON grant_row.id=pr.create_grant_id
 WHERE grant_row.namespace=original_job.realm AND grant_row.environment=original_job.environment
 AND grant_row.domain=original_job.domain AND grant_row.dimension=original_job.dimension
 AND (cc.recorded_at>=original_job.started_at-interval '30 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces nn WHERE nn.challenge_id=cc.id AND nn.recorded_at>=original_job.started_at-interval '30 seconds')
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends ss WHERE ss.challenge_id=cc.id AND (ss.recorded_at>=original_job.started_at-interval '30 seconds' OR ss.possible_send_at>=original_job.started_at-interval '30 seconds'))
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns rr WHERE rr.challenge_id=cc.id AND rr.recorded_at>=original_job.started_at-interval '30 seconds'));
 IF cardinality(ids) IS DISTINCT FROM 2 THEN RETURN NULL; END IF;
 SELECT * INTO STRICT publication FROM public.capacity_guest_notify_canary_challenges WHERE id=ANY(ids) AND phase='publish';
 SELECT * INTO STRICT reader FROM public.capacity_guest_notify_canary_challenges WHERE id=ANY(ids) AND phase='read';
 IF (publication.id<>reader.id AND publication.record_challenge_id=publication.id AND reader.record_challenge_id=publication.id
  AND publication.preregistration_id=reader.preregistration_id AND publication.executor_id=reader.executor_id
  AND publication.lease_owner=reader.lease_owner
  AND publication.original_record->>'schema'='guest_notify_business_canary_publish_challenge_v1'
  AND publication.original_record->>'purpose'='create_notify_original_canary_once'
  AND reader.original_record->>'schema'='guest_notify_business_canary_challenge_v1'
  AND reader.original_record->>'purpose'='original_notify_creation_read_only'
  AND (publication.original_record-ARRAY['schema','purpose','challenge_id','nonce_sha256','issued_at','original_deadline','guest_nonce','signature'])
     =(reader.original_record-ARRAY['schema','purpose','challenge_id','nonce_sha256','issued_at','original_deadline','guest_nonce','signature'])
  AND (reader.original_record->>'issued_at')::timestamptz>=(publication.original_record->>'issued_at')::timestamptz
  AND (reader.original_record->>'issued_at')::timestamptz<publication.original_deadline
  AND reader.original_deadline<=publication.original_deadline
  AND reader.recorded_at>=publication.recorded_at) IS NOT TRUE THEN RETURN NULL; END IF;
 FOR challenge IN SELECT * FROM public.capacity_guest_notify_canary_challenges WHERE id=ANY(ids) LOOP
  SELECT * INTO STRICT nonce_row FROM public.capacity_guest_notify_canary_nonces WHERE challenge_id=challenge.id;
  SELECT * INTO STRICT send_row FROM public.capacity_guest_notify_canary_sends WHERE challenge_id=challenge.id;
  final_record=convert_from(nonce_row.final_challenge_wire,'UTF8')::jsonb;
  nonce_record=convert_from(nonce_row.nonce_wire,'UTF8')::jsonb;
  IF (challenge.original_record=convert_from(challenge.original_wire,'UTF8')::jsonb
   AND challenge.challenge_sha256=encode(sha256(challenge.original_wire),'hex')
   AND challenge.original_record->>'challenge_id'=challenge.id::text
   AND challenge.original_record->>'record_challenge_id'=challenge.record_challenge_id::text
   AND challenge.original_record->>'preregistration_id'=challenge.preregistration_id::text
   AND challenge.original_record->>'usage_class'='steady_useful_membership'
   AND challenge.original_record->>'slot'='1'
   AND challenge.preregistration_id::text=members#>>'{0,preregistration_id}'
   AND challenge.original_record->>'enrollment_sha256'=members#>>'{0,enrollment_sha256}'
   AND challenge.policy_id::text=original_job.envelope::jsonb#>>'{policy,id}'
   AND challenge.workflow_id::text=original_job.envelope::jsonb#>>'{workflow,id}'
   AND challenge.original_record->>'policy_id'=challenge.policy_id::text
   AND challenge.original_record->>'workflow_id'=challenge.workflow_id::text
   AND challenge.original_record->>'policy_checksum'=original_job.envelope::jsonb#>>'{policy,checksum}'
   AND challenge.original_record->>'workflow_checksum'=original_job.envelope::jsonb#>>'{workflow,checksum}'
   AND challenge.generation::text=current_intent->>'generation' AND challenge.fence::text=current_intent->>'fencing_token'
   AND challenge.original_record->>'generation'=challenge.generation::text
   AND challenge.original_record->>'fence'=challenge.fence::text
   AND challenge.original_record->>'lease_owner'=challenge.lease_owner
   AND challenge.original_record->>'nonce_sha256'=challenge.nonce_sha256
   AND challenge.original_record->'tuple'=(SELECT enrollment_record#>'{statement,tuple}' FROM public.capacity_vm_original_enrollments WHERE preregistration_id=challenge.preregistration_id)
   AND challenge.original_deadline=(challenge.original_record->>'original_deadline')::timestamptz
   AND challenge.original_deadline>(challenge.original_record->>'issued_at')::timestamptz
   AND challenge.original_deadline<=(challenge.original_record->>'issued_at')::timestamptz+interval '5 seconds'
   AND challenge.original_deadline<=original_job.lease_expires_at AND challenge.original_deadline<statement_timestamp()
   AND challenge.recorded_at>=original_job.started_at AND challenge.recorded_at<=original_run.updated_at
   AND challenge.recorded_at<original_job.lease_expires_at
   AND nonce_row.recorded_at>=challenge.recorded_at AND nonce_row.recorded_at<=original_run.updated_at
   AND nonce_row.recorded_at<original_job.lease_expires_at
   AND nonce_row.final_challenge_sha256=encode(sha256(nonce_row.final_challenge_wire),'hex')
   AND final_record-ARRAY['guest_nonce','signature']=challenge.original_record-ARRAY['guest_nonce','signature']
   AND final_record->'guest_nonce'=nonce_record
   AND nonce_row.guest_nonce_sha256=nonce_record->>'nonce_sha256'
   AND nonce_row.original_transport->>'ResponseSHA256'=encode(sha256(nonce_row.nonce_wire),'hex')
   AND nonce_row.original_transport->'OriginalContextFailed'='false'::jsonb
   AND nonce_row.original_transport->'Status'='200'::jsonb
   AND nonce_row.original_transport->>'ResponseBodyScope'='complete_original_body_read'
   AND nonce_row.original_transport->'ReceivedBodyBytes'=to_jsonb(octet_length(nonce_row.nonce_wire))
   AND nonce_row.original_transport->'RetainedPrefixBytes'=to_jsonb(octet_length(nonce_row.nonce_wire))
   AND nonce_row.original_transport->>'RetainedPrefixSHA256'=encode(sha256(nonce_row.nonce_wire),'hex')
   AND nonce_row.original_transport->'PreflightFailed'='false'::jsonb AND nonce_row.original_transport->'DoFailed'='false'::jsonb
   AND nonce_row.original_transport->'ReadFailed'='false'::jsonb AND nonce_row.original_transport->'CloseFailed'='false'::jsonb
   AND (nonce_row.original_transport->>'StartedAt')::timestamptz>=(challenge.original_record->>'issued_at')::timestamptz
   AND (nonce_row.original_transport->>'DoStartedAt')::timestamptz>=(nonce_row.original_transport->>'StartedAt')::timestamptz
   AND (nonce_row.original_transport->>'DoReturnedAt')::timestamptz>=(nonce_row.original_transport->>'DoStartedAt')::timestamptz
   AND (nonce_row.original_transport->>'ReadReturnedAt')::timestamptz>=(nonce_row.original_transport->>'DoReturnedAt')::timestamptz
   AND (nonce_row.original_transport->>'CloseReturnedAt')::timestamptz>=(nonce_row.original_transport->>'ReadReturnedAt')::timestamptz
   AND (nonce_row.original_transport->>'DriverReturnedAt')::timestamptz>=(nonce_row.original_transport->>'CloseReturnedAt')::timestamptz
   AND (nonce_row.original_transport->>'DriverReturnedAt')::timestamptz<challenge.original_deadline
   AND (nonce_row.original_transport->>'DriverReturnedAt')::timestamptz<=send_row.possible_send_at
   AND send_row.original_deadline=challenge.original_deadline
   AND send_row.possible_send_at>=(challenge.original_record->>'issued_at')::timestamptz
   AND send_row.possible_send_at<challenge.original_deadline AND send_row.recorded_at<original_job.lease_expires_at
   AND send_row.recorded_at>=nonce_row.recorded_at AND send_row.recorded_at<=original_run.updated_at
   AND send_row.request_sha256=encode(sha256(convert_to('{"challenge":','UTF8')||nonce_row.final_challenge_wire||convert_to('}','UTF8')),'hex')
   AND EXISTS(SELECT 1 FROM public.capacity_guest_authority_issues ai WHERE ai.issue_kind='canary_challenge' AND ai.issue_id=challenge.id
    AND ai.policy_id=challenge.policy_id AND ai.workflow_id=challenge.workflow_id AND ai.executor_id=challenge.executor_id
    AND ai.issued_wire_sha256=challenge.challenge_sha256)) IS NOT TRUE THEN RETURN NULL; END IF;
 END LOOP;
 SELECT * INTO STRICT publication_return FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=publication.id;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=reader.id) THEN RETURN NULL; END IF;
 pub_body=convert_from(publication_return.original_wire,'UTF8')::jsonb;
 transport=publication_return.original_transport;
 IF (publication_return.outcome='accepted' AND publication_return.original_wire IS NOT NULL
  AND publication_return.return_sha256=encode(sha256(publication_return.original_wire),'hex')
  AND jsonb_typeof(publication_return.business_observation)='object'
  AND transport->>'CanaryReturnValidationStage'='accepted'
  AND transport->'Status'='200'::jsonb AND transport->>'ResponseBodyScope'='complete_original_body_read'
  AND transport->>'ResponseSHA256'=publication_return.return_sha256
  AND transport->>'RetainedPrefixSHA256'=publication_return.return_sha256
  AND transport->'ReceivedBodyBytes'=to_jsonb(octet_length(publication_return.original_wire))
  AND transport->'RetainedPrefixBytes'=to_jsonb(octet_length(publication_return.original_wire))
  AND transport->'PreflightFailed'='false'::jsonb AND transport->'DoFailed'='false'::jsonb
  AND transport->'ReadFailed'='false'::jsonb AND transport->'CloseFailed'='false'::jsonb AND transport->'OriginalContextFailed'='false'::jsonb
  AND (transport->>'StartedAt')::timestamptz>=(publication.original_record->>'issued_at')::timestamptz
  AND (transport->>'DoStartedAt')::timestamptz>=(transport->>'StartedAt')::timestamptz
  AND (transport->>'DoReturnedAt')::timestamptz>=(transport->>'DoStartedAt')::timestamptz
  AND (transport->>'ReadReturnedAt')::timestamptz>=(transport->>'DoReturnedAt')::timestamptz
  AND (transport->>'CloseReturnedAt')::timestamptz>=(transport->>'ReadReturnedAt')::timestamptz
  AND (transport->>'DriverReturnedAt')::timestamptz>=(transport->>'CloseReturnedAt')::timestamptz
  AND (transport->>'DriverReturnedAt')::timestamptz<publication.original_deadline
  AND (transport->>'DriverReturnedAt')::timestamptz<=(reader.original_record->>'issued_at')::timestamptz
  AND publication_return.recorded_at<original_job.lease_expires_at AND publication_return.recorded_at<=reader.recorded_at
  AND publication_return.recorded_at>=(SELECT recorded_at FROM public.capacity_guest_notify_canary_sends WHERE challenge_id=publication.id)
  AND publication_return.recorded_at<=original_run.updated_at
  AND pub_body->>'schema'='guest_notify_business_canary_publication_v1'
  AND pub_body->>'purpose'='create_notify_original_canary_once'
  AND pub_body->>'challenge_id'=publication.id::text
  AND pub_body->>'challenge_sha256'=(SELECT final_challenge_sha256 FROM public.capacity_guest_notify_canary_nonces WHERE challenge_id=publication.id)
  AND pub_body->>'preregistration_id'=publication.preregistration_id::text
  AND pub_body->>'enrollment_sha256'=publication.original_record->>'enrollment_sha256'
  AND pub_body->'tuple'=publication.original_record->'tuple'
  AND pub_body->'original_context_failed'='false'::jsonb AND pub_body->'hold_reasons'='[]'::jsonb) IS NOT TRUE THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('publish_id',publication.id,'read_id',reader.id,
  'publish_challenge_sha256',publication.challenge_sha256,'read_challenge_sha256',reader.challenge_sha256,
  'publish_return_sha256',encode(sha256(convert_to(to_jsonb(publication_return)::text,'UTF8')),'hex'));
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_effect_scan(job uuid)
RETURNS jsonb LANGUAGE sql STABLE SET timezone='UTC' AS $$
WITH j AS(SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 w AS(SELECT wr.* FROM public.workflow_runs wr,j WHERE wr.id=j.run_id),
 it AS(SELECT ci.intent FROM public.capacity_intents ci,j WHERE ci.namespace=j.realm AND ci.environment=j.environment AND ci.domain=j.domain AND ci.dimension=j.dimension),
 old_policy AS(SELECT p.* FROM public.manifests p,j WHERE p.id::text=j.envelope::jsonb#>>'{policy,id}' AND p.kind='capacity_policy'),
 replacement AS(SELECT c.* FROM public.manifests c,old_policy p WHERE c.kind=p.kind AND c.namespace=p.namespace AND c.name=p.name
  AND NOT p.active AND c.active AND c.version>p.version AND c.spec=p.spec AND c.checksum=p.checksum
  AND NOT EXISTS(SELECT 1 FROM public.manifests later WHERE later.kind=c.kind AND later.namespace=c.namespace AND later.name=c.name AND ((later.active AND later.id<>c.id) OR later.version>c.version))),
 mem AS(SELECT public.superseded_http_maintenance_dispatch_members(job) value),
 pair AS(SELECT public.superseded_http_maintenance_dispatch_canary_pair(job) value),
 epoch AS(SELECT COALESCE(j.realm='dakasa-production' AND j.environment='production' AND j.domain='notify'
  AND j.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND it.intent->>'namespace'=j.realm AND it.intent->>'environment'=j.environment AND it.intent->>'domain'=j.domain AND it.intent->>'dimension'=j.dimension
  AND it.intent->>'policy_id'=p.id::text AND it.intent->>'policy_checksum'=p.checksum
  AND it.intent->>'phase' IN('promoted','reconciled','reconciled_partial')
  AND COALESCE(it.intent->>'lease_owner','')='' AND COALESCE(it.intent->>'lease_executor_id','')=''
  AND COALESCE(jsonb_typeof(it.intent->'lease_expires_at'),'null')='null'
  AND COALESCE(it.intent->>'recovery_only','false')='false' AND COALESCE(it.intent->>'floor_degraded','false')='false'
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['failed_installed_disposal','installed_guest_reconcile','installed_readiness_handoff','original_notify_window','failed_serving_disposal','failed_expansion_terminal_reconcile','failed_unwitnessed_expansion_cleanup_id']) field
   WHERE COALESCE(jsonb_typeof(it.intent->field),'null')<>'null')
  AND it.intent#>>'{decision,action}'='hold' AND it.intent#>'{decision,execution_permitted}'='false'::jsonb
  AND it.intent#>>'{decision,reason}'='down_window_pending'
  AND it.intent#>'{decision,units}'='1'::jsonb AND it.intent#>'{assessment,snapshot,units}'='1'::jsonb
  AND (COALESCE(jsonb_typeof(it.intent->'retirement_forward'),'null')='null' OR EXISTS(
   SELECT 1 FROM public.capacity_guest_retirement_forwards terminal
   WHERE terminal.id::text=it.intent#>>'{retirement_forward,id}' AND terminal.stage='terminal'
   AND terminal.namespace=j.realm AND terminal.environment=j.environment AND terminal.domain=j.domain AND terminal.dimension=j.dimension
   AND terminal.original_record=convert_from(terminal.original_wire,'UTF8')::jsonb AND terminal.record_sha256=encode(sha256(terminal.original_wire),'hex')
   AND terminal.original_record->>'generation'=it.intent->>'generation' AND terminal.original_record->>'fence'=it.intent->>'fencing_token'
   AND terminal.retirement_request_id::text=it.intent#>>'{retirement_forward,retirement_request_id}'
   AND terminal.preregistration_id::text=it.intent#>>'{retirement_forward,preregistration_id}'
   AND it.intent#>>'{retirement_forward,stage}'='terminal'
   AND encode(sha256(decode(terminal.original_record->>'terminal_intent_wire','base64')),'hex')=terminal.original_record->>'terminal_intent_sha256'
   AND convert_from(decode(terminal.original_record->>'terminal_intent_wire','base64'),'UTF8')::jsonb->'retirement_forward'=it.intent->'retirement_forward'
   AND EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings binding JOIN public.capacity_mutation_grants destroy ON destroy.id=binding.destroy_grant_id
    WHERE binding.intent_id=terminal.retirement_request_id AND destroy.state='confirmed' AND destroy.id::text=terminal.original_record->>'destroy_grant_id')))
  AND p.spec#>>'{guest_notify_reconcile_binding,mode}'='original_guest_notify_reconcile_v1'
  AND p.spec->>'environment'=j.environment AND p.spec->>'domain'=j.domain AND p.spec->>'dimension'=j.dimension,false) valid FROM j,it,old_policy p)
SELECT jsonb_build_object('schema','superseded_equivalent_policy_http_maintenance_dispatch_effect_scan_v1',
 'base',public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at),
 'current_members',(SELECT value FROM mem),'current_members_sha256',encode(sha256(convert_to((SELECT value FROM mem)::text,'UTF8')),'hex'),
 'current_member_count',jsonb_array_length((SELECT value FROM mem)),
 'equivalent_policy_valid',EXISTS(SELECT 1 FROM replacement),
 'other_catalog_pins_valid',NOT EXISTS(SELECT 1 FROM(VALUES('workflow',j.envelope::jsonb->'workflow'),('rbac',j.envelope::jsonb->'rbac'),('policy',j.envelope::jsonb->'authorization_policy')) pins(kind,pin)
  WHERE pin IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.manifests m WHERE m.id::text=pin->>'id' AND m.kind=pins.kind AND m.namespace=pin->>'namespace' AND m.name=pin->>'name' AND m.version::text=pin->>'version' AND m.checksum=pin->>'checksum' AND m.active)),
 'stable_epoch_valid',COALESCE((SELECT valid FROM epoch),false),
 'readonly_result_valid',COALESCE((SELECT public.superseded_http_maintenance_dispatch_result_valid(w.result,it.intent->>'generation',it.intent->>'fencing_token')
  AND w.result#>>'{steps,0,metadata,reason}'=it.intent#>>'{decision,reason}'
  AND w.result#>>'{workflow,id}'=j.envelope::jsonb#>>'{workflow,id}' AND w.result#>>'{workflow,kind}'='workflow'
  AND w.result#>>'{workflow,namespace}'=j.envelope::jsonb#>>'{workflow,namespace}' AND w.result#>>'{workflow,name}'=j.envelope::jsonb#>>'{workflow,name}'
  AND w.result#>>'{workflow,version}'=j.envelope::jsonb#>>'{workflow,version}' FROM w,it),false),
 'invalid_canary_pair_rows',CASE WHEN(SELECT value FROM pair) IS NULL THEN 1 ELSE 0 END,
 'current_intent_sha256',(SELECT encode(sha256(convert_to(it.intent::text,'UTF8')),'hex') FROM it),
 'canary_evidence',COALESCE((SELECT value FROM pair),'{}'::jsonb)) FROM j
$$;
-- +goose StatementEnd

-- Exact 12/47/5 key sets distinguish absent/null counters from real zeroes.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_effect_scan_tolerable(p_scan jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE b jsonb=p_scan->'base'; c jsonb=p_scan->'canary_evidence'; member jsonb=p_scan#>'{current_members,0}';
BEGIN
 RETURN (jsonb_typeof(p_scan)='object'
  AND p_scan ?& ARRAY['schema','base','current_members','current_members_sha256','current_member_count','equivalent_policy_valid','other_catalog_pins_valid','stable_epoch_valid','readonly_result_valid','invalid_canary_pair_rows','current_intent_sha256','canary_evidence']
  AND p_scan-ARRAY['schema','base','current_members','current_members_sha256','current_member_count','equivalent_policy_valid','other_catalog_pins_valid','stable_epoch_valid','readonly_result_valid','invalid_canary_pair_rows','current_intent_sha256','canary_evidence']='{}'::jsonb
  AND p_scan->>'schema'='superseded_equivalent_policy_http_maintenance_dispatch_effect_scan_v1'
  AND p_scan->'equivalent_policy_valid'='true'::jsonb AND p_scan->'other_catalog_pins_valid'='true'::jsonb
  AND p_scan->'stable_epoch_valid'='true'::jsonb AND p_scan->'readonly_result_valid'='true'::jsonb
  AND p_scan->'invalid_canary_pair_rows'='0'::jsonb AND p_scan->>'invalid_canary_pair_rows'='0'
  AND jsonb_typeof(p_scan->'current_members')='array' AND jsonb_array_length(p_scan->'current_members')=1
  AND p_scan->'current_member_count'='1'::jsonb AND p_scan->>'current_member_count'='1'
  AND p_scan->>'current_members_sha256'=encode(sha256(convert_to((p_scan->'current_members')::text,'UTF8')),'hex')
  AND p_scan->>'current_intent_sha256' ~ '^[a-f0-9]{64}$'
  AND jsonb_typeof(p_scan->'current_intent_sha256')='string' AND jsonb_typeof(p_scan->'current_members_sha256')='string'
  AND jsonb_typeof(member)='object'
  AND member ?& ARRAY['slot','resource_id','preregistration_id','enrollment_sha256','installation_sha256','slot_sha256','policy_id','policy_checksum']
  AND member-ARRAY['slot','resource_id','preregistration_id','enrollment_sha256','installation_sha256','slot_sha256','policy_id','policy_checksum']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(member) z WHERE z.key<>'slot' AND jsonb_typeof(z.value)<>'string')
  AND member->'slot'='1'::jsonb AND member->>'slot'='1' AND octet_length(member->>'resource_id') BETWEEN 1 AND 256
  AND position(chr(13) in member->>'resource_id')=0 AND position(chr(10) in member->>'resource_id')=0
  AND btrim(member->>'resource_id',U&'\0009\000a\000b\000c\000d\0020\0085\00a0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200a\2028\2029\202f\205f\3000')=member->>'resource_id'
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['preregistration_id','policy_id']) k WHERE COALESCE(member->>k,'') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' OR (member->>k)::uuid='00000000-0000-0000-0000-000000000000'::uuid)
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['enrollment_sha256','installation_sha256','slot_sha256','policy_checksum']) k WHERE COALESCE(member->>k,'') !~ '^[a-f0-9]{64}$')
  AND jsonb_typeof(b)='object' AND b ?& ARRAY['authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','base_schema','caller_possible_sends_since_start','caller_returns_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','clock_skew_margin_seconds','create_witnesses_since_start','enrollments_since_start','executor_activity_updated_since_start','grants_created_or_updated_since_start','installations_since_start','intent_events_since_start','intents_updated_since_start','native_commands_since_start','native_lifetime_archives_since_start','native_lifetimes_updated_since_start','native_pod_checkpoints_since_start','native_poweroff_reads_since_start','notify_window_markers_for_job','observation_refresh_slot_updates','open_undisposed_grants','partial_nativeoff_reads_since_start','partial_nativeoff_reconciliations_since_start','prejournal_refusal_recoveries_since_start','preregistrations_since_start','presend_retirement_recoveries_since_start','provider_quiescence_proved','provider_read_performed','pure_assessment_intent_updates','qualification_native_source_returns_since_start','qualification_probe_challenges_since_start','resource_slots_updated_since_start','retirement_contexts_since_start','retirement_delete_bindings_since_start','retirement_intents_since_start','retirement_native_readbacks_since_start','retirement_original_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','schema','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start'] AND b-ARRAY['authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','base_schema','caller_possible_sends_since_start','caller_returns_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','clock_skew_margin_seconds','create_witnesses_since_start','enrollments_since_start','executor_activity_updated_since_start','grants_created_or_updated_since_start','installations_since_start','intent_events_since_start','intents_updated_since_start','native_commands_since_start','native_lifetime_archives_since_start','native_lifetimes_updated_since_start','native_pod_checkpoints_since_start','native_poweroff_reads_since_start','notify_window_markers_for_job','observation_refresh_slot_updates','open_undisposed_grants','partial_nativeoff_reads_since_start','partial_nativeoff_reconciliations_since_start','prejournal_refusal_recoveries_since_start','preregistrations_since_start','presend_retirement_recoveries_since_start','provider_quiescence_proved','provider_read_performed','pure_assessment_intent_updates','qualification_native_source_returns_since_start','qualification_probe_challenges_since_start','resource_slots_updated_since_start','retirement_contexts_since_start','retirement_delete_bindings_since_start','retirement_intents_since_start','retirement_native_readbacks_since_start','retirement_original_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','schema','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(b) z WHERE z.key NOT IN('schema','base_schema','provider_read_performed','provider_quiescence_proved')
   AND (jsonb_typeof(z.value)<>'number' OR z.value::text !~ '^(0|[1-9][0-9]*)$'))
  AND b->'canary_challenges_since_start'='2'::jsonb AND b->'canary_nonces_since_start'='2'::jsonb
  AND b->'canary_possible_sends_since_start'='2'::jsonb AND b->'canary_returns_since_start'='1'::jsonb
  AND b->'pure_assessment_intent_updates'='1'::jsonb AND b->'observation_refresh_slot_updates'='1'::jsonb
  AND public.finalization_lost_dispatch_effect_scan_tolerable(b||jsonb_build_object('canary_challenges_since_start',0,'canary_nonces_since_start',0,'canary_possible_sends_since_start',0,'canary_returns_since_start',0)) IS TRUE
  AND jsonb_typeof(c)='object' AND c ?& ARRAY['publish_id','read_id','publish_challenge_sha256','read_challenge_sha256','publish_return_sha256']
  AND c-ARRAY['publish_id','read_id','publish_challenge_sha256','read_challenge_sha256','publish_return_sha256']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(c) z WHERE jsonb_typeof(z.value)<>'string')
  AND c->>'publish_id'<>c->>'read_id'
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['publish_id','read_id']) k WHERE COALESCE(c->>k,'') !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' OR (c->>k)::uuid='00000000-0000-0000-0000-000000000000'::uuid)
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['publish_challenge_sha256','read_challenge_sha256','publish_return_sha256']) k WHERE COALESCE(c->>k,'') !~ '^[a-f0-9]{64}$')) IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_admissible(job uuid,process_started_at timestamptz,now_at timestamptz)
RETURNS boolean LANGUAGE sql STABLE SET timezone='UTC' AS $$
SELECT COALESCE(j.id<>'00000000-0000-0000-0000-000000000000'::uuid AND j.run_id<>'00000000-0000-0000-0000-000000000000'::uuid AND j.lease_owner<>'00000000-0000-0000-0000-000000000000'::uuid AND j.fencing_token>0
 AND j.realm='dakasa-production' AND j.protocol='capacity_dispatch_prestart_v1' AND j.state='unknown'
 AND j.started_at IS NOT NULL AND j.returned_at IS NOT NULL AND j.lease_expires_at IS NOT NULL AND j.lease_owner IS NOT NULL
 AND j.return_status='failed' AND j.return_error='capacity dispatch original workflow returned error'
 AND j.finalization_error IS NULL AND j.finalization_ack_at IS NULL
 AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0
 AND j.started_at<j.returned_at AND j.returned_at<j.lease_expires_at
 AND now_at>=j.lease_expires_at+interval '15 minutes' AND process_started_at>j.lease_expires_at AND process_started_at<=now_at
 AND w.status='failed' AND w.error=j.return_error AND w.started_at=j.started_at AND w.finished_at=j.returned_at
 AND j.envelope_sha256=encode(sha256(convert_to(j.envelope,'UTF8')),'hex')
 AND w.workflow_namespace=j.envelope::jsonb#>>'{workflow,namespace}' AND w.workflow_name=j.envelope::jsonb#>>'{workflow,name}'
 AND w.workflow_version::text=j.envelope::jsonb#>>'{workflow,version}'
 AND(w.workflow_id IS NULL OR w.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}')
 AND w.inputs=j.envelope::jsonb->'inputs' AND w.metadata=j.envelope::jsonb->'metadata'
 AND EXISTS(SELECT 1 FROM public.manifests p WHERE p.id::text=j.envelope::jsonb#>>'{policy,id}' AND p.kind='capacity_policy' AND NOT p.active
  AND p.namespace=j.envelope::jsonb#>>'{policy,namespace}' AND p.name=j.envelope::jsonb#>>'{policy,name}'
  AND p.version::text=j.envelope::jsonb#>>'{policy,version}' AND p.checksum=j.envelope::jsonb#>>'{policy,checksum}')
 AND public.superseded_http_maintenance_dispatch_effect_scan_tolerable(public.superseded_http_maintenance_dispatch_effect_scan(j.id)),false)
FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=job
$$;
-- +goose StatementEnd

CREATE TABLE IF NOT EXISTS public.capacity_dispatch_superseded_http_maintenance_dispositions (
 id uuid PRIMARY KEY,
 job_id uuid NOT NULL UNIQUE CHECK(job_id<>'00000000-0000-0000-0000-000000000000'::uuid) REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE CHECK(run_id<>'00000000-0000-0000-0000-000000000000'::uuid) REFERENCES public.workflow_runs(id),
 original_dispatch_sha256 text NOT NULL CHECK(original_dispatch_sha256 ~ '^[a-f0-9]{64}$'),
 original_dispatch_updated_at timestamptz NOT NULL,
 original_run_sha256 text NOT NULL CHECK(original_run_sha256 ~ '^[a-f0-9]{64}$'),
 original_returned_at timestamptz NOT NULL,
 current_members_sha256 text NOT NULL CHECK(current_members_sha256 ~ '^[a-f0-9]{64}$'),
 executor_barrier text NOT NULL CHECK(executor_barrier='disposing_core_process_started_after_lease_expiry_v1'),
 disposing_core_process_started_at timestamptz NOT NULL,
 disposing_core_hostname text NOT NULL CHECK(disposing_core_hostname ~ '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'),
 disposing_core_pid integer NOT NULL CHECK(disposing_core_pid>0),
 disposing_core_source_commit text NOT NULL CHECK(disposing_core_source_commit ~ '^[a-f0-9]{40}$'),
 issuer text NOT NULL CHECK(issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
 reason text NOT NULL CHECK(reason='superseded_equivalent_policy_http_maintenance_dispatch_disposed'),
 historical_return text NOT NULL CHECK(historical_return='unknown'),
 recorded_at timestamptz NOT NULL,
 provider_mutation_evidence jsonb NOT NULL CHECK(public.superseded_http_maintenance_dispatch_effect_scan_tolerable(provider_mutation_evidence)),
 original_policy_id uuid NOT NULL CHECK(original_policy_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 original_policy_version integer NOT NULL CHECK(original_policy_version>0),
 original_policy_checksum text NOT NULL CHECK(original_policy_checksum ~ '^[a-f0-9]{64}$'),
 replacement_policy_id uuid NOT NULL CHECK(replacement_policy_id<>original_policy_id AND replacement_policy_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 replacement_policy_version integer NOT NULL CHECK(replacement_policy_version>original_policy_version),
 replacement_policy_checksum text NOT NULL CHECK(replacement_policy_checksum=original_policy_checksum),
 original_dispatch_wire bytea NOT NULL CHECK(octet_length(original_dispatch_wire) BETWEEN 1 AND 1048576),
 original_run_wire bytea NOT NULL CHECK(octet_length(original_run_wire) BETWEEN 1 AND 8388608),
 original_policy_wire bytea NOT NULL CHECK(octet_length(original_policy_wire) BETWEEN 1 AND 1048576),
 replacement_policy_wire bytea NOT NULL CHECK(octet_length(replacement_policy_wire) BETWEEN 1 AND 1048576),
 current_intent_wire bytea NOT NULL CHECK(octet_length(current_intent_wire) BETWEEN 1 AND 1048576),
 current_members_wire bytea NOT NULL CHECK(octet_length(current_members_wire) BETWEEN 1 AND 1048576),
 canary_evidence_wire bytea NOT NULL CHECK(octet_length(canary_evidence_wire) BETWEEN 1 AND 65536)
);

-- Historical authentication is intentionally PURE over retained snapshots.
-- Later active policy IDs, observations and generation changes are irrelevant.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_receipt_valid(d public.capacity_dispatch_superseded_http_maintenance_dispositions)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET timezone='UTC' AS $$
DECLARE original_job jsonb; original_run jsonb; old_policy jsonb; replacement jsonb; it jsonb; members jsonb; evidence jsonb;
BEGIN
 original_job=convert_from(d.original_dispatch_wire,'UTF8')::jsonb;
 original_run=convert_from(d.original_run_wire,'UTF8')::jsonb;
 old_policy=convert_from(d.original_policy_wire,'UTF8')::jsonb;
 replacement=convert_from(d.replacement_policy_wire,'UTF8')::jsonb;
 it=convert_from(d.current_intent_wire,'UTF8')::jsonb;
 members=convert_from(d.current_members_wire,'UTF8')::jsonb;
 evidence=convert_from(d.canary_evidence_wire,'UTF8')::jsonb;
 RETURN (public.superseded_http_maintenance_dispatch_effect_scan_tolerable(d.provider_mutation_evidence)
  AND d.id<>'00000000-0000-0000-0000-000000000000'::uuid
  AND d.original_dispatch_sha256=encode(sha256(d.original_dispatch_wire),'hex')
  AND d.original_run_sha256=encode(sha256(d.original_run_wire),'hex')
  AND d.current_members_sha256=encode(sha256(d.current_members_wire),'hex')
  AND d.provider_mutation_evidence->>'current_intent_sha256'=encode(sha256(d.current_intent_wire),'hex')
  AND members=d.provider_mutation_evidence->'current_members' AND evidence=d.provider_mutation_evidence->'canary_evidence'
  AND d.current_members_sha256=d.provider_mutation_evidence->>'current_members_sha256'
  AND original_job->>'id'=d.job_id::text AND original_job->>'run_id'=d.run_id::text
  AND original_job->>'protocol'='capacity_dispatch_prestart_v1' AND original_job->>'state'='unknown'
  AND original_job->>'return_status'='failed' AND original_job->>'return_error'='capacity dispatch original workflow returned error'
  AND original_job->'finalization_error'='null'::jsonb AND original_job->'finalization_ack_at'='null'::jsonb
  AND (original_job->>'updated_at')::timestamptz=d.original_dispatch_updated_at
  AND (original_job->>'returned_at')::timestamptz=d.original_returned_at
  AND (original_job->>'started_at')::timestamptz<d.original_returned_at
  AND d.original_returned_at<(original_job->>'lease_expires_at')::timestamptz
  AND d.original_dispatch_updated_at<=d.recorded_at
  AND d.recorded_at>=(original_job->>'lease_expires_at')::timestamptz+interval '15 minutes'
  AND d.disposing_core_process_started_at>(original_job->>'lease_expires_at')::timestamptz
  AND d.disposing_core_process_started_at<=d.recorded_at
  AND original_run->>'id'=d.run_id::text AND original_run->>'status'='failed'
  AND original_run->>'error'=original_job->>'return_error'
  AND (original_run->>'started_at')::timestamptz=(original_job->>'started_at')::timestamptz
  AND (original_run->>'finished_at')::timestamptz=d.original_returned_at
  AND original_run->'inputs'=(original_job->>'envelope')::jsonb->'inputs'
  AND original_run->'metadata'=(original_job->>'envelope')::jsonb->'metadata'
  AND original_job->>'envelope_sha256'=encode(sha256(convert_to(original_job->>'envelope','UTF8')),'hex')
  AND original_job->>'realm'='dakasa-production' AND original_job->>'environment'='production' AND original_job->>'domain'='notify'
  AND original_job->>'dimension' IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND old_policy->>'id'=d.original_policy_id::text AND old_policy->>'version'=d.original_policy_version::text
  AND old_policy->>'checksum'=d.original_policy_checksum AND old_policy->>'kind'='capacity_policy' AND old_policy->'active'='false'::jsonb
  AND replacement->>'id'=d.replacement_policy_id::text AND replacement->>'version'=d.replacement_policy_version::text
  AND replacement->>'checksum'=d.replacement_policy_checksum AND replacement->>'kind'=old_policy->>'kind' AND replacement->'active'='true'::jsonb
  AND (replacement->>'namespace',replacement->>'name')=(old_policy->>'namespace',old_policy->>'name')
  AND replacement->'spec'=old_policy->'spec'
  AND d.replacement_policy_id<>d.original_policy_id AND d.replacement_policy_version>d.original_policy_version
  AND d.original_policy_checksum=d.replacement_policy_checksum
  AND old_policy->>'id'=(original_job->>'envelope')::jsonb#>>'{policy,id}'
  AND old_policy->>'version'=(original_job->>'envelope')::jsonb#>>'{policy,version}'
  AND old_policy->>'checksum'=(original_job->>'envelope')::jsonb#>>'{policy,checksum}'
  AND it->>'policy_id'=d.original_policy_id::text AND it->>'policy_checksum'=d.original_policy_checksum
  AND it->>'namespace'=original_job->>'realm' AND it->>'environment'=original_job->>'environment'
  AND it->>'domain'=original_job->>'domain' AND it->>'dimension'=original_job->>'dimension'
  AND d.reason='superseded_equivalent_policy_http_maintenance_dispatch_disposed' AND d.historical_return='unknown'
  AND d.executor_barrier='disposing_core_process_started_after_lease_expiry_v1') IS TRUE;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_superseded_http_maintenance_disposition_insert() RETURNS trigger
LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE original_job public.capacity_dispatch_jobs; original_run public.workflow_runs; old_policy public.manifests;
 replacement public.manifests; current_intent jsonb; scan jsonb;
BEGIN
 SELECT * INTO STRICT original_job FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[original_job.realm,original_job.environment,original_job.domain,original_job.dimension]) part
  WHERE part IS NULL OR part !~ '^[ -~]+$' OR part ~ '[<>&]')
 THEN RAISE EXCEPTION 'superseded HTTP disposition requires exact scope encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[original_job.realm,original_job.environment,original_job.domain,original_job.dimension])::text,0));
 SELECT * INTO STRICT original_job FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 PERFORM id FROM public.manifests WHERE id::text IN(original_job.envelope::jsonb#>>'{policy,id}',original_job.envelope::jsonb#>>'{workflow,id}',original_job.envelope::jsonb#>>'{rbac,id}',original_job.envelope::jsonb#>>'{authorization_policy,id}',NEW.replacement_policy_id::text) ORDER BY id FOR SHARE;
 PERFORM id FROM public.manifests WHERE kind='capacity_policy' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id::text=original_job.envelope::jsonb#>>'{policy,id}') ORDER BY version,id FOR SHARE;
 SELECT intent INTO STRICT current_intent FROM public.capacity_intents WHERE namespace=original_job.realm AND environment=original_job.environment AND domain=original_job.domain AND dimension=original_job.dimension FOR SHARE;
 PERFORM slot FROM public.capacity_resource_slots WHERE namespace=original_job.realm AND environment=original_job.environment AND domain=original_job.domain AND dimension=original_job.dimension ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE;
 PERFORM id FROM public.capacity_mutation_grants WHERE namespace=original_job.realm AND environment=original_job.environment AND domain=original_job.domain AND dimension=original_job.dimension ORDER BY id FOR SHARE;
 SELECT * INTO STRICT original_run FROM public.workflow_runs WHERE id=original_job.run_id FOR UPDATE;
 SELECT * INTO STRICT old_policy FROM public.manifests WHERE id=NEW.original_policy_id;
 SELECT * INTO STRICT replacement FROM public.manifests WHERE id=NEW.replacement_policy_id;
 IF public.superseded_http_maintenance_dispatch_admissible(original_job.id,NEW.disposing_core_process_started_at,NEW.recorded_at) IS DISTINCT FROM true
  OR NEW.run_id IS DISTINCT FROM original_job.run_id OR NEW.original_returned_at IS DISTINCT FROM original_job.returned_at
  OR NEW.original_dispatch_updated_at IS DISTINCT FROM original_job.updated_at
  OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
  OR old_policy.id::text IS DISTINCT FROM original_job.envelope::jsonb#>>'{policy,id}'
  OR old_policy.version IS DISTINCT FROM NEW.original_policy_version OR old_policy.checksum IS DISTINCT FROM NEW.original_policy_checksum
  OR replacement.version IS DISTINCT FROM NEW.replacement_policy_version OR replacement.checksum IS DISTINCT FROM NEW.replacement_policy_checksum
  OR replacement.kind IS DISTINCT FROM old_policy.kind OR (replacement.namespace,replacement.name) IS DISTINCT FROM(old_policy.namespace,old_policy.name)
  OR old_policy.active OR NOT replacement.active OR replacement.version<=old_policy.version
  OR EXISTS(SELECT 1 FROM public.manifests later WHERE later.kind=replacement.kind AND later.namespace=replacement.namespace AND later.name=replacement.name AND ((later.active AND later.id<>replacement.id) OR later.version>replacement.version))
  OR replacement.spec IS DISTINCT FROM old_policy.spec OR replacement.checksum IS DISTINCT FROM old_policy.checksum
  OR EXISTS(SELECT 1 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions WHERE job_id=original_job.id OR run_id=original_job.run_id)
 THEN RAISE EXCEPTION 'superseded HTTP disposition requires exact expired failed original and equivalent latest active policy'; END IF;
 scan=public.superseded_http_maintenance_dispatch_effect_scan(original_job.id);
 IF NEW.provider_mutation_evidence IS DISTINCT FROM scan OR public.superseded_http_maintenance_dispatch_effect_scan_tolerable(scan) IS DISTINCT FROM true
  OR NEW.current_members_sha256 IS DISTINCT FROM scan->>'current_members_sha256'
  OR NEW.original_dispatch_wire IS DISTINCT FROM convert_to(to_jsonb(original_job)::text,'UTF8')
  OR NEW.original_run_wire IS DISTINCT FROM convert_to(to_jsonb(original_run)::text,'UTF8')
  OR NEW.original_policy_wire IS DISTINCT FROM convert_to(to_jsonb(old_policy)::text,'UTF8')
  OR NEW.replacement_policy_wire IS DISTINCT FROM convert_to(to_jsonb(replacement)::text,'UTF8')
  OR NEW.current_intent_wire IS DISTINCT FROM convert_to(current_intent::text,'UTF8')
  OR NEW.current_members_wire IS DISTINCT FROM convert_to((scan->'current_members')::text,'UTF8')
  OR NEW.canary_evidence_wire IS DISTINCT FROM convert_to((scan->'canary_evidence')::text,'UTF8')
  OR public.superseded_http_maintenance_dispatch_receipt_valid(NEW) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'superseded HTTP disposition requires exact whole original snapshots and closed effect scan'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_superseded_http_maintenance_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE receipt public.capacity_dispatch_superseded_http_maintenance_dispositions;
BEGIN
 IF old_row.state='superseded_http_maintenance_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'superseded HTTP maintenance terminal is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'unknown' OR new_row.state<>'superseded_http_maintenance_disposed' OR old_row.finalization_ack_at IS NOT NULL
  OR(to_jsonb(new_row)-ARRAY['state','updated_at']) IS DISTINCT FROM(to_jsonb(old_row)-ARRAY['state','updated_at'])
 THEN RAISE EXCEPTION 'superseded HTTP maintenance preserves every original dispatch field'; END IF;
 SELECT * INTO STRICT receipt FROM public.capacity_dispatch_superseded_http_maintenance_dispositions WHERE job_id=old_row.id AND run_id=old_row.run_id;
 IF receipt.original_dispatch_wire IS DISTINCT FROM convert_to(to_jsonb(old_row)::text,'UTF8')
  OR new_row.updated_at IS DISTINCT FROM receipt.recorded_at
  OR public.superseded_http_maintenance_dispatch_receipt_valid(receipt) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'superseded HTTP maintenance needs same transaction authenticated receipt'; END IF;
 RETURN new_row;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_superseded_http_maintenance_job_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='superseded_http_maintenance_disposed' THEN RAISE EXCEPTION 'superseded HTTP maintenance requires retained UNKNOWN original'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.immutable_superseded_http_maintenance_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'superseded HTTP maintenance disposition is immutable'; END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_superseded_http_maintenance_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions WHERE run_id=OLD.id) AND(TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'superseded HTTP maintenance original workflow is immutable'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- Same existing physical-dimension scope lock as every genuine canary writer.
-- Taking it BEFORE testing receipt existence closes an INSERT/FK wait race;
-- no parent-row lock upgrade or global lock is introduced.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_superseded_http_maintenance_canary_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE realm text; environment_name text; domain_name text; dimension_name text;
BEGIN
 SELECT grant_row.namespace,grant_row.environment,grant_row.domain,grant_row.dimension
 INTO realm,environment_name,domain_name,dimension_name
 FROM public.capacity_guest_notify_canary_challenges cc
 JOIN public.capacity_vm_provisioning_preregistrations pr ON pr.id=cc.preregistration_id
 JOIN public.capacity_mutation_grants grant_row ON grant_row.id=pr.create_grant_id WHERE cc.id=NEW.challenge_id;
 -- Preserve the existing FK23503 refusal for missing challenge rows.
 IF NOT FOUND THEN RETURN NEW; END IF;
 IF (realm='dakasa-production' AND environment_name='production' AND domain_name='notify'
  AND dimension_name IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')) IS NOT TRUE THEN RETURN NEW; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[realm,environment_name,domain_name,dimension_name]) part
  WHERE part IS NULL OR part !~ '^[ -~]+$' OR part ~ '[<>&]')
 THEN RAISE EXCEPTION 'superseded HTTP canary archive requires exact scope encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[realm,environment_name,domain_name,dimension_name])::text,0));
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions receipt
  WHERE receipt.provider_mutation_evidence#>>'{canary_evidence,publish_id}'=NEW.challenge_id::text
     OR receipt.provider_mutation_evidence#>>'{canary_evidence,read_id}'=NEW.challenge_id::text)
 THEN RAISE EXCEPTION 'superseded HTTP maintenance canary originals are permanently closed'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.require_superseded_http_maintenance_links() RETURNS trigger
LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE original_job public.capacity_dispatch_jobs; original_run public.workflow_runs; scan jsonb;
BEGIN
 SELECT * INTO STRICT original_job FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT * INTO STRICT original_run FROM public.workflow_runs WHERE id=NEW.run_id;
 scan=public.superseded_http_maintenance_dispatch_effect_scan(NEW.job_id);
 IF original_job.state IS DISTINCT FROM 'superseded_http_maintenance_disposed' OR original_job.run_id IS DISTINCT FROM NEW.run_id
  OR original_job.updated_at IS DISTINCT FROM NEW.recorded_at OR original_job.returned_at IS DISTINCT FROM NEW.original_returned_at
  OR original_job.finalization_ack_at IS NOT NULL
  OR num_nonnulls(original_job.failed_original_disposition_id,original_job.native_denied_disposition_id,original_job.enrolled_failed_disposition_id,original_job.abandoned_disposition_id,original_job.finalization_lost_disposition_id,original_job.unknown_maintenance_disposition_id)<>0
  OR NEW.original_dispatch_wire IS DISTINCT FROM convert_to((to_jsonb(original_job)||jsonb_build_object('state','unknown','updated_at',NEW.original_dispatch_updated_at))::text,'UTF8')
  OR NEW.original_run_wire IS DISTINCT FROM convert_to(to_jsonb(original_run)::text,'UTF8')
  OR NEW.provider_mutation_evidence IS DISTINCT FROM scan
  OR public.superseded_http_maintenance_dispatch_receipt_valid(NEW) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'superseded HTTP receipt requires terminal job and unchanged originals/pair in same commit'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd

-- Only one typed prefix is added. The entire migration99 guard body below
-- that prefix, and every older terminal branch, remains byte-identical.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state='superseded_http_maintenance_disposed' OR NEW.state='superseded_http_maintenance_disposed' THEN
        RETURN public.check_superseded_http_maintenance_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='preaction_plan_disposed' OR NEW.state='preaction_plan_disposed' THEN
        RETURN public.check_preaction_failed_plan_transition(OLD,NEW);
    END IF;
    IF OLD.state='installed_timeout_disposed' OR NEW.state='installed_timeout_disposed' THEN
        RETURN public.check_installed_provision_timeout_transition(OLD,NEW);
    END IF;
    IF OLD.state='http_maintenance_disposed' OR NEW.state='http_maintenance_disposed' THEN
        RETURN public.check_http_maintenance_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='unknown_maintenance_disposed' OR NEW.state='unknown_maintenance_disposed'
       OR OLD.unknown_maintenance_disposition_id IS NOT NULL OR NEW.unknown_maintenance_disposition_id IS NOT NULL THEN
        RETURN public.check_unknown_maintenance_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='finalization_lost_disposed' OR NEW.state='finalization_lost_disposed'
       OR OLD.finalization_lost_disposition_id IS NOT NULL OR NEW.finalization_lost_disposition_id IS NOT NULL THEN
        RETURN public.check_finalization_lost_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='abandoned_disposed' OR NEW.state='abandoned_disposed'
       OR OLD.abandoned_disposition_id IS NOT NULL OR NEW.abandoned_disposition_id IS NOT NULL THEN
        RETURN public.check_abandoned_dispatch_transition(OLD,NEW);
    END IF;
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

ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v11_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v11_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v12_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v12_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v12_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed','superseded_http_maintenance_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v12_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed','superseded_http_maintenance_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.superseded_http_maintenance_dispatch_terminal_valid(job uuid)
RETURNS boolean LANGUAGE sql STABLE SET timezone='UTC' AS $$
SELECT COALESCE(j.state='superseded_http_maintenance_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
 AND public.superseded_http_maintenance_dispatch_receipt_valid(d) IS TRUE
 AND d.original_dispatch_wire=convert_to((to_jsonb(j)||jsonb_build_object('state','unknown','updated_at',d.original_dispatch_updated_at))::text,'UTF8')
 AND d.original_run_wire=convert_to(to_jsonb(w)::text,'UTF8'),false)
FROM public.capacity_dispatch_superseded_http_maintenance_dispositions d
JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id
JOIN public.workflow_runs w ON w.id=d.run_id WHERE j.id=job
$$;
-- +goose StatementEnd

-- The stale raw-state list is deliberately untouched. Only a retained typed
-- receipt and exact current originals make the new terminal quiet.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (SELECT count(*)=1 FROM public.capacity_dispatch_jobs j WHERE j.run_id=own AND j.state='started' AND j.started_at IS NOT NULL AND j.returned_at IS NULL AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND (j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' OR (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}')=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed') OR (j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL)))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='installed_timeout_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.installed_provision_timeout_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='preaction_plan_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.preaction_failed_plan_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire,d.evidence_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions d
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND public.superseded_http_maintenance_dispatch_terminal_valid(j.id) IS TRUE))
 AND NOT EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.id<>own AND (w.workflow_id IN(SELECT id FROM public.manifests WHERE kind='workflow' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(r#>>'{original,Request,intent,tuple,integration_instance_id}',r#>>'{original,Request,intent,tuple,scope_checksum}',r#>>'{original,Request,intent,tuple,profile}') AND g.state IN('issued','redeemed','settled','compensating') AND g.id::text<>r->>'destroy_grant_id')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(r#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
$$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_superseded_http_maintenance_dispositions'::regclass AND tgname='superseded_http_maintenance_insert') THEN
  CREATE TRIGGER superseded_http_maintenance_insert BEFORE INSERT ON public.capacity_dispatch_superseded_http_maintenance_dispositions FOR EACH ROW EXECUTE FUNCTION public.guard_superseded_http_maintenance_disposition_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_superseded_http_maintenance_dispositions'::regclass AND tgname='superseded_http_maintenance_immutable') THEN
  CREATE TRIGGER superseded_http_maintenance_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_superseded_http_maintenance_dispositions FOR EACH ROW EXECUTE FUNCTION public.immutable_superseded_http_maintenance_disposition();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_jobs'::regclass AND tgname='superseded_http_maintenance_job_insert') THEN
  CREATE TRIGGER superseded_http_maintenance_job_insert BEFORE INSERT ON public.capacity_dispatch_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_superseded_http_maintenance_job_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.workflow_runs'::regclass AND tgname='superseded_http_maintenance_workflow_immutable') THEN
  CREATE TRIGGER superseded_http_maintenance_workflow_immutable BEFORE UPDATE OR DELETE ON public.workflow_runs FOR EACH ROW EXECUTE FUNCTION public.guard_superseded_http_maintenance_workflow();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_superseded_http_maintenance_dispositions'::regclass AND tgname='superseded_http_maintenance_complete_links') THEN
  CREATE CONSTRAINT TRIGGER superseded_http_maintenance_complete_links AFTER INSERT ON public.capacity_dispatch_superseded_http_maintenance_dispositions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_superseded_http_maintenance_links();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_guest_notify_canary_nonces'::regclass AND tgname='superseded_http_maintenance_nonce_closed') THEN
  CREATE TRIGGER superseded_http_maintenance_nonce_closed BEFORE INSERT ON public.capacity_guest_notify_canary_nonces FOR EACH ROW EXECUTE FUNCTION public.guard_superseded_http_maintenance_canary_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_guest_notify_canary_sends'::regclass AND tgname='superseded_http_maintenance_send_closed') THEN
  CREATE TRIGGER superseded_http_maintenance_send_closed BEFORE INSERT ON public.capacity_guest_notify_canary_sends FOR EACH ROW EXECUTE FUNCTION public.guard_superseded_http_maintenance_canary_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_guest_notify_canary_returns'::regclass AND tgname='superseded_http_maintenance_return_closed') THEN
  CREATE TRIGGER superseded_http_maintenance_return_closed BEFORE INSERT ON public.capacity_guest_notify_canary_returns FOR EACH ROW EXECUTE FUNCTION public.guard_superseded_http_maintenance_canary_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose Down
-- Empty-database reversal only. An original disposition is retained forever.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions) OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE state='superseded_http_maintenance_disposed')
 THEN RAISE EXCEPTION 'superseded HTTP maintenance is a retained boundary'; END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (SELECT count(*)=1 FROM public.capacity_dispatch_jobs j WHERE j.run_id=own AND j.state='started' AND j.started_at IS NOT NULL AND j.returned_at IS NULL AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND (j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' OR (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}')=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed') OR (j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL)))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='installed_timeout_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.installed_provision_timeout_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='preaction_plan_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.preaction_failed_plan_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire,d.evidence_wire) IS TRUE))
 AND NOT EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.id<>own AND (w.workflow_id IN(SELECT id FROM public.manifests WHERE kind='workflow' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(r#>>'{original,Request,intent,tuple,integration_instance_id}',r#>>'{original,Request,intent,tuple,scope_checksum}',r#>>'{original,Request,intent,tuple,profile}') AND g.state IN('issued','redeemed','settled','compensating') AND g.id::text<>r->>'destroy_grant_id')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(r#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state='preaction_plan_disposed' OR NEW.state='preaction_plan_disposed' THEN
        RETURN public.check_preaction_failed_plan_transition(OLD,NEW);
    END IF;
    IF OLD.state='installed_timeout_disposed' OR NEW.state='installed_timeout_disposed' THEN
        RETURN public.check_installed_provision_timeout_transition(OLD,NEW);
    END IF;
    IF OLD.state='http_maintenance_disposed' OR NEW.state='http_maintenance_disposed' THEN
        RETURN public.check_http_maintenance_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='unknown_maintenance_disposed' OR NEW.state='unknown_maintenance_disposed'
       OR OLD.unknown_maintenance_disposition_id IS NOT NULL OR NEW.unknown_maintenance_disposition_id IS NOT NULL THEN
        RETURN public.check_unknown_maintenance_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='finalization_lost_disposed' OR NEW.state='finalization_lost_disposed'
       OR OLD.finalization_lost_disposition_id IS NOT NULL OR NEW.finalization_lost_disposition_id IS NOT NULL THEN
        RETURN public.check_finalization_lost_dispatch_transition(OLD,NEW);
    END IF;
    IF OLD.state='abandoned_disposed' OR NEW.state='abandoned_disposed'
       OR OLD.abandoned_disposition_id IS NOT NULL OR NEW.abandoned_disposition_id IS NOT NULL THEN
        RETURN public.check_abandoned_dispatch_transition(OLD,NEW);
    END IF;
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

ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v12_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v12_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v11_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v11_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));

DROP TRIGGER IF EXISTS superseded_http_maintenance_return_closed ON public.capacity_guest_notify_canary_returns;
DROP TRIGGER IF EXISTS superseded_http_maintenance_send_closed ON public.capacity_guest_notify_canary_sends;
DROP TRIGGER IF EXISTS superseded_http_maintenance_nonce_closed ON public.capacity_guest_notify_canary_nonces;
DROP TRIGGER IF EXISTS superseded_http_maintenance_complete_links ON public.capacity_dispatch_superseded_http_maintenance_dispositions;
DROP TRIGGER IF EXISTS superseded_http_maintenance_workflow_immutable ON public.workflow_runs;
DROP TRIGGER IF EXISTS superseded_http_maintenance_job_insert ON public.capacity_dispatch_jobs;
DROP TRIGGER IF EXISTS superseded_http_maintenance_immutable ON public.capacity_dispatch_superseded_http_maintenance_dispositions;
DROP TRIGGER IF EXISTS superseded_http_maintenance_insert ON public.capacity_dispatch_superseded_http_maintenance_dispositions;
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_terminal_valid(uuid);
DROP FUNCTION IF EXISTS public.require_superseded_http_maintenance_links();
DROP FUNCTION IF EXISTS public.guard_superseded_http_maintenance_canary_insert();
DROP FUNCTION IF EXISTS public.guard_superseded_http_maintenance_workflow();
DROP FUNCTION IF EXISTS public.immutable_superseded_http_maintenance_disposition();
DROP FUNCTION IF EXISTS public.guard_superseded_http_maintenance_job_insert();
DROP FUNCTION IF EXISTS public.check_superseded_http_maintenance_dispatch_transition(public.capacity_dispatch_jobs,public.capacity_dispatch_jobs);
DROP FUNCTION IF EXISTS public.guard_superseded_http_maintenance_disposition_insert();
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_receipt_valid(public.capacity_dispatch_superseded_http_maintenance_dispositions);
DROP TABLE IF EXISTS public.capacity_dispatch_superseded_http_maintenance_dispositions;
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_admissible(uuid,timestamptz,timestamptz);
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_effect_scan_tolerable(jsonb);
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_effect_scan(uuid);
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_canary_pair(uuid);
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_members(uuid);
DROP FUNCTION IF EXISTS public.superseded_http_maintenance_dispatch_result_valid(jsonb,text,text);
