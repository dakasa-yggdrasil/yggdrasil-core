-- +goose Up
-- ADR-0103: a separate recorded context-refused HTTP publication disposition.
-- No old job column, original ACK, workflow/canary rewrite, replay or native effect.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.http_maintenance_dispatch_result_valid(result jsonb,generation text,fence text)
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
 AND result#>>'{steps,3,metadata,original_guest_notify_refusal_stage}' ='original_HTTP_or_return',false)
$$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.http_maintenance_dispatch_policy_projection(input_spec jsonb)
RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
WITH a AS(SELECT input_spec s,input_spec->'guest_retirement_binding' b,input_spec->'guest_notify_canary_binding' n),
 picked AS(SELECT a.*,
  (SELECT jsonb_agg(v) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s->'mutation_bindings')='array' THEN s->'mutation_bindings' ELSE '[]'::jsonb END) v WHERE v->>'name'=b->>'mutation_binding_name') ms,
  (SELECT jsonb_agg(v) FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s->'profiles')='array' THEN s->'profiles' ELSE '[]'::jsonb END) v WHERE v->>'name'=b#>>'{profile_manifest,profile}') ps FROM a),
 x AS(SELECT *,ms->0 m,ps->0 p FROM picked)
SELECT CASE WHEN COALESCE(jsonb_typeof(s)='object' AND jsonb_typeof(b)='object' AND jsonb_typeof(n)='object'
 AND b->>'mode'='original_guest_retirement_v1' AND b->>'evidence_class'='owned_provisioner_original'
 AND b#>>'{profile_manifest,schema}'='original_guest_protected_profile_v1'
 AND b#>>'{profile_manifest,coverage_class}'='complete_production_roster'
 AND n->>'mode'='original_guest_notify_canary_v1'
 AND jsonb_typeof(s->'mutation_bindings')='array' AND jsonb_typeof(s->'profiles')='array'
 AND jsonb_array_length(ms)=1 AND jsonb_array_length(ps)=1
 AND jsonb_typeof(s->'workflow')='object' AND s#>>'{workflow,namespace}'<>'' AND s#>>'{workflow,name}'<>''
 AND s->>'environment'='production' AND s->>'domain'='notify'
 AND s->>'dimension' IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
 AND jsonb_typeof(b->'max_evidence_age_seconds')='number' AND b->'max_evidence_age_seconds'>='1'::jsonb AND b->'max_evidence_age_seconds'<='30'::jsonb
 AND jsonb_typeof(s->'max_evidence_age_seconds')='number' AND b->'max_evidence_age_seconds'<=s->'max_evidence_age_seconds'
 AND jsonb_typeof(n->'minimum_publication_interval_seconds')='number' AND n->'minimum_publication_interval_seconds'>='5'::jsonb
 AND n->'minimum_publication_interval_seconds'<='3600'::jsonb AND n->'minimum_publication_interval_seconds'<=s->'max_evidence_age_seconds'
 AND jsonb_typeof(n->'maximum_publications_per_hour')='number' AND n->'maximum_publications_per_hour'>='1'::jsonb AND n->'maximum_publications_per_hour'<='120'::jsonb
 AND n->'recipient_count'='2'::jsonb
 AND jsonb_array_length(CASE WHEN jsonb_typeof(n->'table_oids')='array' THEN n->'table_oids' ELSE '[]'::jsonb END)=4
 AND jsonb_array_length(CASE WHEN jsonb_typeof(b->'members')='array' THEN b->'members' ELSE '[]'::jsonb END) BETWEEN 1 AND 8
 AND jsonb_array_length(CASE WHEN jsonb_typeof(b#>'{profile_manifest,writers}')='array' THEN b#>'{profile_manifest,writers}' ELSE '[]'::jsonb END)=1
 AND p->>'provider' IN('aws','hetzner') AND p->>'name'=m->>'profile_name'
 AND b#>>'{profile_manifest,mutation_binding}'=m->>'name'
 AND b#>>'{profile_manifest,actor_source_commit}'=b->>'guest_source_commit'
 AND b#>>'{profile_manifest,protected_cgroup}'='/sys/fs/cgroup/yggdrasil-protected-writers'
 AND n->>'writer_id'=b#>>'{profile_manifest,writers,0,id}' AND n->>'notify_source_commit'=b#>>'{profile_manifest,writers,0,source_commit}'
 AND jsonb_typeof(b#>'{profile_manifest,notify_canary_topology}')='object'
 AND b#>>'{profile_manifest,notify_canary_topology,binding}'=m->>'name'
 AND jsonb_array_length(CASE WHEN jsonb_typeof(m->'slots')='array' THEN m->'slots' ELSE '[]'::jsonb END)>=jsonb_array_length(CASE WHEN jsonb_typeof(b->'members')='array' THEN b->'members' ELSE '[]'::jsonb END)
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['provisioner_source_commit','guest_source_commit','core_authority_source_commit']) k WHERE COALESCE(b->>k,'') !~ '^[a-f0-9]{40}$')
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['provisioner_public_key','enrollment_issuer_public_key','enrollment_signing_key_ref','intent_signing_key_ref','profile_manifest_sha256']) k WHERE jsonb_typeof(b->k) IS DISTINCT FROM 'string' OR COALESCE(b->>k,'')='')
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['production_catalog_sha256','bootstrap_owner_binary_sha256','bootstrap_reader_binary_sha256','bootstrap_payload_sha256','owner_binary_sha256','actor_binary_sha256','runtime_client_command_sha256','poweroff_command_sha256']) k WHERE COALESCE(b#>>ARRAY['profile_manifest',k],'') !~ '^[a-f0-9]{64}$')
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['name','writer_id','notify_source_commit','query_sha256','recipient_sha256','database','database_oid','system_identifier','topology_sha256']) k WHERE jsonb_typeof(n->k) IS DISTINCT FROM 'string' OR COALESCE(n->>k,'')='')
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(b->'members')='array' THEN b->'members' ELSE '[]'::jsonb END) e WHERE NOT COALESCE(jsonb_typeof(e)='object' AND jsonb_typeof(e->'slot')='number' AND e->'slot'>='1'::jsonb AND e->'slot'<='8'::jsonb
  AND e->>'name'<>'' AND e->>'origin' ~ '^https://[^/?#@]+$' AND e->>'server_ca_ref'<>'' AND e->>'client_certificate_ref'<>'' AND e->>'client_key_ref'<>'' AND e->>'actor_client_principal'<>'' AND e->>'provisioner_client_principal'<>'',false)),false)
 THEN jsonb_build_object('guest_retirement_binding',b,'guest_notify_canary_binding',n,'mutation_binding',m,
  'provider',p->'provider','profile',p->'name','region',p->'region','environment',s->'environment','domain',s->'domain','dimension',s->'dimension','workflow',s->'workflow') END FROM x
$$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.http_maintenance_dispatch_policy_continuous(prior_id uuid,prior_checksum text,current_id uuid,current_checksum text)
RETURNS boolean LANGUAGE sql STABLE AS $$
WITH c AS(SELECT * FROM public.manifests WHERE id=current_id AND kind='capacity_policy' AND active AND checksum=current_checksum),
 p AS(SELECT p.* FROM public.manifests p,c WHERE p.id=prior_id AND p.kind=c.kind AND p.namespace=c.namespace AND p.name=c.name AND p.checksum=prior_checksum),
 target AS(SELECT public.http_maintenance_dispatch_policy_projection(c.spec) value FROM c)
SELECT COALESCE(EXISTS(SELECT 1 FROM c,p,target WHERE target.value IS NOT NULL AND
 ((p.id=c.id AND p.checksum=c.checksum) OR(p.version<c.version AND NOT EXISTS(
 SELECT 1 FROM public.manifests v WHERE v.kind=c.kind AND v.namespace=c.namespace AND v.name=c.name AND v.version>=p.version AND v.version<c.version
 AND public.http_maintenance_dispatch_policy_projection(v.spec) IS DISTINCT FROM target.value)))),false)
$$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.http_maintenance_dispatch_members(job uuid)
RETURNS jsonb LANGUAGE sql STABLE SET timezone='UTC' AS $$
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 all_sl AS (SELECT s.* FROM public.capacity_resource_slots s,j WHERE s.namespace=j.realm
  AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension
  AND s.resource_id<>'' AND COALESCE(s.slot_record->>'tombstone','false')='false'
 ), sl AS (SELECT * FROM all_sl WHERE NOT(slot_record ? 'authority_kind')),
 joined AS (
 SELECT s.slot,s.resource_id,s.slot_record,s.revision,s.updated_at,p.id AS preregistration_id,
  e.enrollment_sha256,n.confirmation_sha256,p.preregistration_record
 FROM sl s CROSS JOIN j
 JOIN public.capacity_mutation_grants g ON g.namespace=j.realm AND g.environment=j.environment
  AND g.domain=j.domain AND g.dimension=j.dimension AND g.slot=s.slot
  AND g.integration_instance_id=s.integration_instance_id AND g.scope_checksum=s.scope_checksum
  AND g.profile_name=s.profile_name AND g.state='confirmed'
  AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL
  AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL
 JOIN public.capacity_vm_provisioning_preregistrations p ON p.create_grant_id=g.id
  AND p.preregistration_record->>'slot'=s.slot::text
  AND public.http_maintenance_dispatch_policy_continuous((p.preregistration_record->>'policy_id')::uuid,p.preregistration_record->>'policy_checksum',(j.envelope::jsonb#>>'{policy,id}')::uuid,j.envelope::jsonb#>>'{policy,checksum}')
  AND p.preregistration_record->>'workflow_id'=j.envelope::jsonb#>>'{workflow,id}'
  AND p.preregistration_record->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'
  AND p.preregistration_record->>'generation'=(SELECT intent->>'generation' FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension)
  AND p.preregistration_record->>'fence'=(SELECT intent->>'fencing_token' FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension)

 JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=p.id
  AND e.enrollment_record#>>'{statement,tuple,resource_id}'=s.resource_id
  AND e.enrollment_record#>>'{statement,tuple,resource_created_at}'=s.slot_record->>'resource_created_at'
 JOIN public.capacity_guest_original_installations n ON n.preregistration_id=p.id
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


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.http_maintenance_dispatch_effect_scan(job uuid)
RETURNS jsonb LANGUAGE sql STABLE SET timezone='UTC' AS $$
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 w AS (SELECT w.* FROM public.workflow_runs w,j WHERE w.id=j.run_id),
 it AS (SELECT i.intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm
  AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),
 mem AS (SELECT public.http_maintenance_dispatch_members(job) AS members),
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
  j.realm='dakasa-production' AND j.environment='production' AND j.domain='notify' AND j.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND it.intent->>'policy_id'=j.envelope::jsonb#>>'{policy,id}'
  AND it.intent->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND it.intent->>'phase' IN('promoted','reconciled','reconciled_partial')
  AND COALESCE(it.intent->>'lease_owner','')='' AND COALESCE(it.intent->>'lease_executor_id','')=''
  AND COALESCE(jsonb_typeof(it.intent->'lease_expires_at'),'null')='null'
  AND COALESCE(it.intent->>'recovery_only','false')='false' AND COALESCE(it.intent->>'floor_degraded','false')='false'
  AND COALESCE(jsonb_typeof(it.intent->'failed_installed_disposal'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'installed_guest_reconcile'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'original_notify_window'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'failed_serving_disposal'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'retirement_forward'),'null')='null'
  AND it.intent#>>'{decision,action}'='hold' AND COALESCE(it.intent#>>'{decision,execution_permitted}','false')='false'
  AND EXISTS(SELECT 1 FROM public.manifests p WHERE p.id::text=j.envelope::jsonb#>>'{policy,id}' AND p.kind='capacity_policy'
   AND p.active AND p.checksum=j.envelope::jsonb#>>'{policy,checksum}'
   AND p.spec#>>'{guest_notify_reconcile_binding,mode}'='original_guest_notify_reconcile_v1'
   AND p.spec#>>'{environment}'=j.environment AND p.spec#>>'{domain}'=j.domain AND p.spec#>>'{dimension}'=j.dimension)
  AND EXISTS(SELECT 1 FROM public.manifests wf WHERE wf.id::text=j.envelope::jsonb#>>'{workflow,id}' AND wf.kind='workflow'
   AND wf.active AND wf.checksum=j.envelope::jsonb#>>'{workflow,checksum}'),false) AS valid FROM j,w,it)
SELECT jsonb_build_object('schema','recorded_http_maintenance_dispatch_effect_scan_v1',
 'base',public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at),
 'current_members',(SELECT members FROM mem),
 'current_members_sha256',encode(sha256(convert_to((SELECT members FROM mem)::text,'UTF8')),'hex'),
 'current_member_count',jsonb_array_length((SELECT members FROM mem)),
 'policy_epoch_valid',COALESCE((SELECT valid FROM epoch),false),
 'refresh_only_result',COALESCE((SELECT public.http_maintenance_dispatch_result_valid(w.result,it.intent->>'generation',it.intent->>'fencing_token')
  AND w.result#>>'{workflow,id}'=j.envelope::jsonb#>>'{workflow,id}'
  AND w.result#>>'{workflow,kind}'='workflow'
  AND w.result#>>'{workflow,namespace}'=j.envelope::jsonb#>>'{workflow,namespace}'
  AND w.result#>>'{workflow,name}'=j.envelope::jsonb#>>'{workflow,name}'
  AND w.result#>>'{workflow,version}'=j.envelope::jsonb#>>'{workflow,version}' FROM w,it),false),
 'invalid_maintenance_canary_rows',(CASE WHEN (SELECT count(*) FROM candidates)<>1 THEN 1 ELSE (SELECT count(*) FROM candidates c WHERE NOT COALESCE(
  c.phase='publish' AND c.record_challenge_id=c.id
  AND EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces nn WHERE nn.challenge_id=c.id)
  AND EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends ss WHERE ss.challenge_id=c.id)
  AND EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns rr WHERE rr.challenge_id=c.id AND rr.outcome='held' AND rr.original_wire IS NULL AND rr.business_observation IS NULL)
  AND c.challenge_sha256=encode(sha256(c.original_wire),'hex') AND
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
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.lease_expires_at),false)) END))
FROM j
$$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.http_maintenance_dispatch_effect_scan_tolerable(scan jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT COALESCE(jsonb_typeof(scan)='object' AND scan->>'schema'='recorded_http_maintenance_dispatch_effect_scan_v1'
 AND scan->'policy_epoch_valid'='true'::jsonb AND scan->'refresh_only_result'='true'::jsonb
 AND scan->'invalid_maintenance_canary_rows'='0'::jsonb
 AND jsonb_typeof(scan->'current_members')='array' AND jsonb_array_length(scan->'current_members')=1
 AND scan->'current_member_count'=to_jsonb(jsonb_array_length(scan->'current_members'))
 AND scan->>'current_members_sha256'=encode(sha256(convert_to((scan->'current_members')::text,'UTF8')),'hex')
 AND (scan#>>'{base,canary_challenges_since_start}')='1'
 AND (scan#>>'{base,canary_nonces_since_start}')='1'
 AND (scan#>>'{base,canary_possible_sends_since_start}')='1'
 AND (scan#>>'{base,canary_returns_since_start}')='1'
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan->'base') e WHERE e.key IN('canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start')
   AND (jsonb_typeof(e.value)<>'number' OR (e.value::text)::numeric<0 OR trunc((e.value::text)::numeric)<>(e.value::text)::numeric))
 AND public.finalization_lost_dispatch_effect_scan_tolerable((scan->'base') || jsonb_build_object(
  'canary_challenges_since_start',0,'canary_nonces_since_start',0,'canary_possible_sends_since_start',0,'canary_returns_since_start',0)),false)
$$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.http_maintenance_dispatch_admission_valid(job uuid)
RETURNS boolean LANGUAGE sql STABLE SET timezone='UTC' AS $$
SELECT COALESCE(j.realm='dakasa-production' AND j.protocol='capacity_dispatch_prestart_v1' AND j.state='unknown' AND j.started_at IS NOT NULL AND j.returned_at IS NOT NULL
 AND j.return_status='failed' AND j.return_error='capacity dispatch original context refused' AND j.finalization_error=j.return_error
 AND j.finalization_ack_at IS NULL AND num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0
 AND j.lease_owner IS NOT NULL AND j.lease_expires_at IS NOT NULL AND j.started_at<j.returned_at AND j.returned_at<j.lease_expires_at
 AND clock_timestamp()>=j.lease_expires_at+interval '15 minutes'
 AND w.status='failed' AND w.error=j.return_error AND w.started_at=j.started_at AND w.finished_at=j.returned_at
 AND j.envelope_sha256=encode(sha256(convert_to(j.envelope,'UTF8')),'hex')
 AND w.workflow_namespace=j.envelope::jsonb#>>'{workflow,namespace}' AND w.workflow_name=j.envelope::jsonb#>>'{workflow,name}'
 AND w.workflow_version::text=j.envelope::jsonb#>>'{workflow,version}'
 AND(w.workflow_id IS NULL OR w.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}')
 AND w.inputs=j.envelope::jsonb->'inputs' AND w.metadata=j.envelope::jsonb->'metadata'
 AND NOT EXISTS(SELECT 1 FROM(VALUES('capacity_policy',j.envelope::jsonb->'policy'),('workflow',j.envelope::jsonb->'workflow'),('rbac',j.envelope::jsonb->'rbac'),('policy',j.envelope::jsonb->'authorization_policy')) pins(kind,pin)
  WHERE pin IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.manifests m WHERE m.id::text=pin->>'id' AND m.kind=pins.kind AND m.namespace=pin->>'namespace'
   AND m.name=pin->>'name' AND m.version::text=pin->>'version' AND m.checksum=pin->>'checksum' AND m.active))
 AND public.http_maintenance_dispatch_effect_scan_tolerable(public.http_maintenance_dispatch_effect_scan(j.id)),false)
FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=job
$$;
-- +goose StatementEnd


CREATE TABLE IF NOT EXISTS public.capacity_dispatch_http_maintenance_dispositions (
 id uuid PRIMARY KEY,
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
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
 reason text NOT NULL CHECK(reason='recorded_context_refused_http_maintenance_dispatch_disposed'),
 historical_return text NOT NULL CHECK(historical_return='unknown'),
 recorded_at timestamptz NOT NULL,
 provider_mutation_evidence jsonb NOT NULL CHECK(public.http_maintenance_dispatch_effect_scan_tolerable(provider_mutation_evidence))
);
-- No dispatch column is added: existing to_jsonb(j) preimages keep their shape.
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v8_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v8_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v9_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v9_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v9_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v9_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_http_maintenance_dispatch_disposition_insert() RETURNS trigger
LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs; scan jsonb;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[j.realm,j.environment,j.domain,j.dimension]) n WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'HTTP maintenance disposition requires exact scope encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[j.realm,j.environment,j.domain,j.dimension])::text,0));
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=j.run_id FOR UPDATE;
 PERFORM id FROM public.manifests WHERE id::text IN(j.envelope::jsonb#>>'{policy,id}',j.envelope::jsonb#>>'{workflow,id}',j.envelope::jsonb#>>'{rbac,id}',j.envelope::jsonb#>>'{authorization_policy,id}') ORDER BY id FOR SHARE;
 PERFORM id FROM public.manifests WHERE kind='capacity_policy' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id::text=j.envelope::jsonb#>>'{policy,id}') ORDER BY version,id FOR SHARE;
 PERFORM namespace FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension FOR SHARE;
 PERFORM slot FROM public.capacity_resource_slots WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE;
 PERFORM id FROM public.capacity_mutation_grants WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY id FOR SHARE;
 IF public.http_maintenance_dispatch_admission_valid(j.id) IS DISTINCT FROM true
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_http_maintenance_dispositions WHERE job_id=j.id OR run_id=j.run_id)
 OR w.id IS DISTINCT FROM NEW.run_id OR NEW.original_returned_at IS DISTINCT FROM j.returned_at OR NEW.original_dispatch_updated_at IS DISTINCT FROM j.updated_at
 OR NEW.original_dispatch_sha256 IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')
 OR NEW.original_run_sha256 IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')
 OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 OR NEW.disposing_core_process_started_at<=j.lease_expires_at OR NEW.disposing_core_process_started_at>NEW.recorded_at
 THEN RAISE EXCEPTION 'HTTP maintenance disposition requires exact expired original and later process'; END IF;
 scan=public.http_maintenance_dispatch_effect_scan(j.id);
 IF NEW.provider_mutation_evidence IS DISTINCT FROM scan OR public.http_maintenance_dispatch_effect_scan_tolerable(scan) IS DISTINCT FROM true
 OR NEW.current_members_sha256 IS DISTINCT FROM scan->>'current_members_sha256'
 THEN RAISE EXCEPTION 'HTTP maintenance disposition requires exact closed evidence'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_http_maintenance_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE d public.capacity_dispatch_http_maintenance_dispositions;
BEGIN
 IF old_row.state='http_maintenance_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'HTTP maintenance terminal is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'unknown' OR new_row.state<>'http_maintenance_disposed'
 OR(to_jsonb(new_row)-ARRAY['state','updated_at']) IS DISTINCT FROM(to_jsonb(old_row)-ARRAY['state','updated_at'])
 THEN RAISE EXCEPTION 'HTTP maintenance disposition must preserve original job fields'; END IF;
 SELECT * INTO STRICT d FROM public.capacity_dispatch_http_maintenance_dispositions WHERE job_id=old_row.id AND run_id=old_row.run_id;
 IF d.original_dispatch_updated_at IS DISTINCT FROM old_row.updated_at
 OR d.original_dispatch_sha256 IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(old_row)::text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'HTTP maintenance transition requires exact same transaction receipt'; END IF;
 RETURN new_row;
END; $$;
-- +goose StatementEnd


-- Every pre-existing branch below is byte-identical to migration87.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
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


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_http_maintenance_dispatch_job_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='http_maintenance_disposed' THEN RAISE EXCEPTION 'HTTP maintenance terminal requires retained original job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.immutable_http_maintenance_dispatch_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'HTTP maintenance disposition is immutable'; END; $$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_http_maintenance_dispatch_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_http_maintenance_dispositions WHERE run_id=OLD.id) AND(TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'HTTP maintenance original workflow is immutable'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.require_http_maintenance_dispatch_disposition_links() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=NEW.run_id;
 IF j.state IS DISTINCT FROM 'http_maintenance_disposed' OR j.run_id IS DISTINCT FROM NEW.run_id
 OR j.returned_at IS DISTINCT FROM NEW.original_returned_at OR j.finalization_ack_at IS NOT NULL
 OR num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)<>0
 OR encode(sha256(convert_to((to_jsonb(j)||jsonb_build_object('state','unknown','updated_at',NEW.original_dispatch_updated_at))::text,'UTF8')),'hex') IS DISTINCT FROM NEW.original_dispatch_sha256
 OR encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') IS DISTINCT FROM NEW.original_run_sha256
 THEN RAISE EXCEPTION 'HTTP maintenance receipt requires terminal job and unchanged originals in same commit'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd


-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_http_maintenance_dispositions'::regclass AND tgname='http_maintenance_dispatch_disposition_insert') THEN
 CREATE TRIGGER http_maintenance_dispatch_disposition_insert BEFORE INSERT ON public.capacity_dispatch_http_maintenance_dispositions FOR EACH ROW EXECUTE FUNCTION public.guard_http_maintenance_dispatch_disposition_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd


-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_http_maintenance_dispositions'::regclass AND tgname='http_maintenance_dispatch_disposition_immutable') THEN
 CREATE TRIGGER http_maintenance_dispatch_disposition_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_http_maintenance_dispositions FOR EACH ROW EXECUTE FUNCTION public.immutable_http_maintenance_dispatch_disposition();
 END IF;
END $idempotent$;
-- +goose StatementEnd


-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_jobs'::regclass AND tgname='http_maintenance_dispatch_job_insert') THEN
 CREATE TRIGGER http_maintenance_dispatch_job_insert BEFORE INSERT ON public.capacity_dispatch_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_http_maintenance_dispatch_job_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd


-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.workflow_runs'::regclass AND tgname='http_maintenance_dispatch_workflow_immutable') THEN
 CREATE TRIGGER http_maintenance_dispatch_workflow_immutable BEFORE UPDATE OR DELETE ON public.workflow_runs FOR EACH ROW EXECUTE FUNCTION public.guard_http_maintenance_dispatch_workflow();
 END IF;
END $idempotent$;
-- +goose StatementEnd


-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_http_maintenance_dispositions'::regclass AND tgname='http_maintenance_dispatch_disposition_complete_links') THEN
 CREATE CONSTRAINT TRIGGER http_maintenance_dispatch_disposition_complete_links AFTER INSERT ON public.capacity_dispatch_http_maintenance_dispositions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_http_maintenance_dispatch_disposition_links();
 END IF;
END $idempotent$;
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'HTTP maintenance disposition is a retained forward-only boundary'; END; $$;
-- +goose StatementEnd
