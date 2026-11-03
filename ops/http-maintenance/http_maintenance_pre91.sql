-- Generated from migration91 SQL bodies; do not hand-edit.
-- Source SHA256: 6ea7ce084db9dbdb7d9443acd8af94876aff6b126fdf7652bf975982d512f240
-- READ ONLY UTC transaction required; no new-process barrier or full Go ADR94 proof.
-- Two independent Source scan expansions are preserved; no inferred memoization.
-- http_maintenance_dispatch_result_valid: 21591d3ae4cd30561f8ac6dc38e497ba92a1ab8b79b531fb235596c8141bd7be
-- http_maintenance_dispatch_policy_projection: 140704a048a380a8a73f514449f125284188c6cb0d0c11dfdfdc7237dca03517
-- http_maintenance_dispatch_policy_continuous: cb95009944efaed5ea758bc8e7459e38f58b5af0a3607b3b1a4ee977cc000e49
-- http_maintenance_dispatch_members: 3a2b7579ecac1a6dd29237e805bc9403d9397fda318a678397df43a28db7af5e
-- http_maintenance_dispatch_effect_scan: 7891ba715e3aa451f342420f1aef6e8404f7a530fac3eeb9f8fda9ac8bd00614
-- http_maintenance_dispatch_effect_scan_tolerable: f2151029849b86803f2a82edd1f270845e9bafbdf005042cf2c35f5bfc875064
-- http_maintenance_dispatch_admission_valid: 26ea09ea151a20deecb249d43742bb5fa777d8ff807336ab8ea0cb94d6c45ad5
WITH __r6_pre91_input AS MATERIALIZED (
 SELECT $1::uuid AS job_id
 WHERE current_setting('transaction_read_only')='on' AND current_setting('TimeZone')='UTC'
  AND current_setting('standard_conforming_strings')='on'
), __r6_pre91_scan AS MATERIALIZED (
 SELECT (WITH __r6_pre91_args_1 AS MATERIALIZED (SELECT (__r6_pre91_input.job_id)::uuid AS p0) SELECT (
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=__r6_pre91_args_1.p0),
 w AS (SELECT w.* FROM public.workflow_runs w,j WHERE w.id=j.run_id),
 it AS (SELECT i.intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm
  AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),
 mem AS (SELECT (WITH __r6_pre91_args_2 AS MATERIALIZED (SELECT (__r6_pre91_args_1.p0)::uuid AS p0) SELECT (
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=__r6_pre91_args_2.p0),
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
  AND (WITH __r6_pre91_args_3 AS MATERIALIZED (SELECT ((p.preregistration_record->>'policy_id')::uuid)::uuid AS p0, (p.preregistration_record->>'policy_checksum')::text AS p1, ((j.envelope::jsonb#>>'{policy,id}')::uuid)::uuid AS p2, (j.envelope::jsonb#>>'{policy,checksum}')::text AS p3) SELECT (
WITH c AS(SELECT * FROM public.manifests WHERE id=__r6_pre91_args_3.p2 AND kind='capacity_policy' AND active AND checksum=__r6_pre91_args_3.p3),
 p AS(SELECT p.* FROM public.manifests p,c WHERE p.id=__r6_pre91_args_3.p0 AND p.kind=c.kind AND p.namespace=c.namespace AND p.name=c.name AND p.checksum=__r6_pre91_args_3.p1),
 target AS(SELECT (WITH __r6_pre91_args_4 AS MATERIALIZED (SELECT (c.spec)::jsonb AS p0) SELECT (
WITH a AS(SELECT __r6_pre91_args_4.p0 s,__r6_pre91_args_4.p0->'guest_retirement_binding' b,__r6_pre91_args_4.p0->'guest_notify_canary_binding' n),
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
) FROM __r6_pre91_args_4) value FROM c)
SELECT COALESCE(EXISTS(SELECT 1 FROM c,p,target WHERE target.value IS NOT NULL AND
 ((p.id=c.id AND p.checksum=c.checksum) OR(p.version<c.version AND NOT EXISTS(
 SELECT 1 FROM public.manifests v WHERE v.kind=c.kind AND v.namespace=c.namespace AND v.name=c.name AND v.version>=p.version AND v.version<c.version
 AND (WITH __r6_pre91_args_5 AS MATERIALIZED (SELECT (v.spec)::jsonb AS p0) SELECT (
WITH a AS(SELECT __r6_pre91_args_5.p0 s,__r6_pre91_args_5.p0->'guest_retirement_binding' b,__r6_pre91_args_5.p0->'guest_notify_canary_binding' n),
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
) FROM __r6_pre91_args_5) IS DISTINCT FROM target.value)))),false)
) FROM __r6_pre91_args_3)
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
) FROM __r6_pre91_args_2) AS members),
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
 'refresh_only_result',COALESCE((SELECT (WITH __r6_pre91_args_6 AS MATERIALIZED (SELECT (w.result)::jsonb AS p0, (it.intent->>'generation')::text AS p1, (it.intent->>'fencing_token')::text AS p2) SELECT (
SELECT COALESCE(jsonb_typeof(__r6_pre91_args_6.p0)='object' AND __r6_pre91_args_6.p0->>'status'='failed'
 AND jsonb_typeof(__r6_pre91_args_6.p0->'steps')='array' AND jsonb_array_length(__r6_pre91_args_6.p0->'steps')=7
 AND NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(__r6_pre91_args_6.p0->'steps') WITH ORDINALITY x(s,n)
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
 AND __r6_pre91_args_6.p0#>>'{steps,0,attempts}'='1'
 AND __r6_pre91_args_6.p0#>>'{steps,0,metadata,mode}'='refresh'
 AND __r6_pre91_args_6.p0#>>'{steps,0,metadata,slot}'='0'
 AND __r6_pre91_args_6.p0#>>'{steps,0,metadata,reason}'='capacity_boundary'
 AND __r6_pre91_args_6.p0#>>'{steps,0,metadata,generation}'=__r6_pre91_args_6.p1
 AND __r6_pre91_args_6.p0#>>'{steps,0,metadata,fencing_token}'=__r6_pre91_args_6.p2
 AND __r6_pre91_args_6.p0#>>'{steps,0,metadata,lease_owner}'=''
 AND __r6_pre91_args_6.p0#>>'{steps,0,metadata,preregistration_id}'=''
 AND NOT (__r6_pre91_args_6.p0#>'{steps,0,metadata}' ? 'request_id')
 AND __r6_pre91_args_6.p0#>>'{steps,3,attempts}'='1'
 AND __r6_pre91_args_6.p0#>>'{steps,3,error}'='original Guest reconciliation held'
 AND __r6_pre91_args_6.p0#>>'{steps,3,metadata,original_guest_reconcile_refusal_stage}'='fresh_original_canary'
 AND __r6_pre91_args_6.p0#>>'{steps,3,metadata,original_guest_notify_refusal_stage}' ='original_HTTP_or_return',false)
) FROM __r6_pre91_args_6)
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
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.lease_expires_at),false))) END)
FROM j
) FROM __r6_pre91_args_1) AS effect_scan FROM __r6_pre91_input
)
SELECT jsonb_build_object(
 'observed_at_pg',clock_timestamp(),'job_id',j.id,'run_id',j.run_id,
 'original_dispatch_sha256',CASE WHEN j.id IS NOT NULL THEN encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex') END,
 'original_run_sha256',CASE WHEN w.id IS NOT NULL THEN encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') END,
 'cas',jsonb_build_object('job_id',j.id,'expected_run_id',j.run_id,'expected_envelope_sha256',j.envelope_sha256,
  'expected_fencing_token',j.fencing_token,'expected_lease_owner',j.lease_owner,'expected_pending_wake_count',j.pending_wake_count,
  'expected_returned_at',j.returned_at,
  'expected_run_sha256',CASE WHEN w.id IS NOT NULL THEN encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') END,
  'expected_members_sha256',__r6_pre91_scan.effect_scan->>'current_members_sha256'),
 'effect_scan',__r6_pre91_scan.effect_scan,'admission',COALESCE((WITH __r6_pre91_args_7 AS MATERIALIZED (SELECT (__r6_pre91_input.job_id)::uuid AS p0) SELECT (
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
 AND (WITH __r6_pre91_args_14 AS MATERIALIZED (SELECT ((WITH __r6_pre91_args_8 AS MATERIALIZED (SELECT (j.id)::uuid AS p0) SELECT (
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=__r6_pre91_args_8.p0),
 w AS (SELECT w.* FROM public.workflow_runs w,j WHERE w.id=j.run_id),
 it AS (SELECT i.intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm
  AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),
 mem AS (SELECT (WITH __r6_pre91_args_9 AS MATERIALIZED (SELECT (__r6_pre91_args_8.p0)::uuid AS p0) SELECT (
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=__r6_pre91_args_9.p0),
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
  AND (WITH __r6_pre91_args_10 AS MATERIALIZED (SELECT ((p.preregistration_record->>'policy_id')::uuid)::uuid AS p0, (p.preregistration_record->>'policy_checksum')::text AS p1, ((j.envelope::jsonb#>>'{policy,id}')::uuid)::uuid AS p2, (j.envelope::jsonb#>>'{policy,checksum}')::text AS p3) SELECT (
WITH c AS(SELECT * FROM public.manifests WHERE id=__r6_pre91_args_10.p2 AND kind='capacity_policy' AND active AND checksum=__r6_pre91_args_10.p3),
 p AS(SELECT p.* FROM public.manifests p,c WHERE p.id=__r6_pre91_args_10.p0 AND p.kind=c.kind AND p.namespace=c.namespace AND p.name=c.name AND p.checksum=__r6_pre91_args_10.p1),
 target AS(SELECT (WITH __r6_pre91_args_11 AS MATERIALIZED (SELECT (c.spec)::jsonb AS p0) SELECT (
WITH a AS(SELECT __r6_pre91_args_11.p0 s,__r6_pre91_args_11.p0->'guest_retirement_binding' b,__r6_pre91_args_11.p0->'guest_notify_canary_binding' n),
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
) FROM __r6_pre91_args_11) value FROM c)
SELECT COALESCE(EXISTS(SELECT 1 FROM c,p,target WHERE target.value IS NOT NULL AND
 ((p.id=c.id AND p.checksum=c.checksum) OR(p.version<c.version AND NOT EXISTS(
 SELECT 1 FROM public.manifests v WHERE v.kind=c.kind AND v.namespace=c.namespace AND v.name=c.name AND v.version>=p.version AND v.version<c.version
 AND (WITH __r6_pre91_args_12 AS MATERIALIZED (SELECT (v.spec)::jsonb AS p0) SELECT (
WITH a AS(SELECT __r6_pre91_args_12.p0 s,__r6_pre91_args_12.p0->'guest_retirement_binding' b,__r6_pre91_args_12.p0->'guest_notify_canary_binding' n),
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
) FROM __r6_pre91_args_12) IS DISTINCT FROM target.value)))),false)
) FROM __r6_pre91_args_10)
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
) FROM __r6_pre91_args_9) AS members),
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
 'refresh_only_result',COALESCE((SELECT (WITH __r6_pre91_args_13 AS MATERIALIZED (SELECT (w.result)::jsonb AS p0, (it.intent->>'generation')::text AS p1, (it.intent->>'fencing_token')::text AS p2) SELECT (
SELECT COALESCE(jsonb_typeof(__r6_pre91_args_13.p0)='object' AND __r6_pre91_args_13.p0->>'status'='failed'
 AND jsonb_typeof(__r6_pre91_args_13.p0->'steps')='array' AND jsonb_array_length(__r6_pre91_args_13.p0->'steps')=7
 AND NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(__r6_pre91_args_13.p0->'steps') WITH ORDINALITY x(s,n)
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
 AND __r6_pre91_args_13.p0#>>'{steps,0,attempts}'='1'
 AND __r6_pre91_args_13.p0#>>'{steps,0,metadata,mode}'='refresh'
 AND __r6_pre91_args_13.p0#>>'{steps,0,metadata,slot}'='0'
 AND __r6_pre91_args_13.p0#>>'{steps,0,metadata,reason}'='capacity_boundary'
 AND __r6_pre91_args_13.p0#>>'{steps,0,metadata,generation}'=__r6_pre91_args_13.p1
 AND __r6_pre91_args_13.p0#>>'{steps,0,metadata,fencing_token}'=__r6_pre91_args_13.p2
 AND __r6_pre91_args_13.p0#>>'{steps,0,metadata,lease_owner}'=''
 AND __r6_pre91_args_13.p0#>>'{steps,0,metadata,preregistration_id}'=''
 AND NOT (__r6_pre91_args_13.p0#>'{steps,0,metadata}' ? 'request_id')
 AND __r6_pre91_args_13.p0#>>'{steps,3,attempts}'='1'
 AND __r6_pre91_args_13.p0#>>'{steps,3,error}'='original Guest reconciliation held'
 AND __r6_pre91_args_13.p0#>>'{steps,3,metadata,original_guest_reconcile_refusal_stage}'='fresh_original_canary'
 AND __r6_pre91_args_13.p0#>>'{steps,3,metadata,original_guest_notify_refusal_stage}' ='original_HTTP_or_return',false)
) FROM __r6_pre91_args_13)
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
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.lease_expires_at),false))) END)
FROM j
) FROM __r6_pre91_args_8))::jsonb AS p0) SELECT (
SELECT COALESCE(jsonb_typeof(__r6_pre91_args_14.p0)='object' AND __r6_pre91_args_14.p0->>'schema'='recorded_http_maintenance_dispatch_effect_scan_v1'
 AND __r6_pre91_args_14.p0->'policy_epoch_valid'='true'::jsonb AND __r6_pre91_args_14.p0->'refresh_only_result'='true'::jsonb
 AND __r6_pre91_args_14.p0->'invalid_maintenance_canary_rows'='0'::jsonb
 AND jsonb_typeof(__r6_pre91_args_14.p0->'current_members')='array' AND jsonb_array_length(__r6_pre91_args_14.p0->'current_members')=1
 AND __r6_pre91_args_14.p0->'current_member_count'=to_jsonb(jsonb_array_length(__r6_pre91_args_14.p0->'current_members'))
 AND __r6_pre91_args_14.p0->>'current_members_sha256'=encode(sha256(convert_to((__r6_pre91_args_14.p0->'current_members')::text,'UTF8')),'hex')
 AND (__r6_pre91_args_14.p0#>>'{base,canary_challenges_since_start}')='1'
 AND (__r6_pre91_args_14.p0#>>'{base,canary_nonces_since_start}')='1'
 AND (__r6_pre91_args_14.p0#>>'{base,canary_possible_sends_since_start}')='1'
 AND (__r6_pre91_args_14.p0#>>'{base,canary_returns_since_start}')='1'
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(__r6_pre91_args_14.p0->'base') e WHERE e.key IN('canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start')
   AND (jsonb_typeof(e.value)<>'number' OR (e.value::text)::numeric<0 OR trunc((e.value::text)::numeric)<>(e.value::text)::numeric))
 AND public.finalization_lost_dispatch_effect_scan_tolerable((__r6_pre91_args_14.p0->'base') || jsonb_build_object(
  'canary_challenges_since_start',0,'canary_nonces_since_start',0,'canary_possible_sends_since_start',0,'canary_returns_since_start',0)),false)
) FROM __r6_pre91_args_14),false)
FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.id=__r6_pre91_args_7.p0
) FROM __r6_pre91_args_7),false))
FROM __r6_pre91_input CROSS JOIN __r6_pre91_scan
LEFT JOIN public.capacity_dispatch_jobs j ON j.id=__r6_pre91_input.job_id
LEFT JOIN public.workflow_runs w ON w.id=j.run_id;
