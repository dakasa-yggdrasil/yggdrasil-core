-- +goose Up
-- Retain the exhausted M98 generation and its failed originals forever.
-- One distinct readiness-only generation per M98 origin; never a fourth attempt.
CREATE TABLE IF NOT EXISTS public.capacity_installed_readiness_exhausted_handoffs (
 id uuid PRIMARY KEY,
 original_disposition_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_installed_provision_timeout_dispositions(id),
 namespace text NOT NULL CHECK(length(namespace) BETWEEN 1 AND 64),
 environment text NOT NULL CHECK(length(environment) BETWEEN 1 AND 128),
 domain text NOT NULL CHECK(length(domain) BETWEEN 1 AND 128),
 dimension text NOT NULL CHECK(length(dimension) BETWEEN 1 AND 128),
 original_record jsonb NOT NULL,
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 1048576),
 record_sha256 text NOT NULL UNIQUE CHECK(record_sha256 ~ '^[0-9a-f]{64}$'),
 original_intent_wire bytea NOT NULL CHECK(octet_length(original_intent_wire) BETWEEN 1 AND 1048576),
 failed_jobs_wire bytea NOT NULL CHECK(octet_length(failed_jobs_wire) BETWEEN 1 AND 3145728),
 failed_runs_wire bytea NOT NULL CHECK(octet_length(failed_runs_wire) BETWEEN 1 AND 8388608),
 previous_canaries_wire bytea NOT NULL CHECK(octet_length(previous_canaries_wire) BETWEEN 1 AND 8388608),
 members_wire bytea NOT NULL CHECK(octet_length(members_wire) BETWEEN 1 AND 1048576),
 marker_wire bytea NOT NULL CHECK(octet_length(marker_wire) BETWEEN 1 AND 16384),
 successor_intent_wire bytea NOT NULL CHECK(octet_length(successor_intent_wire) BETWEEN 1 AND 1048576),
 successor_job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 successor_run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
 recorded_at timestamptz NOT NULL,
 CHECK(original_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(record_sha256=encode(sha256(original_wire),'hex')),
 CHECK(octet_length(original_wire)+octet_length(original_intent_wire)+octet_length(failed_jobs_wire)+octet_length(failed_runs_wire)+octet_length(previous_canaries_wire)+octet_length(members_wire)+octet_length(marker_wire)+octet_length(successor_intent_wire)<=16777216)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.immutable_installed_readiness_handoff() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'installed readiness exhausted handoff is immutable'; END; $$;
-- +goose StatementEnd

-- Exact failed scheduler originals, never a caller classification of an error.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.installed_readiness_failed_ack_valid(j jsonb,w jsonb,m jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE env jsonb; result jsonb; step jsonb; k integer; ids text[]:=ARRAY['plan-original-guest','provision-original-notify','retire-original-guest','refresh-original-membership','complete-original-provision','finish-original-retirement','complete-original-retirement'];
BEGIN
 IF jsonb_typeof(j) IS DISTINCT FROM 'object' OR jsonb_typeof(w) IS DISTINCT FROM 'object' OR jsonb_typeof(m) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 env=(j->>'envelope')::jsonb; result=w->'result';
 IF (j->>'state'='returned' AND j->>'return_status'='failed' AND j->'finalization_ack_at'<>'null'::jsonb
 AND j->'returned_at'<>'null'::jsonb AND j->>'run_id'=w->>'id' AND w->>'id'=m->>'new_run_id'
 AND w->>'status'='failed' AND (w->>'finished_at')::timestamptz=(j->>'returned_at')::timestamptz
 AND (j->>'started_at')::timestamptz<(j->>'returned_at')::timestamptz
 AND (j->>'returned_at')::timestamptz<=(j->>'lease_expires_at')::timestamptz
 AND (j->>'finalization_ack_at')::timestamptz>=(j->>'returned_at')::timestamptz
 AND (w->>'started_at')::timestamptz=(j->>'started_at')::timestamptz
 AND env->>'protocol'='capacity_dispatch_prestart_v1' AND env->>'job_id'=j->>'id' AND env->>'run_id'=j->>'run_id'
 AND encode(sha256(convert_to(j->>'envelope','UTF8')),'hex')=j->>'envelope_sha256'
 AND env#>>'{metadata,triggered_by}'='workflow_scheduler' AND env#>>'{metadata,capacity_dispatch_job_id}'=j->>'id'
 AND w#>>'{metadata,triggered_by}'='workflow_scheduler' AND w#>>'{metadata,capacity_dispatch_job_id}'=j->>'id'
 AND (w->>'workflow_id' IS NULL OR w->>'workflow_id'=env#>>'{workflow,id}')
 AND w->>'workflow_namespace'=env#>>'{workflow,namespace}' AND w->>'workflow_name'=env#>>'{workflow,name}'
 AND result->>'status'='failed' AND jsonb_typeof(result->'steps')='array' AND jsonb_array_length(result->'steps')=7
 AND (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(result->'steps')x)=7
 AND result#>>'{workflow,id}'=env#>>'{workflow,id}' AND result#>>'{workflow,namespace}'=env#>>'{workflow,namespace}'
 AND result#>>'{workflow,name}'=env#>>'{workflow,name}' AND result#>'{workflow,version}'=env#>'{workflow,version}') IS NOT TRUE THEN RETURN false; END IF;
 FOR k IN 1..7 LOOP
  SELECT x INTO STRICT step FROM jsonb_array_elements(result->'steps')x WHERE x->>'id'=ids[k];
  IF (step->>'kind'='yggdrasil' AND step->>'operation'=(ARRAY['capacity.plan_original_guest','capacity.provision_original_guest','capacity.retire_original_guest','capacity.complete_original_guest','capacity.complete_original_guest','capacity.finish_original_guest_retirement','capacity.complete_original_guest'])[k]
   AND step->>'capability'=step->>'operation'
   AND step->>'status'=CASE k WHEN 1 THEN 'succeeded' WHEN 4 THEN 'failed' ELSE 'skipped' END
   AND coalesce(step->'attempts','0'::jsonb)=CASE WHEN k IN(1,4)THEN '1'::jsonb ELSE '0'::jsonb END
   AND NOT step ?| ARRAY['integration_instance','integration_type']) IS NOT TRUE THEN RETURN false; END IF;
  IF k=1 AND (step#>>'{metadata,mode}'='refresh' AND step#>>'{metadata,reason}'='installed_original_readiness_reconcile'
   AND step#>'{metadata,generation}'=m->'original_generation' AND step#>'{metadata,fencing_token}'=m->'new_fence') IS NOT TRUE THEN RETURN false; END IF;
  IF k=4 AND (step#>>'{metadata,original_guest_reconcile_refusal_stage}'='advance_prepared' AND step->>'error'='original Guest reconciliation held') IS NOT TRUE THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- All old rows remain whole originals. A possible send must have a closed
-- transport return; an expired deadline alone never supplies a return.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.installed_readiness_closed_canaries_valid(c jsonb,p uuid,w uuid,g bigint,fs bigint[],at_time timestamptz)
RETURNS boolean LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE expected jsonb; challenge public.capacity_guest_notify_canary_challenges; returned public.capacity_guest_notify_canary_returns; sent public.capacity_guest_notify_canary_sends; tr jsonb;
BEGIN
 IF (jsonb_typeof(c)='object' AND (SELECT count(*) FROM jsonb_object_keys(c))=4
 AND c ?& ARRAY['authority_markers','challenges','returns','sends']
 AND jsonb_typeof(c->'authority_markers')='array' AND jsonb_array_length(c->'authority_markers')=3
 AND jsonb_typeof(c->'challenges')='array' AND jsonb_array_length(c->'challenges')<=256
 AND jsonb_typeof(c->'returns')='array' AND jsonb_array_length(c->'returns')<=256
 AND jsonb_typeof(c->'sends')='array' AND jsonb_array_length(c->'sends')<=256) IS NOT TRUE THEN RETURN false; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.id),'[]'::jsonb) INTO expected FROM public.capacity_guest_notify_canary_challenges x WHERE x.policy_id=p AND x.generation=g AND x.fence=ANY(fs);
 IF c->'challenges' IS DISTINCT FROM expected THEN RETURN false; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.challenge_id),'[]'::jsonb) INTO expected FROM public.capacity_guest_notify_canary_returns x JOIN public.capacity_guest_notify_canary_challenges q ON q.id=x.challenge_id WHERE q.policy_id=p AND q.generation=g AND q.fence=ANY(fs);
 IF c->'returns' IS DISTINCT FROM expected THEN RETURN false; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.challenge_id),'[]'::jsonb) INTO expected FROM public.capacity_guest_notify_canary_sends x JOIN public.capacity_guest_notify_canary_challenges q ON q.id=x.challenge_id WHERE q.policy_id=p AND q.generation=g AND q.fence=ANY(fs);
 IF c->'sends' IS DISTINCT FROM expected THEN RETURN false; END IF;
 FOR challenge IN SELECT * FROM public.capacity_guest_notify_canary_challenges x WHERE x.policy_id=p AND x.generation=g AND x.fence=ANY(fs) LOOP
  IF challenge.workflow_id<>w OR challenge.original_deadline>at_time OR challenge.recorded_at>at_time THEN RETURN false; END IF;
  SELECT * INTO sent FROM public.capacity_guest_notify_canary_sends WHERE challenge_id=challenge.id;
  IF FOUND THEN
   SELECT * INTO returned FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=challenge.id;
   IF NOT FOUND THEN RETURN false; END IF;
   tr=returned.original_transport;
   IF (tr->'PreflightFailed'='false'::jsonb AND tr->'DoFailed'='false'::jsonb AND tr->'ReadFailed'='false'::jsonb AND tr->'CloseFailed'='false'::jsonb AND tr->'OriginalContextFailed'='false'::jsonb
   AND jsonb_typeof(tr->'Status')='number' AND (tr->>'Status')::integer BETWEEN 100 AND 599
   AND tr->>'ResponseBodyScope'='complete_original_body_read'
   AND (tr->>'StartedAt')::timestamptz>=sent.possible_send_at
   AND (tr->>'DoStartedAt')::timestamptz>=(tr->>'StartedAt')::timestamptz
   AND (tr->>'DoReturnedAt')::timestamptz>=(tr->>'DoStartedAt')::timestamptz
   AND (tr->>'ReadReturnedAt')::timestamptz>=(tr->>'DoReturnedAt')::timestamptz
   AND (tr->>'CloseReturnedAt')::timestamptz>=(tr->>'ReadReturnedAt')::timestamptz
   AND (tr->>'DriverReturnedAt')::timestamptz>=(tr->>'CloseReturnedAt')::timestamptz
   AND (tr->>'DriverReturnedAt')::timestamptz<challenge.original_deadline
   AND returned.recorded_at<=at_time) IS NOT TRUE THEN RETURN false; END IF;
  ELSIF EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=challenge.id) THEN RETURN false;
  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- Immutable history is validated against its recorded instant, not a later
-- wall clock. Live eligibility is separately required by the INSERT/intent CAS.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.installed_readiness_handoff_valid(h public.capacity_installed_readiness_exhausted_handoffs)
RETURNS boolean LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE r jsonb:=h.original_record; old_i jsonb; next_i jsonb; mark jsonb; old_m jsonb; jobs jsonb; runs jsonb; canaries jsonb; members jsonb; a jsonb; m jsonb; prev jsonb;
 origin public.capacity_dispatch_installed_provision_timeout_dispositions; policy public.manifests; workflow public.manifests; issue public.capacity_guest_authority_issues;
 job public.capacity_dispatch_jobs; run public.workflow_runs; original_env jsonb; env jsonb; k integer; n integer; fs bigint[]:='{}';
BEGIN
 IF (jsonb_typeof(r)='object' AND (SELECT count(*) FROM jsonb_object_keys(r))=36
 AND r ?& ARRAY['schema','id','original_disposition_id','namespace','environment','domain','dimension','policy_id','policy_checksum','workflow_id','workflow_checksum','exhausted_generation','exhausted_fence','exhausted_attempts','successor_generation','successor_fence','successor_job_id','successor_run_id','successor_executor_id','successor_lease_owner','successor_lease_expires_at','admitting_core_source','old_issuer_core_source','profile','members_count','original_intent_sha256','failed_jobs_sha256','failed_runs_sha256','previous_canaries_sha256','members_sha256','recorded_at','old_generation_outcome','original_failure_preserved','original_quiescence_or_no_effect_claimed','provider_mutations_authorized','child_handoff_allowed']
 AND r->>'schema'='installed_readiness_exhausted_handoff_record_v1' AND r->>'id'=h.id::text
 AND r->>'original_disposition_id'=h.original_disposition_id::text
 AND r->>'namespace'=h.namespace AND r->>'environment'=h.environment AND r->>'domain'=h.domain AND r->>'dimension'=h.dimension
 AND r->'exhausted_attempts'='3'::jsonb AND r->>'old_generation_outcome'='exhausted_failed'
 AND r->'original_failure_preserved'='true'::jsonb AND r->'original_quiescence_or_no_effect_claimed'='false'::jsonb
 AND r->'provider_mutations_authorized'='false'::jsonb AND r->'child_handoff_allowed'='false'::jsonb
 AND jsonb_typeof(r->'recorded_at')='string' AND isfinite((r->>'recorded_at')::timestamptz)
 AND jsonb_typeof(r->'successor_lease_expires_at')='string' AND isfinite((r->>'successor_lease_expires_at')::timestamptz)
 AND r->>'successor_job_id'=h.successor_job_id::text AND r->>'successor_run_id'=h.successor_run_id::text
 AND (r->>'recorded_at')::timestamptz=h.recorded_at
 AND convert_from(h.original_wire,'UTF8')::jsonb=r AND encode(sha256(h.original_wire),'hex')=h.record_sha256) IS NOT TRUE THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['id','original_disposition_id','policy_id','workflow_id','successor_job_id','successor_run_id','successor_executor_id','successor_lease_owner']) x
  WHERE jsonb_typeof(r->x) IS DISTINCT FROM 'string' OR r->>x !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR r->>x='00000000-0000-0000-0000-000000000000')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['policy_checksum','workflow_checksum','original_intent_sha256','failed_jobs_sha256','failed_runs_sha256','previous_canaries_sha256','members_sha256']) x
  WHERE jsonb_typeof(r->x) IS DISTINCT FROM 'string' OR r->>x !~ '^[0-9a-f]{64}$')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['admitting_core_source','old_issuer_core_source'])x WHERE jsonb_typeof(r->x) IS DISTINCT FROM 'string' OR r->>x !~ '^[0-9a-f]{40}$')
 OR r->>'admitting_core_source'=r->>'old_issuer_core_source'
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['exhausted_generation','exhausted_fence','successor_generation','successor_fence'])x
  WHERE jsonb_typeof(r->x) IS DISTINCT FROM 'number' OR r->>x !~ '^[1-9][0-9]*$' OR (r->>x)::bigint>9007199254740991)
 OR (r->>'successor_generation')::bigint<>(r->>'exhausted_generation')::bigint+1
 OR (r->>'successor_fence')::bigint<>(r->>'exhausted_fence')::bigint+1 THEN RETURN false; END IF;
 old_i=convert_from(h.original_intent_wire,'UTF8')::jsonb; next_i=convert_from(h.successor_intent_wire,'UTF8')::jsonb;
 mark=convert_from(h.marker_wire,'UTF8')::jsonb; jobs=convert_from(h.failed_jobs_wire,'UTF8')::jsonb; runs=convert_from(h.failed_runs_wire,'UTF8')::jsonb;
 canaries=convert_from(h.previous_canaries_wire,'UTF8')::jsonb; members=convert_from(h.members_wire,'UTF8')::jsonb; old_m=old_i->'installed_guest_reconcile';
 IF (encode(sha256(h.original_intent_wire),'hex')=r->>'original_intent_sha256'
 AND encode(sha256(h.failed_jobs_wire),'hex')=r->>'failed_jobs_sha256' AND encode(sha256(h.failed_runs_wire),'hex')=r->>'failed_runs_sha256'
 AND encode(sha256(h.previous_canaries_wire),'hex')=r->>'previous_canaries_sha256' AND encode(sha256(h.members_wire),'hex')=r->>'members_sha256'
 AND jsonb_typeof(jobs)='array' AND jsonb_array_length(jobs)=3 AND jsonb_typeof(runs)='array' AND jsonb_array_length(runs)=3
 AND (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(jobs)x)=3 AND (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(runs)x)=3
 AND jsonb_typeof(members)='array' AND jsonb_array_length(members) BETWEEN 2 AND 8
 AND jsonb_typeof(r->'members_count')='number' AND r->'members_count'=to_jsonb(jsonb_array_length(members))
 AND old_m->>'schema'='installed_original_guest_readiness_reconcile_v1' AND old_m->'attempt'='3'::jsonb
 AND old_m->>'installed_provision_timeout_disposition_id'=h.original_disposition_id::text
 AND old_i->'generation'=r->'exhausted_generation' AND old_i->'fencing_token'=r->'exhausted_fence'
 AND old_i->'generation'=old_m->'original_generation' AND old_i->'fencing_token'=old_m->'new_fence'
 AND old_i->>'phase' IN('preparing','prepared','canary') AND old_i->'recovery_only'='false'::jsonb
 AND coalesce(old_i->'floor_degraded','false'::jsonb)='false'::jsonb AND NOT old_i ?| ARRAY['installed_readiness_handoff','failed_installed_disposal','failed_serving_disposal','failed_expansion_terminal_reconcile','failed_unwitnessed_expansion_cleanup_id','retirement_forward','original_notify_window']
 AND old_i->>'namespace'=h.namespace AND old_i->>'environment'=h.environment AND old_i->>'domain'=h.domain AND old_i->>'dimension'=h.dimension
 AND old_i->>'policy_id'=r->>'policy_id' AND old_i->>'policy_checksum'=r->>'policy_checksum'
 AND old_i->>'lease_executor_id'=old_m->>'new_executor_id' AND (old_i->>'lease_expires_at')::timestamptz<=h.recorded_at
 AND old_i->>'lease_owner' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 AND old_i#>'{decision,units}'=r->'members_count' AND old_i#>>'{decision,profile}'=r->>'profile') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO STRICT origin FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=h.original_disposition_id;
 IF public.installed_provision_timeout_valid(origin.original_record,origin.original_dispatch_wire,origin.original_run_wire,origin.original_intent_wire,origin.members_wire) IS DISTINCT FROM true
 OR h.members_wire IS DISTINCT FROM origin.members_wire OR old_m->>'original_job_id'<>origin.job_id::text OR old_m->>'original_run_id'<>origin.run_id::text
 OR old_m->>'original_run_sha256'<>origin.original_record->>'original_run_sha256' OR old_m->'original_fence'<>origin.original_record->'fencing_token'
 OR old_i->'generation'<>origin.original_record->'generation' THEN RETURN false; END IF;
 original_env=(convert_from(origin.original_dispatch_wire,'UTF8')::jsonb->>'envelope')::jsonb;
 SELECT * INTO STRICT policy FROM public.manifests WHERE id=(r->>'policy_id')::uuid AND kind='capacity_policy';
 SELECT * INTO STRICT workflow FROM public.manifests WHERE id=(r->>'workflow_id')::uuid AND kind='workflow';
 IF (policy.checksum=r->>'policy_checksum' AND policy.namespace=h.namespace AND workflow.namespace=h.namespace AND workflow.checksum=r->>'workflow_checksum'
 AND original_env->'policy'=jsonb_build_object('id',policy.id,'namespace',policy.namespace,'name',policy.name,'version',policy.version,'checksum',policy.checksum)
 AND original_env#>>'{workflow,id}'=workflow.id::text AND original_env#>>'{workflow,checksum}'=workflow.checksum
 AND policy.spec->>'environment'=h.environment AND policy.spec->>'domain'=h.domain AND policy.spec->>'dimension'=h.dimension
 AND policy.spec->'execution_enabled'='true'::jsonb AND (policy.spec->>'floor')::integer<=jsonb_array_length(members)
 AND (policy.spec->>'ceiling')::integer>=jsonb_array_length(members)
 AND policy.spec#>>'{mutation_bindings,0,profile_name}'=r->>'profile'
 AND public.preaction_failed_plan_graph_valid(workflow.spec,h.namespace,policy.name,policy.spec#>>'{mutation_bindings,0,name}')) IS NOT TRUE THEN RETURN false; END IF;
 IF (jsonb_typeof(canaries)='object' AND jsonb_typeof(canaries->'authority_markers')='array' AND jsonb_array_length(canaries->'authority_markers')=3) IS NOT TRUE THEN RETURN false; END IF;
 FOR k IN 0..2 LOOP
  a=canaries->'authority_markers'->k;
  SELECT * INTO STRICT issue FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_reconcile' AND issue_id=(a->>'issue_id')::uuid;
  m=convert_from(decode(issue.original_record->>'installed_reconcile_marker_base64','base64'),'UTF8')::jsonb;
  SELECT * INTO STRICT job FROM public.capacity_dispatch_jobs WHERE id=(jobs->k->>'id')::uuid;
  SELECT * INTO STRICT run FROM public.workflow_runs WHERE id=(runs->k->>'id')::uuid;
  env=(jobs->k->>'envelope')::jsonb;
  IF (to_jsonb(issue)=a AND to_jsonb(job)=jobs->k AND to_jsonb(run)=runs->k
  AND issue.policy_id=policy.id AND issue.workflow_id=workflow.id AND issue.issuer_actual_source_commit=r->>'old_issuer_core_source'
  AND issue.protocol_authority_source_commit=policy.spec#>>'{guest_retirement_binding,core_authority_source_commit}'
  AND issue.profile=r->>'profile' AND issue.executor_id=m->>'new_executor_id'
  AND issue.issue_id::text=m->>'new_run_id' AND issue.issued_wire_sha256=encode(sha256(decode(issue.original_record->>'installed_reconcile_marker_base64','base64')),'hex')
  AND m->>'schema'='installed_original_guest_readiness_reconcile_v1' AND m->'attempt'=to_jsonb(k+1)
  AND m->>'installed_provision_timeout_disposition_id'=h.original_disposition_id::text AND m->>'original_job_id'=origin.job_id::text AND m->>'original_run_id'=origin.run_id::text
  AND m->'original_generation'=r->'exhausted_generation' AND m->'original_fence'=origin.original_record->'fencing_token'
  AND m->>'preregistration_id'=origin.original_record->>'preregistration_id'
  AND m->>'enrollment_sha256'=old_m->>'enrollment_sha256' AND m->>'installation_sha256'=old_m->>'installation_sha256'
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(members)x WHERE x->>'preregistration_id'=m->>'preregistration_id' AND x->>'enrollment_sha256'=m->>'enrollment_sha256' AND x->>'installation_sha256'=m->>'installation_sha256')
  AND m->'original_failure_preserved'='true'::jsonb AND m->'original_quiescence_or_no_effect_claimed'='false'::jsonb
  AND (m->>'new_fence')::bigint=(origin.original_record->>'fencing_token')::bigint+k+1
  AND (m->>'previous_fence')::bigint=(m->>'new_fence')::bigint-1
  AND m->>'original_run_sha256'=origin.original_record->>'original_run_sha256'
  AND job.realm=h.namespace AND job.environment=h.environment AND job.domain=h.domain AND job.dimension=h.dimension
  AND env->'policy'=original_env->'policy' AND env->'workflow'=original_env->'workflow'
  AND issue.recorded_at>=job.started_at AND issue.recorded_at<=job.returned_at AND job.finalization_ack_at<=h.recorded_at
  AND public.installed_readiness_failed_ack_valid(jobs->k,runs->k,m)) IS NOT TRUE THEN RETURN false; END IF;
  IF k=0 THEN
   IF coalesce(m->>'previous_resume_run_id','')<>'' OR coalesce(m->>'previous_resume_run_sha256','')<>'' THEN RETURN false; END IF;
  ELSE
   IF m->>'previous_resume_run_id' IS DISTINCT FROM runs->(k-1)->>'id'
   OR m->>'previous_resume_run_sha256' IS DISTINCT FROM (SELECT encode(sha256(convert_to(row_to_json(x)::text,'UTF8')),'hex') FROM public.workflow_runs x WHERE x.id=(runs->(k-1)->>'id')::uuid)
   THEN RETURN false; END IF;
  END IF;
  IF k=2 AND m IS DISTINCT FROM old_m THEN RETURN false; END IF;
  fs=array_append(fs,(m->>'new_fence')::bigint); prev=m;
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(canaries->'challenges')x WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(canaries->'authority_markers')am WHERE x->>'fence'=(convert_from(decode(am#>>'{original_record,installed_reconcile_marker_base64}','base64'),'UTF8')::jsonb->>'new_fence') AND x->>'executor_id'=am->>'executor_id')) THEN RETURN false; END IF;
 IF public.installed_readiness_closed_canaries_valid(canaries,policy.id,workflow.id,(r->>'exhausted_generation')::bigint,fs,h.recorded_at) IS DISTINCT FROM true THEN RETURN false; END IF;
 IF mark IS DISTINCT FROM jsonb_build_object('schema','installed_readiness_exhausted_handoff_v1','handoff_id',h.id,'handoff_sha256',h.record_sha256,'original_disposition_id',h.original_disposition_id,
  'exhausted_generation',r->'exhausted_generation','exhausted_fence',r->'exhausted_fence','claim_generation',r->'successor_generation','claim_fence',r->'successor_fence',
  'run_id',h.successor_run_id,'executor_id',r->>'successor_executor_id','core_source',r->>'admitting_core_source') THEN RETURN false; END IF;
 IF (next_i->'installed_readiness_handoff'=mark AND NOT next_i ? 'installed_guest_reconcile'
 AND next_i->'generation'=r->'successor_generation' AND next_i->'fencing_token'=r->'successor_fence' AND next_i->>'phase'='preparing'
 AND next_i->>'lease_owner'=r->>'successor_lease_owner' AND next_i->>'lease_executor_id'=r->>'successor_executor_id'
 AND next_i->>'lease_owner'<>old_i->>'lease_owner' AND next_i->>'lease_executor_id'<>old_i->>'lease_executor_id'
 AND (next_i->>'lease_expires_at')::timestamptz=(r->>'successor_lease_expires_at')::timestamptz
 AND (next_i->>'lease_expires_at')::timestamptz>h.recorded_at
 AND (next_i->>'lease_expires_at')::timestamptz<=h.recorded_at+interval '90 seconds'
 AND (next_i->>'updated_at')::timestamptz=h.recorded_at
 AND (next_i-ARRAY['installed_readiness_handoff','generation','fencing_token','phase','lease_owner','lease_executor_id','lease_expires_at','assessment','baseline_snapshot','updated_at','decision'])=(old_i-ARRAY['installed_guest_reconcile','generation','fencing_token','phase','lease_owner','lease_executor_id','lease_expires_at','assessment','baseline_snapshot','updated_at','decision'])
 AND ((next_i->'decision')-ARRAY['action','reason','execution_permitted'])=((old_i->'decision')-ARRAY['action','reason','execution_permitted'])
 AND next_i#>>'{decision,action}'='hold' AND next_i#>>'{decision,reason}'='installed_readiness_exhausted_terminal_readonly_reconcile'
 AND next_i#>'{decision,execution_permitted}'='false'::jsonb
 AND next_i->'baseline_snapshot'=next_i#>'{assessment,snapshot}'
 AND next_i#>'{assessment,snapshot,units}'=r->'members_count' AND next_i#>>'{assessment,snapshot,profile}'=r->>'profile') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO STRICT issue FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_readiness_handoff' AND issue_id=h.successor_run_id;
 IF issue.policy_id<>policy.id OR issue.workflow_id<>workflow.id OR issue.issuer_actual_source_commit IS DISTINCT FROM r->>'admitting_core_source'
 OR issue.executor_id IS DISTINCT FROM r->>'successor_executor_id' OR issue.profile IS DISTINCT FROM r->>'profile'
 OR issue.protocol_authority_source_commit IS DISTINCT FROM policy.spec#>>'{guest_retirement_binding,core_authority_source_commit}'
 OR issue.issued_wire_sha256 IS DISTINCT FROM encode(sha256(h.marker_wire),'hex') THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.installed_readiness_handoff_members_match(h public.capacity_installed_readiness_exhausted_handoffs)
RETURNS boolean LANGUAGE sql STABLE SET timezone='UTC' AS $$
 SELECT coalesce((SELECT count(*) FROM public.capacity_resource_slots s WHERE s.namespace=h.namespace AND s.environment=h.environment AND s.domain=h.domain AND s.dimension=h.dimension AND s.resource_id<>'' AND s.slot_record->'tombstone'='false'::jsonb)=(h.original_record->>'members_count')::integer
 AND NOT EXISTS(SELECT 1 FROM public.capacity_resource_slots s WHERE s.namespace=h.namespace AND s.environment=h.environment AND s.domain=h.domain AND s.dimension=h.dimension
  AND (s.slot_record ? 'authority_kind' OR s.resource_id<>'' AND jsonb_typeof(s.slot_record->'tombstone') IS DISTINCT FROM 'boolean' OR s.resource_id<>'' AND s.slot_record->'tombstone'='false'::jsonb AND NOT EXISTS(
   SELECT 1 FROM jsonb_array_elements(convert_from(h.members_wire,'UTF8')::jsonb)m JOIN public.capacity_mutation_grants g ON g.id=(m->>'create_grant_id')::uuid
   WHERE s.integration_instance_id::text=m#>>'{tuple,integration_instance_id}' AND s.scope_checksum=m#>>'{tuple,scope_checksum}' AND s.profile_name=m#>>'{tuple,profile}' AND s.slot=(m->>'slot')::integer
   AND s.resource_id=m#>>'{tuple,resource_id}' AND s.slot_record->>'resource_id'=s.resource_id AND s.slot_record->>'resource_created_at'=m#>>'{tuple,resource_created_at}' AND s.slot_record->>'desired_spec_sha256'=m->>'request_sha256'
   AND g.namespace=h.namespace AND g.environment=h.environment AND g.domain=h.domain AND g.dimension=h.dimension AND g.state='confirmed' AND NOT(g.grant_record ? 'authority_kind')
   AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL))),false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_readiness_handoff_insert() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE current_i jsonb; policy public.manifests; workflow public.manifests; job public.capacity_dispatch_jobs; run public.workflow_runs; env jsonb; first_started timestamptz;
BEGIN
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension]) x WHERE x !~ '^[ -~]+$' OR x ~ '[<>&]') THEN RAISE EXCEPTION 'readiness handoff requires exact scope encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension])::text,0));
 SELECT intent INTO STRICT current_i FROM public.capacity_intents WHERE namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension FOR UPDATE;
 SELECT * INTO STRICT policy FROM public.manifests WHERE id=(NEW.original_record->>'policy_id')::uuid FOR SHARE;
 SELECT * INTO STRICT workflow FROM public.manifests WHERE id=(NEW.original_record->>'workflow_id')::uuid FOR SHARE;
 PERFORM x.id FROM public.capacity_dispatch_jobs x WHERE x.id IN(SELECT (j->>'id')::uuid FROM jsonb_array_elements(convert_from(NEW.failed_jobs_wire,'UTF8')::jsonb)j) ORDER BY x.id FOR SHARE;
 PERFORM x.id FROM public.workflow_runs x WHERE x.id IN(SELECT (w->>'id')::uuid FROM jsonb_array_elements(convert_from(NEW.failed_runs_wire,'UTF8')::jsonb)w) ORDER BY x.id FOR SHARE;
 PERFORM slot FROM public.capacity_resource_slots WHERE namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE;
 PERFORM id FROM public.capacity_mutation_grants WHERE namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension ORDER BY id FOR SHARE;
 SELECT * INTO STRICT job FROM public.capacity_dispatch_jobs WHERE id=NEW.successor_job_id FOR SHARE;
 SELECT * INTO STRICT run FROM public.workflow_runs WHERE id=NEW.successor_run_id FOR SHARE;
 env=job.envelope::jsonb;
 IF EXISTS(SELECT 1 FROM public.capacity_installed_readiness_exhausted_handoffs prior WHERE prior.namespace=NEW.namespace AND prior.environment=NEW.environment AND prior.domain=NEW.domain AND prior.dimension=NEW.dimension AND (prior.original_record->>'successor_generation')::bigint=(NEW.original_record->>'exhausted_generation')::bigint)
 OR current_i IS DISTINCT FROM convert_from(NEW.original_intent_wire,'UTF8')::jsonb
 OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 OR NOT policy.active OR NOT workflow.active
 OR public.installed_readiness_handoff_valid(NEW) IS DISTINCT FROM true OR public.installed_readiness_handoff_members_match(NEW) IS DISTINCT FROM true
 OR job.run_id<>NEW.successor_run_id OR job.state<>'started' OR job.returned_at IS NOT NULL OR job.finalization_ack_at IS NOT NULL
 OR job.lease_expires_at<=clock_timestamp() OR run.status<>'running' OR run.finished_at IS NOT NULL
 OR job.realm<>NEW.namespace OR job.environment<>NEW.environment OR job.domain<>NEW.domain OR job.dimension<>NEW.dimension
 OR env->>'protocol' IS DISTINCT FROM 'capacity_dispatch_prestart_v1' OR env->>'job_id' IS DISTINCT FROM job.id::text OR env->>'run_id' IS DISTINCT FROM run.id::text
 OR encode(sha256(convert_to(job.envelope,'UTF8')),'hex')<>job.envelope_sha256
 OR env#>>'{metadata,triggered_by}' IS DISTINCT FROM 'workflow_scheduler' OR env#>>'{metadata,capacity_dispatch_job_id}' IS DISTINCT FROM job.id::text
 OR run.metadata->>'triggered_by' IS DISTINCT FROM 'workflow_scheduler' OR run.metadata->>'capacity_dispatch_job_id' IS DISTINCT FROM job.id::text
 OR env#>>'{policy,id}' IS DISTINCT FROM policy.id::text OR env#>>'{policy,checksum}' IS DISTINCT FROM policy.checksum
 OR env#>>'{workflow,id}' IS DISTINCT FROM workflow.id::text OR env#>>'{workflow,checksum}' IS DISTINCT FROM workflow.checksum
 OR (env-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256']) IS DISTINCT FROM ((SELECT j->>'envelope' FROM jsonb_array_elements(convert_from(NEW.failed_jobs_wire,'UTF8')::jsonb)j LIMIT 1)::jsonb-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256'])
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(convert_from(NEW.failed_jobs_wire,'UTF8')::jsonb)j WHERE j->>'id'=job.id::text OR j->>'run_id'=run.id::text OR j->>'source_tick'=job.source_tick)
 OR (NEW.original_record->>'successor_lease_expires_at')::timestamptz>job.lease_expires_at
 OR (NEW.original_record->>'successor_lease_expires_at')::timestamptz>NEW.recorded_at+make_interval(secs=>least((policy.spec->>'lease_seconds')::integer,90))
 THEN RAISE EXCEPTION 'readiness handoff requires exact exhausted epoch and distinct live scheduler owner'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs x WHERE x.realm=NEW.namespace AND x.environment=NEW.environment AND x.domain=NEW.domain AND x.dimension=NEW.dimension AND x.id<>job.id
  AND(x.state IN('queued','started','unknown') OR x.state='returned' AND x.finalization_ack_at IS NULL))
 OR EXISTS(SELECT 1 FROM public.workflow_runs x WHERE x.id<>run.id AND (x.workflow_id=workflow.id OR x.workflow_id IS NULL AND x.workflow_namespace=workflow.namespace AND x.workflow_name=workflow.name)
  AND(coalesce(x.status,'')NOT IN('succeeded','failed','cancelled') OR x.finished_at IS NULL))
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.namespace=NEW.namespace AND g.environment=NEW.environment AND g.domain=NEW.domain AND g.dimension=NEW.dimension
  AND NOT(g.grant_record ? 'authority_kind') AND g.state IN('issued','redeemed','settled','compensating')
  AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL)
 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots s WHERE s.namespace=NEW.namespace AND s.environment=NEW.environment AND s.domain=NEW.domain AND s.dimension=NEW.dimension AND s.resource_id<>'' AND s.slot_record->'tombstone'='false'::jsonb
  AND (jsonb_typeof(s.slot_record->'observed_at')='string' AND isfinite((s.slot_record->>'observed_at')::timestamptz) AND (s.slot_record->>'observed_at')::timestamptz BETWEEN NEW.recorded_at-make_interval(secs=>(policy.spec->>'max_evidence_age_seconds')::integer) AND NEW.recorded_at+interval '5 seconds') IS NOT TRUE)
 THEN RAISE EXCEPTION 'readiness handoff requires complete fresh installed tuples and zero unresolved owners'; END IF;
 SELECT min((j->>'started_at')::timestamptz) INTO first_started FROM jsonb_array_elements(convert_from(NEW.failed_jobs_wire,'UTF8')::jsonb)j;
 IF EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.namespace=NEW.namespace AND g.environment=NEW.environment AND g.domain=NEW.domain AND g.dimension=NEW.dimension AND (g.updated_at>=first_started OR jsonb_typeof(g.grant_record->'created_at')='string' AND g.grant_record->>'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T' AND (g.grant_record->>'created_at')::timestamptz>=first_started))
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents t JOIN jsonb_array_elements(convert_from(NEW.members_wire,'UTF8')::jsonb)m ON t.preregistration_id::text=m->>'preregistration_id')
 THEN RAISE EXCEPTION 'readiness handoff cannot conceal provider authority or retirement'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.installed_readiness_handoff_fresh_canaries(h public.capacity_installed_readiness_exhausted_handoffs)
RETURNS boolean LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE n integer:=(h.original_record->>'members_count')::integer; g bigint:=(h.original_record->>'successor_generation')::bigint; f bigint:=(h.original_record->>'successor_fence')::bigint; p uuid:=(h.original_record->>'policy_id')::uuid; age integer; member jsonb;
BEGIN
 SELECT (spec->>'max_evidence_age_seconds')::integer INTO STRICT age FROM public.manifests WHERE id=p;
 IF (SELECT count(*) FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=p AND c.generation=g AND c.fence=f)<>2*n THEN RETURN false; END IF;
 FOR member IN SELECT x FROM jsonb_array_elements(convert_from(h.members_wire,'UTF8')::jsonb)x LOOP
  -- Exactly one publication and its own distinct read; no old ID is replayed.
  IF (SELECT count(*) FROM public.capacity_guest_notify_canary_challenges c
   JOIN public.capacity_guest_notify_canary_returns r ON r.challenge_id=c.id
   JOIN public.capacity_guest_notify_canary_sends s ON s.challenge_id=c.id
   JOIN public.capacity_guest_notify_canary_nonces no ON no.challenge_id=c.id
   JOIN public.capacity_guest_authority_issues a ON a.issue_kind='canary_challenge' AND a.issue_id=c.id
   WHERE c.policy_id=p AND c.generation=g AND c.fence=f AND c.preregistration_id::text=member->>'preregistration_id'
   AND c.workflow_id=(h.original_record->>'workflow_id')::uuid AND c.executor_id=h.original_record->>'successor_executor_id' AND c.lease_owner=h.original_record->>'successor_lease_owner'
   AND c.recorded_at>=h.recorded_at AND c.original_deadline<=(h.original_record->>'successor_lease_expires_at')::timestamptz
   AND r.outcome='accepted' AND r.original_wire IS NOT NULL AND r.return_sha256=encode(sha256(r.original_wire),'hex')
   AND r.business_observation IS NOT NULL AND r.recorded_at>=clock_timestamp()-make_interval(secs=>age) AND r.recorded_at<=clock_timestamp()+interval '5 seconds'
   AND a.issuer_actual_source_commit=h.original_record->>'admitting_core_source' AND a.policy_id=p AND a.workflow_id=c.workflow_id AND a.executor_id=c.executor_id
   AND a.issued_wire_sha256=c.challenge_sha256
   AND (c.phase='publish' AND c.record_challenge_id=c.id OR c.phase='read' AND c.record_challenge_id<>c.id
    AND EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges pub JOIN public.capacity_guest_notify_canary_returns pr ON pr.challenge_id=pub.id
      WHERE pub.id=c.record_challenge_id AND pub.phase='publish' AND pub.preregistration_id=c.preregistration_id AND pub.policy_id=p AND pub.generation=g AND pub.fence=f AND pr.outcome='accepted')))=2 IS NOT TRUE
  OR (SELECT count(DISTINCT c.phase) FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=p AND c.generation=g AND c.fence=f AND c.preregistration_id::text=member->>'preregistration_id')<>2
  THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- The only additional M98 transition: exact archived exhausted OLD to its
-- exact first successor. This cannot authorize another OLD marker or child.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.installed_readiness_handoff_transition(old_i jsonb,next_i jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE h public.capacity_installed_readiness_exhausted_handoffs;
BEGIN
 IF old_i ? 'installed_readiness_handoff' OR next_i ? 'installed_guest_reconcile' THEN RETURN false; END IF;
 SELECT * INTO STRICT h FROM public.capacity_installed_readiness_exhausted_handoffs WHERE id=(next_i#>>'{installed_readiness_handoff,handoff_id}')::uuid;
 RETURN old_i=convert_from(h.original_intent_wire,'UTF8')::jsonb AND next_i=convert_from(h.successor_intent_wire,'UTF8')::jsonb
  AND public.installed_readiness_handoff_valid(h) AND public.installed_readiness_handoff_members_match(h);
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_readiness_handoff_intent() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE h public.capacity_installed_readiness_exhausted_handoffs; first_i jsonb; marker jsonb; job public.capacity_dispatch_jobs; run public.workflow_runs;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.intent ? 'installed_readiness_handoff' THEN RAISE EXCEPTION 'readiness handoff requires retained prior intent'; END IF;
  RETURN NEW;
 END IF;
 IF NOT OLD.intent ? 'installed_readiness_handoff' THEN
  IF NEW.intent ? 'installed_readiness_handoff' AND public.installed_readiness_handoff_transition(OLD.intent,NEW.intent) IS DISTINCT FROM true THEN RAISE EXCEPTION 'readiness handoff requires exact archived transition'; END IF;
  RETURN NEW;
 END IF;
 marker=OLD.intent->'installed_readiness_handoff';
 SELECT * INTO STRICT h FROM public.capacity_installed_readiness_exhausted_handoffs WHERE id=(marker->>'handoff_id')::uuid;
 IF public.installed_readiness_handoff_valid(h) IS DISTINCT FROM true THEN RAISE EXCEPTION 'readiness handoff archive is not valid'; END IF;
 IF NOT NEW.intent ? 'installed_readiness_handoff' THEN
  IF (OLD.intent->>'phase'='promoted' AND coalesce(OLD.intent->>'lease_owner','')='' AND coalesce(OLD.intent->>'lease_executor_id','')=''
   AND coalesce(OLD.intent->'lease_expires_at','null'::jsonb)='null'::jsonb
   AND NOT NEW.intent ? 'installed_guest_reconcile'
   AND coalesce(NEW.intent->>'lease_owner','')='' AND coalesce(NEW.intent->>'lease_executor_id','')='' AND coalesce(NEW.intent->'lease_expires_at','null'::jsonb)='null'::jsonb
   AND NEW.intent->'fencing_token'=OLD.intent->'fencing_token'
   AND (NEW.intent->'generation'=OLD.intent->'generation' AND NEW.intent->>'phase' IN('hold','promoted')
    OR NEW.intent->'generation'=to_jsonb((OLD.intent->>'generation')::bigint+1) AND NEW.intent->>'phase'='proposed')
   AND NEW.intent->'namespace'=OLD.intent->'namespace' AND NEW.intent->'environment'=OLD.intent->'environment' AND NEW.intent->'domain'=OLD.intent->'domain' AND NEW.intent->'dimension'=OLD.intent->'dimension'
   AND (NEW.namespace,NEW.environment,NEW.domain,NEW.dimension)=(OLD.namespace,OLD.environment,OLD.domain,OLD.dimension)) IS NOT TRUE
  THEN RAISE EXCEPTION 'readiness handoff cannot be dropped before stable unleased continuity'; END IF;
  RETURN NEW;
 END IF;
 first_i=convert_from(h.successor_intent_wire,'UTF8')::jsonb;
 IF NEW.intent->'installed_readiness_handoff' IS DISTINCT FROM marker
 OR (NEW.intent-ARRAY['phase','assessment','updated_at','lease_owner','lease_executor_id','lease_expires_at','decision']) IS DISTINCT FROM(first_i-ARRAY['phase','assessment','updated_at','lease_owner','lease_executor_id','lease_expires_at','decision'])
 OR ((NEW.intent->'decision')-'clock') IS DISTINCT FROM((first_i->'decision')-'clock')
 OR public.installed_readiness_handoff_members_match(h) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'readiness handoff cannot reset origin, generation, fence or immutable membership'; END IF;
 SELECT * INTO STRICT job FROM public.capacity_dispatch_jobs WHERE id=h.successor_job_id;
 SELECT * INTO STRICT run FROM public.workflow_runs WHERE id=h.successor_run_id;
 IF job.state<>'started' OR job.returned_at IS NOT NULL OR job.finalization_ack_at IS NOT NULL OR run.status<>'running' OR run.finished_at IS NOT NULL
 OR job.lease_expires_at<=clock_timestamp() OR (OLD.intent->>'lease_expires_at')::timestamptz<=clock_timestamp()
 OR OLD.intent->>'lease_owner' IS DISTINCT FROM h.original_record->>'successor_lease_owner' OR OLD.intent->>'lease_executor_id' IS DISTINCT FROM h.original_record->>'successor_executor_id'
 OR (OLD.intent->>'lease_expires_at')::timestamptz IS DISTINCT FROM (h.original_record->>'successor_lease_expires_at')::timestamptz
 THEN RAISE EXCEPTION 'readiness handoff requires its original live scheduler epoch'; END IF;
 IF NEW.intent->>'phase' IS NOT DISTINCT FROM OLD.intent->>'phase' THEN
  IF NEW.intent->'decision' IS DISTINCT FROM OLD.intent->'decision' OR NEW.intent->>'lease_owner' IS DISTINCT FROM OLD.intent->>'lease_owner'
   OR NEW.intent->>'lease_executor_id' IS DISTINCT FROM OLD.intent->>'lease_executor_id' OR NEW.intent->'lease_expires_at' IS DISTINCT FROM OLD.intent->'lease_expires_at'
  THEN RAISE EXCEPTION 'readiness handoff cannot renew or replace its lease'; END IF;
 ELSIF (OLD.intent->>'phase'='preparing' AND NEW.intent->>'phase'='prepared' OR OLD.intent->>'phase'='prepared' AND NEW.intent->>'phase'='canary' OR OLD.intent->>'phase'='canary' AND NEW.intent->>'phase'='promoted') IS NOT TRUE
  OR public.installed_readiness_handoff_fresh_canaries(h) IS DISTINCT FROM true THEN RAISE EXCEPTION 'readiness handoff requires fresh full canaries and exact phase order';
 END IF;
 IF NEW.updated_at IS DISTINCT FROM (NEW.intent->>'updated_at')::timestamptz THEN RAISE EXCEPTION 'readiness handoff intent stamp must match row'; END IF;
 IF NEW.intent->>'phase'='promoted' THEN
  IF ((NEW.intent#>'{decision,clock}')-ARRAY['last_action_at','up_since','down_since']) IS DISTINCT FROM ((OLD.intent#>'{decision,clock}')-ARRAY['last_action_at','up_since','down_since'])
   OR (NEW.intent#>>'{decision,clock,last_action_at}')::timestamptz IS DISTINCT FROM (NEW.intent->>'updated_at')::timestamptz
   OR NEW.intent#>>'{decision,clock,up_since}' IS DISTINCT FROM '0001-01-01T00:00:00Z'
   OR NEW.intent#>>'{decision,clock,down_since}' IS DISTINCT FROM '0001-01-01T00:00:00Z'
  THEN RAISE EXCEPTION 'readiness handoff promotion must retain its original decision clock'; END IF;
  IF (coalesce(NEW.intent->>'lease_owner','')='' AND coalesce(NEW.intent->>'lease_executor_id','')='' AND coalesce(NEW.intent->'lease_expires_at','null'::jsonb)='null'::jsonb) IS NOT TRUE
  THEN RAISE EXCEPTION 'readiness handoff promotion must release its original lease'; END IF;
 ELSE
  IF NEW.intent->>'lease_owner' IS DISTINCT FROM OLD.intent->>'lease_owner' OR NEW.intent->>'lease_executor_id' IS DISTINCT FROM OLD.intent->>'lease_executor_id' OR NEW.intent->'lease_expires_at' IS DISTINCT FROM OLD.intent->'lease_expires_at'
   OR NEW.intent->'decision' IS DISTINCT FROM OLD.intent->'decision' THEN RAISE EXCEPTION 'readiness handoff cannot renew its original lease'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.require_installed_readiness_handoff_links() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE actual jsonb; issue public.capacity_guest_authority_issues;
BEGIN
 SELECT intent INTO STRICT actual FROM public.capacity_intents WHERE namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension;
 SELECT * INTO STRICT issue FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_readiness_handoff' AND issue_id=NEW.successor_run_id;
 IF actual IS DISTINCT FROM convert_from(NEW.successor_intent_wire,'UTF8')::jsonb OR public.installed_readiness_handoff_valid(NEW) IS DISTINCT FROM true
 OR issue.issuer_actual_source_commit IS DISTINCT FROM NEW.original_record->>'admitting_core_source'
 OR issue.policy_id::text IS DISTINCT FROM NEW.original_record->>'policy_id' OR issue.workflow_id::text IS DISTINCT FROM NEW.original_record->>'workflow_id'
 OR issue.executor_id IS DISTINCT FROM NEW.original_record->>'successor_executor_id' OR issue.profile IS DISTINCT FROM NEW.original_record->>'profile'
 OR issue.issued_wire_sha256 IS DISTINCT FROM encode(sha256(NEW.marker_wire),'hex')
 THEN RAISE EXCEPTION 'readiness handoff requires atomic successor and actual issuer'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd

-- No provider mutation grant can ever belong to the readiness-only generation,
-- including after its stable marker is removed by ordinary later assessment.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_readiness_handoff_no_grant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_installed_readiness_exhausted_handoffs h WHERE h.namespace=NEW.namespace AND h.environment=NEW.environment AND h.domain=NEW.domain AND h.dimension=NEW.dimension AND (h.original_record->>'successor_generation')::bigint=NEW.generation)
 THEN RAISE EXCEPTION 'readiness handoff generation cannot acquire provider mutation authority'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_readiness_handoff_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='capacity_dispatch_jobs' THEN
  IF EXISTS(SELECT 1 FROM public.capacity_installed_readiness_exhausted_handoffs h,jsonb_array_elements(convert_from(h.failed_jobs_wire,'UTF8')::jsonb)x WHERE x->>'id'=OLD.id::text)
   AND (TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'readiness handoff failed dispatch is immutable'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.capacity_installed_readiness_exhausted_handoffs h,jsonb_array_elements(convert_from(h.failed_runs_wire,'UTF8')::jsonb)x WHERE x->>'id'=OLD.id::text)
   AND (TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'readiness handoff failed workflow is immutable'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $triggers$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_installed_readiness_exhausted_handoffs'::regclass AND tgname='installed_readiness_handoff_insert') THEN
  CREATE TRIGGER installed_readiness_handoff_insert BEFORE INSERT ON public.capacity_installed_readiness_exhausted_handoffs FOR EACH ROW EXECUTE FUNCTION public.guard_installed_readiness_handoff_insert();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_installed_readiness_exhausted_handoffs'::regclass AND tgname='installed_readiness_handoff_immutable') THEN
  CREATE TRIGGER installed_readiness_handoff_immutable BEFORE UPDATE OR DELETE ON public.capacity_installed_readiness_exhausted_handoffs FOR EACH ROW EXECUTE FUNCTION public.immutable_installed_readiness_handoff();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_installed_readiness_exhausted_handoffs'::regclass AND tgname='installed_readiness_handoff_complete_links') THEN
  CREATE CONSTRAINT TRIGGER installed_readiness_handoff_complete_links AFTER INSERT ON public.capacity_installed_readiness_exhausted_handoffs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_installed_readiness_handoff_links();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_intents'::regclass AND tgname='installed_readiness_handoff_intent') THEN
  CREATE TRIGGER installed_readiness_handoff_intent BEFORE INSERT OR UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION public.guard_installed_readiness_handoff_intent();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_mutation_grants'::regclass AND tgname='installed_readiness_handoff_no_grant') THEN
  CREATE TRIGGER installed_readiness_handoff_no_grant BEFORE INSERT OR UPDATE ON public.capacity_mutation_grants FOR EACH ROW EXECUTE FUNCTION public.guard_installed_readiness_handoff_no_grant();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_jobs'::regclass AND tgname='installed_readiness_handoff_failed_job') THEN
  CREATE TRIGGER installed_readiness_handoff_failed_job BEFORE UPDATE OR DELETE ON public.capacity_dispatch_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_installed_readiness_handoff_history();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.workflow_runs'::regclass AND tgname='installed_readiness_handoff_failed_run') THEN
  CREATE TRIGGER installed_readiness_handoff_failed_run BEFORE UPDATE OR DELETE ON public.workflow_runs FOR EACH ROW EXECUTE FUNCTION public.guard_installed_readiness_handoff_history();
 END IF;
END $triggers$;
-- +goose StatementEnd

-- The full old M98 body is byte-preserved below; only this single explicit
-- archive-qualified exception is inserted. Unknown old bodies fail closed.
-- +goose StatementBegin
DO $handoff_origin$ DECLARE old_body text:=$m98_original$
DECLARE marker jsonb; previous jsonb; receipt public.capacity_dispatch_installed_provision_timeout_dispositions;
BEGIN
 marker=NEW.intent->'installed_guest_reconcile';
 IF TG_OP='UPDATE' THEN
  previous=OLD.intent->'installed_guest_reconcile';
  IF previous ? 'installed_provision_timeout_disposition_id'
  AND previous->>'installed_provision_timeout_disposition_id' IS DISTINCT FROM marker->>'installed_provision_timeout_disposition_id'
  AND NOT COALESCE(OLD.intent->>'phase' IN('promoted','reconciled','reconciled_partial')
   AND coalesce(OLD.intent->>'lease_owner','')='' AND coalesce(OLD.intent->>'lease_executor_id','')=''
   AND coalesce(OLD.intent->'lease_expires_at','null'::jsonb)='null'::jsonb,false)
  THEN RAISE EXCEPTION 'installed timeout origin cannot be dropped before stable unleased state'; END IF;
 END IF;
 IF marker ? 'installed_provision_timeout_disposition_id' THEN
  SELECT * INTO STRICT receipt FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=(marker->>'installed_provision_timeout_disposition_id')::uuid;
  IF (public.installed_provision_timeout_valid(receipt.original_record,receipt.original_dispatch_wire,receipt.original_run_wire,receipt.original_intent_wire,receipt.members_wire)
  AND marker->>'schema'='installed_original_guest_readiness_reconcile_v1'
  AND marker->>'original_job_id'=receipt.job_id::text AND marker->>'original_run_id'=receipt.run_id::text
  AND marker->>'original_run_sha256'=receipt.original_record->>'original_run_sha256'
  AND marker->>'preregistration_id'=receipt.original_record->>'preregistration_id'
  AND marker->'original_generation'=receipt.original_record->'generation'
  AND marker->'original_fence'=receipt.original_record->'fencing_token'
  AND NEW.intent->'generation'=receipt.original_record->'generation'
  AND NEW.namespace=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'namespace'
  AND NEW.environment=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'environment'
  AND NEW.domain=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'domain'
  AND NEW.dimension=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'dimension'
  AND marker->'original_failure_preserved'='true'::jsonb
  AND marker->'original_quiescence_or_no_effect_claimed'='false'::jsonb
  AND jsonb_typeof(marker->'attempt')='number' AND marker->>'attempt' ~ '^[1-3]$'
  AND marker->'new_fence'=NEW.intent->'fencing_token'
  AND (marker->>'new_fence')::bigint=(marker->>'previous_fence')::bigint+1
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(receipt.original_record->'members') x WHERE x->>'preregistration_id'=marker->>'preregistration_id' AND x->>'enrollment_sha256'=marker->>'enrollment_sha256' AND x->>'installation_sha256'=marker->>'installation_sha256')) IS NOT TRUE
  THEN RAISE EXCEPTION 'installed timeout readiness origin must retain exact disposition'; END IF;
  IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'installed timeout readiness requires retained prior intent'; END IF;
  IF marker IS DISTINCT FROM previous THEN
   IF (NEW.intent->>'phase'='preparing' AND OLD.intent->>'phase' IN('preparing','prepared','canary')
   AND NEW.intent->'generation'=OLD.intent->'generation'
   AND (NEW.intent->>'fencing_token')::bigint=(OLD.intent->>'fencing_token')::bigint+1
   AND marker->'previous_fence'=OLD.intent->'fencing_token'
   AND NEW.intent->>'policy_id'=receipt.original_record->>'policy_id'
   AND NEW.intent->>'policy_checksum'=receipt.original_record->>'policy_checksum'
   AND (OLD.intent->>'lease_expires_at')::timestamptz<=clock_timestamp()
   AND (NEW.intent->>'lease_expires_at')::timestamptz>clock_timestamp()
   AND (NEW.intent->>'lease_expires_at')::timestamptz<=clock_timestamp()+interval '90 seconds'
   AND NEW.intent->>'lease_owner' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND NEW.intent->>'lease_owner'<>coalesce(OLD.intent->>'lease_owner','')
   AND NEW.intent->>'lease_executor_id'=marker->>'new_executor_id'
   AND marker->>'new_executor_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND marker->>'new_run_id'<>receipt.run_id::text
   AND (previous IS NULL AND marker->'attempt'='1'::jsonb
    OR previous->>'installed_provision_timeout_disposition_id'=receipt.id::text
     AND (marker->>'attempt')::integer=(previous->>'attempt')::integer+1
     AND marker->>'new_run_id'<>previous->>'new_run_id')
   AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
    WHERE j.run_id::text=marker->>'new_run_id' AND j.state='started' AND j.returned_at IS NULL
    AND j.lease_expires_at>clock_timestamp() AND w.status='running' AND w.finished_at IS NULL
    AND j.realm=NEW.namespace AND j.environment=NEW.environment AND j.domain=NEW.domain AND j.dimension=NEW.dimension
    AND j.envelope::jsonb->'policy'=(convert_from(receipt.original_dispatch_wire,'UTF8')::jsonb->>'envelope')::jsonb->'policy'
    AND j.envelope::jsonb->'workflow'=(convert_from(receipt.original_dispatch_wire,'UTF8')::jsonb->>'envelope')::jsonb->'workflow'
    AND w.metadata->>'triggered_by'='workflow_scheduler' AND w.metadata->>'capacity_dispatch_job_id'=j.id::text)) IS NOT TRUE
   THEN RAISE EXCEPTION 'installed timeout readiness requires distinct live fenced owner'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END; $m98_original$; new_body text; actual_body text;
BEGIN
 new_body=replace(old_body,E'BEGIN\n',E'BEGIN\n'||$handoff_exception$ IF TG_OP='UPDATE' AND OLD.intent ? 'installed_guest_reconcile' AND NEW.intent ? 'installed_readiness_handoff'
 AND public.installed_readiness_handoff_transition(OLD.intent,NEW.intent) IS TRUE THEN RETURN NEW; END IF;
$handoff_exception$);
 SELECT prosrc INTO STRICT actual_body FROM pg_proc WHERE oid='public.guard_installed_timeout_origin()'::regprocedure;
 IF actual_body IS DISTINCT FROM old_body AND actual_body IS DISTINCT FROM new_body THEN RAISE EXCEPTION 'readiness handoff refuses unknown M98 origin guard'; END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION public.guard_installed_timeout_origin() RETURNS trigger LANGUAGE plpgsql AS %L',new_body);
END $handoff_origin$;
-- +goose StatementEnd

-- +goose Down
-- A used origin cannot lose its one-shot tombstone or immutable failed wires.
-- +goose StatementBegin
DO $used$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_installed_readiness_exhausted_handoffs)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_readiness_handoff')
 THEN RAISE EXCEPTION 'used installed readiness handoff proof cannot be downgraded'; END IF;
END $used$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $handoff_origin$ DECLARE old_body text:=$m98_original$
DECLARE marker jsonb; previous jsonb; receipt public.capacity_dispatch_installed_provision_timeout_dispositions;
BEGIN
 marker=NEW.intent->'installed_guest_reconcile';
 IF TG_OP='UPDATE' THEN
  previous=OLD.intent->'installed_guest_reconcile';
  IF previous ? 'installed_provision_timeout_disposition_id'
  AND previous->>'installed_provision_timeout_disposition_id' IS DISTINCT FROM marker->>'installed_provision_timeout_disposition_id'
  AND NOT COALESCE(OLD.intent->>'phase' IN('promoted','reconciled','reconciled_partial')
   AND coalesce(OLD.intent->>'lease_owner','')='' AND coalesce(OLD.intent->>'lease_executor_id','')=''
   AND coalesce(OLD.intent->'lease_expires_at','null'::jsonb)='null'::jsonb,false)
  THEN RAISE EXCEPTION 'installed timeout origin cannot be dropped before stable unleased state'; END IF;
 END IF;
 IF marker ? 'installed_provision_timeout_disposition_id' THEN
  SELECT * INTO STRICT receipt FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=(marker->>'installed_provision_timeout_disposition_id')::uuid;
  IF (public.installed_provision_timeout_valid(receipt.original_record,receipt.original_dispatch_wire,receipt.original_run_wire,receipt.original_intent_wire,receipt.members_wire)
  AND marker->>'schema'='installed_original_guest_readiness_reconcile_v1'
  AND marker->>'original_job_id'=receipt.job_id::text AND marker->>'original_run_id'=receipt.run_id::text
  AND marker->>'original_run_sha256'=receipt.original_record->>'original_run_sha256'
  AND marker->>'preregistration_id'=receipt.original_record->>'preregistration_id'
  AND marker->'original_generation'=receipt.original_record->'generation'
  AND marker->'original_fence'=receipt.original_record->'fencing_token'
  AND NEW.intent->'generation'=receipt.original_record->'generation'
  AND NEW.namespace=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'namespace'
  AND NEW.environment=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'environment'
  AND NEW.domain=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'domain'
  AND NEW.dimension=convert_from(receipt.original_intent_wire,'UTF8')::jsonb->>'dimension'
  AND marker->'original_failure_preserved'='true'::jsonb
  AND marker->'original_quiescence_or_no_effect_claimed'='false'::jsonb
  AND jsonb_typeof(marker->'attempt')='number' AND marker->>'attempt' ~ '^[1-3]$'
  AND marker->'new_fence'=NEW.intent->'fencing_token'
  AND (marker->>'new_fence')::bigint=(marker->>'previous_fence')::bigint+1
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(receipt.original_record->'members') x WHERE x->>'preregistration_id'=marker->>'preregistration_id' AND x->>'enrollment_sha256'=marker->>'enrollment_sha256' AND x->>'installation_sha256'=marker->>'installation_sha256')) IS NOT TRUE
  THEN RAISE EXCEPTION 'installed timeout readiness origin must retain exact disposition'; END IF;
  IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'installed timeout readiness requires retained prior intent'; END IF;
  IF marker IS DISTINCT FROM previous THEN
   IF (NEW.intent->>'phase'='preparing' AND OLD.intent->>'phase' IN('preparing','prepared','canary')
   AND NEW.intent->'generation'=OLD.intent->'generation'
   AND (NEW.intent->>'fencing_token')::bigint=(OLD.intent->>'fencing_token')::bigint+1
   AND marker->'previous_fence'=OLD.intent->'fencing_token'
   AND NEW.intent->>'policy_id'=receipt.original_record->>'policy_id'
   AND NEW.intent->>'policy_checksum'=receipt.original_record->>'policy_checksum'
   AND (OLD.intent->>'lease_expires_at')::timestamptz<=clock_timestamp()
   AND (NEW.intent->>'lease_expires_at')::timestamptz>clock_timestamp()
   AND (NEW.intent->>'lease_expires_at')::timestamptz<=clock_timestamp()+interval '90 seconds'
   AND NEW.intent->>'lease_owner' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND NEW.intent->>'lease_owner'<>coalesce(OLD.intent->>'lease_owner','')
   AND NEW.intent->>'lease_executor_id'=marker->>'new_executor_id'
   AND marker->>'new_executor_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND marker->>'new_run_id'<>receipt.run_id::text
   AND (previous IS NULL AND marker->'attempt'='1'::jsonb
    OR previous->>'installed_provision_timeout_disposition_id'=receipt.id::text
     AND (marker->>'attempt')::integer=(previous->>'attempt')::integer+1
     AND marker->>'new_run_id'<>previous->>'new_run_id')
   AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
    WHERE j.run_id::text=marker->>'new_run_id' AND j.state='started' AND j.returned_at IS NULL
    AND j.lease_expires_at>clock_timestamp() AND w.status='running' AND w.finished_at IS NULL
    AND j.realm=NEW.namespace AND j.environment=NEW.environment AND j.domain=NEW.domain AND j.dimension=NEW.dimension
    AND j.envelope::jsonb->'policy'=(convert_from(receipt.original_dispatch_wire,'UTF8')::jsonb->>'envelope')::jsonb->'policy'
    AND j.envelope::jsonb->'workflow'=(convert_from(receipt.original_dispatch_wire,'UTF8')::jsonb->>'envelope')::jsonb->'workflow'
    AND w.metadata->>'triggered_by'='workflow_scheduler' AND w.metadata->>'capacity_dispatch_job_id'=j.id::text)) IS NOT TRUE
   THEN RAISE EXCEPTION 'installed timeout readiness requires distinct live fenced owner'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END; $m98_original$; new_body text; actual_body text;
BEGIN
 new_body=replace(old_body,E'BEGIN\n',E'BEGIN\n'||$handoff_exception$ IF TG_OP='UPDATE' AND OLD.intent ? 'installed_guest_reconcile' AND NEW.intent ? 'installed_readiness_handoff'
 AND public.installed_readiness_handoff_transition(OLD.intent,NEW.intent) IS TRUE THEN RETURN NEW; END IF;
$handoff_exception$);
 SELECT prosrc INTO STRICT actual_body FROM pg_proc WHERE oid='public.guard_installed_timeout_origin()'::regprocedure;
 IF actual_body IS DISTINCT FROM old_body AND actual_body IS DISTINCT FROM new_body THEN RAISE EXCEPTION 'readiness handoff refuses unknown M98 origin guard'; END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION public.guard_installed_timeout_origin() RETURNS trigger LANGUAGE plpgsql AS %L',old_body);
END $handoff_origin$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS installed_readiness_handoff_failed_run ON public.workflow_runs;
DROP TRIGGER IF EXISTS installed_readiness_handoff_failed_job ON public.capacity_dispatch_jobs;
DROP TRIGGER IF EXISTS installed_readiness_handoff_no_grant ON public.capacity_mutation_grants;
DROP TRIGGER IF EXISTS installed_readiness_handoff_intent ON public.capacity_intents;
DROP TRIGGER IF EXISTS installed_readiness_handoff_complete_links ON public.capacity_installed_readiness_exhausted_handoffs;
DROP TRIGGER IF EXISTS installed_readiness_handoff_immutable ON public.capacity_installed_readiness_exhausted_handoffs;
DROP TRIGGER IF EXISTS installed_readiness_handoff_insert ON public.capacity_installed_readiness_exhausted_handoffs;
DROP FUNCTION IF EXISTS public.guard_installed_readiness_handoff_history();
DROP FUNCTION IF EXISTS public.guard_installed_readiness_handoff_no_grant();
DROP FUNCTION IF EXISTS public.require_installed_readiness_handoff_links();
DROP FUNCTION IF EXISTS public.guard_installed_readiness_handoff_intent();
DROP FUNCTION IF EXISTS public.installed_readiness_handoff_transition(jsonb,jsonb);
DROP FUNCTION IF EXISTS public.installed_readiness_handoff_fresh_canaries(public.capacity_installed_readiness_exhausted_handoffs);
DROP FUNCTION IF EXISTS public.guard_installed_readiness_handoff_insert();
DROP FUNCTION IF EXISTS public.installed_readiness_handoff_members_match(public.capacity_installed_readiness_exhausted_handoffs);
DROP FUNCTION IF EXISTS public.installed_readiness_handoff_valid(public.capacity_installed_readiness_exhausted_handoffs);
DROP FUNCTION IF EXISTS public.installed_readiness_closed_canaries_valid(jsonb,uuid,uuid,bigint,bigint[],timestamptz);
DROP FUNCTION IF EXISTS public.installed_readiness_failed_ack_valid(jsonb,jsonb,jsonb);
DROP FUNCTION IF EXISTS public.immutable_installed_readiness_handoff();
DROP TABLE IF EXISTS public.capacity_installed_readiness_exhausted_handoffs;
