-- +goose Up
-- ADR-0112: preserve a recorded failed PLAN with no committed authority.
-- This distinct terminal is neither ACK/success nor provider quiescence/replay.
-- The applied M87/M91/M98 meanings and every old dispatch guard remain intact.
-- Regular transactional index: existing Goose lock/build limits remain in force.
CREATE INDEX IF NOT EXISTS capacity_dispatch_failed_workflow_returned_idx
 ON public.capacity_dispatch_jobs USING btree ((envelope::jsonb #>> '{workflow,id}'::text[]),returned_at)
 WHERE state='returned' AND return_status='failed' AND returned_at IS NOT NULL AND finalization_ack_at IS NOT NULL;


-- Exact UTC nanoseconds from the authenticated ISO wire, never a clock read.
-- PostgreSQL's timestamptz fraction is microsecond-quantized; retain all nine
-- raw response/step digits before comparing their causal order.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.preaction_failed_plan_timestamp_ns(value text)
RETURNS numeric LANGUAGE plpgsql IMMUTABLE SET timezone='UTC' AS $$
DECLARE parts text[]; whole timestamptz; answer numeric;
BEGIN
 parts=regexp_match(value,'^([0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])(?:[.]([0-9]{1,9}))?(Z|[+-][0-2][0-9]:[0-5][0-9])$');
 IF parts IS NULL THEN RETURN NULL;END IF;
 whole=(parts[1]||parts[3])::timestamptz;
 IF NOT isfinite(whole)THEN RETURN NULL;END IF;
 answer=extract(epoch FROM whole)*1000000000+substring(coalesce(parts[2],'')||'000000000' FROM 1 FOR 9)::numeric;
 IF answer=-62135596800000000000 THEN RETURN NULL;END IF;
 RETURN answer;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.preaction_failed_plan_graph_valid(spec jsonb,realm text,policy_name text,binding_name text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE ref jsonb; common jsonb; use_plan jsonb; want jsonb; step jsonb; n integer;
 ids text[]:=ARRAY['plan-original-guest','provision-original-notify','complete-original-provision','retire-original-guest','finish-original-retirement','complete-original-retirement','refresh-original-membership'];
 ops text[]:=ARRAY['capacity.plan_original_guest','capacity.provision_original_guest','capacity.complete_original_guest','capacity.retire_original_guest','capacity.finish_original_guest_retirement','capacity.complete_original_guest','capacity.complete_original_guest'];
 timeouts integer[]:=ARRAY[90,600,90,180,90,90,90];
BEGIN
 IF (jsonb_typeof(spec)='object' AND spec->>'dispatch_mode'='async' AND jsonb_typeof(spec->'authorization')='object'
 AND spec#>>'{trigger,mode}'='schedule' AND spec#>'{trigger,enabled}'='true'::jsonb AND jsonb_typeof(spec#>'{trigger,schedule}')='object'
 AND spec#>'{input_schema,required}'='["policy"]'::jsonb AND spec#>'{input_schema,additionalProperties}'='false'::jsonb
 AND (SELECT count(*)FROM jsonb_object_keys(spec#>'{input_schema,properties}'))=1 AND spec#>>'{input_schema,properties,policy,type}'='object'
 AND coalesce(spec->'defaults','{}'::jsonb)='{}'::jsonb AND jsonb_typeof(spec->'steps')='array' AND jsonb_array_length(spec->'steps')=7) IS NOT TRUE THEN RETURN false; END IF;
 ref=jsonb_build_object('namespace',realm,'name',policy_name);
 common=jsonb_build_object('policy',ref,'binding_name',binding_name,'slot','{{ steps.plan-original-guest.metadata.slot }}',
  'generation','{{ steps.plan-original-guest.metadata.generation }}','fencing_token','{{ steps.plan-original-guest.metadata.fencing_token }}','lease_owner','{{ steps.plan-original-guest.metadata.lease_owner }}');
 want='[]'::jsonb;
 FOR n IN 1..7 LOOP
  step=jsonb_build_object('id',ids[n],'use',jsonb_build_object('kind','yggdrasil','operation',ops[n]),
   'timeout_seconds',timeouts[n],'retry',jsonb_build_object('max_attempts',1));
  IF n=1 THEN step=step||jsonb_build_object('with',jsonb_build_object('policy',ref));
  ELSIF n=7 THEN step=step||jsonb_build_object('with',jsonb_build_object('policy',ref,'mode','refresh'),
   'condition','{{ steps.plan-original-guest.metadata.mode }} == refresh','depends_on',jsonb_build_array('plan-original-guest'));
  ELSE
   use_plan=common;
   IF n IN(3,6) THEN use_plan=use_plan||jsonb_build_object('mode',CASE n WHEN 3 THEN 'provision' ELSE 'retire' END); END IF;
   IF n IN(4,5) THEN use_plan=use_plan||jsonb_build_object('preregistration_id','{{ steps.plan-original-guest.metadata.preregistration_id }}'); END IF;
   IF n IN(5,6) THEN use_plan=use_plan||jsonb_build_object('request_id','{{ steps.retire-original-guest.metadata.request_id }}'); END IF;
   step=step||jsonb_build_object('with',use_plan,'condition',CASE WHEN n IN(2,3) THEN '{{ steps.plan-original-guest.metadata.mode }} == provision' ELSE '{{ steps.plan-original-guest.metadata.mode }} == retire' END,
    'depends_on',jsonb_build_array(CASE n WHEN 3 THEN 'provision-original-notify' WHEN 5 THEN 'retire-original-guest' WHEN 6 THEN 'finish-original-retirement' ELSE 'plan-original-guest' END));
  END IF;
  want=want||jsonb_build_array(step);
 END LOOP;
 RETURN spec->'steps'=want;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- Same enumerated M83/M84 ledgers and fixed thirty-second skew window.
-- No provider call, quiescence assertion or current caller flag is evidence.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.preaction_failed_plan_effect_scan(job uuid,anchor uuid)
RETURNS jsonb LANGUAGE sql STABLE SET timezone='UTC' AS $$
WITH j AS MATERIALIZED(SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 a AS MATERIALIZED(SELECT * FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=anchor),
 win AS(SELECT started_at-interval '30 seconds' AS t FROM j),
 it AS(SELECT intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),
 sl AS(SELECT s.* FROM public.capacity_resource_slots s,j WHERE s.namespace=j.realm AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension),
 g AS(SELECT g.* FROM public.capacity_mutation_grants g,j WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension),
 mem AS(SELECT x FROM a,jsonb_array_elements(a.original_record->'members')x),
 busy_runs AS(
  SELECT w.id FROM public.workflow_runs w,j WHERE w.workflow_id=(j.envelope::jsonb#>>'{workflow,id}')::uuid AND w.id<>j.run_id
   AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL)
  UNION
  SELECT w.id FROM public.workflow_runs w,j WHERE w.workflow_id IS NULL
   AND w.workflow_namespace=j.envelope::jsonb#>>'{workflow,namespace}' AND w.workflow_name=j.envelope::jsonb#>>'{workflow,name}' AND w.id<>j.run_id
   AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
SELECT jsonb_build_object('schema','preaction_failed_plan_effect_scan_v1',
 'base',(SELECT public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at)FROM j),
 'current_intent_matches_anchor',coalesce((SELECT it.intent=convert_from(a.original_intent_wire,'UTF8')::jsonb FROM it,a),false),
 'current_members_match_anchor',coalesce((SELECT
  (SELECT count(*)FROM sl WHERE resource_id<>'' AND slot_record->'tombstone'='false'::jsonb)=jsonb_array_length(a.original_record->'members')
  AND NOT EXISTS(SELECT 1 FROM sl WHERE sl.slot_record ? 'authority_kind' OR sl.resource_id<>'' AND sl.slot_record->'tombstone'='false'::jsonb AND NOT EXISTS(
   SELECT 1 FROM mem WHERE sl.integration_instance_id::text=x#>>'{tuple,integration_instance_id}' AND sl.scope_checksum=x#>>'{tuple,scope_checksum}'
   AND sl.profile_name=x#>>'{tuple,profile}' AND sl.slot=(x->>'slot')::integer AND sl.resource_id=x#>>'{tuple,resource_id}'
   AND sl.slot_record->>'resource_id'=sl.resource_id AND sl.slot_record->>'resource_created_at'=x#>>'{tuple,resource_created_at}'
   AND sl.slot_record->>'desired_spec_sha256'=x->>'request_sha256'
   AND EXISTS(SELECT 1 FROM g WHERE g.id::text=x->>'create_grant_id' AND g.state='confirmed' AND NOT(g.grant_record ? 'authority_kind')
    AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL)))
  FROM a),false),
 'other_busy_dispatches',(SELECT count(*)FROM public.capacity_dispatch_jobs x,j WHERE x.realm=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.id<>j.id
  AND(x.state IN('queued','started','unknown')OR x.state='returned'AND x.finalization_ack_at IS NULL)),
 'other_busy_runs',(SELECT count(*)FROM busy_runs),
 'authority_issues_since_start',(SELECT count(*)FROM public.capacity_guest_authority_issues x JOIN public.manifests p ON p.id=x.policy_id CROSS JOIN j,win
  WHERE(x.issue_id=j.run_id OR p.namespace=j.realm AND p.kind='capacity_policy'AND p.spec->>'environment'=j.environment AND p.spec->>'domain'=j.domain AND p.spec->>'dimension'=j.dimension)
   AND x.recorded_at>=win.t),
 'disposal_rows_since_start',(SELECT count(*)FROM public.capacity_guest_failed_installed_disposals x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t)
  +(SELECT count(*)FROM public.capacity_guest_failed_serving_disposals x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t),
 'retirement_forwards_since_start',(SELECT count(*)FROM public.capacity_guest_retirement_forwards x,j,win WHERE x.namespace=j.realm AND x.environment=j.environment AND x.domain=j.domain AND x.dimension=j.dimension AND x.recorded_at>=win.t),
 'retirement_forward_reads_since_start',(SELECT count(*)FROM public.capacity_guest_retirement_forward_reads x JOIN public.capacity_vm_retirement_intents r ON r.id=x.retirement_request_id JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id JOIN g ON g.id=p.create_grant_id CROSS JOIN win WHERE x.recorded_at>=win.t),
 'undisposed_grants',(SELECT count(*)FROM g WHERE g.state IN('issued','redeemed','settled','compensating')AND NOT(g.grant_record?'authority_kind')
  AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL))
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.preaction_failed_plan_effect_scan_tolerable(scan jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT coalesce(jsonb_typeof(scan)='object' AND(SELECT count(*)FROM jsonb_object_keys(scan))=11
 AND scan ?& ARRAY['schema','base','current_intent_matches_anchor','current_members_match_anchor','other_busy_dispatches','other_busy_runs','authority_issues_since_start','disposal_rows_since_start','retirement_forwards_since_start','retirement_forward_reads_since_start','undisposed_grants']
 AND scan->>'schema'='preaction_failed_plan_effect_scan_v1'
 AND scan->'current_intent_matches_anchor'='true'::jsonb AND scan->'current_members_match_anchor'='true'::jsonb
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan) x WHERE x.key NOT IN('schema','base','current_intent_matches_anchor','current_members_match_anchor')AND (jsonb_typeof(x.value)IS DISTINCT FROM 'number' OR x.value::text<>'0'))
 AND jsonb_typeof(scan->'base')='object' AND(SELECT count(*)FROM jsonb_object_keys(scan->'base'))=47
 AND(scan->'base') ?& ARRAY['schema','clock_skew_margin_seconds','grants_created_or_updated_since_start','open_undisposed_grants','preregistrations_since_start','create_witnesses_since_start','enrollments_since_start','installations_since_start','qualification_probe_challenges_since_start','qualification_native_source_returns_since_start','source_recovery_cleanup_challenges_since_start','source_recovery_cleanup_effect_permits_since_start','partial_nativeoff_reconciliations_since_start','partial_nativeoff_reads_since_start','prejournal_refusal_recoveries_since_start','presend_retirement_recoveries_since_start','retirement_intents_since_start','retirement_contexts_since_start','retirement_original_returns_since_start','retirement_delete_bindings_since_start','retirement_native_readbacks_since_start','caller_possible_sends_since_start','caller_returns_since_start','runtime_snapshot_challenges_since_start','runtime_snapshot_returns_since_start','authority_reads_since_start','authority_returns_since_start','authority_transport_returns_since_start','native_poweroff_reads_since_start','canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start','intents_updated_since_start','notify_window_markers_for_job','intent_events_since_start','native_commands_since_start','native_lifetimes_updated_since_start','native_lifetime_archives_since_start','native_pod_checkpoints_since_start','executor_activity_updated_since_start','resource_slots_updated_since_start','provider_read_performed','provider_quiescence_proved','base_schema','pure_assessment_intent_updates','observation_refresh_slot_updates']
 AND scan#>>'{base,schema}'='finalization_lost_dispatch_effect_scan_v1'
 AND scan#>>'{base,base_schema}'='abandoned_started_dispatch_effect_scan_v2'
 AND scan#>'{base,clock_skew_margin_seconds}'='30'::jsonb
 AND scan#>'{base,provider_read_performed}'='false'::jsonb AND scan#>'{base,provider_quiescence_proved}'='false'::jsonb
 AND scan#>'{base,intents_updated_since_start}'='0'::jsonb AND scan#>'{base,pure_assessment_intent_updates}'='0'::jsonb
 AND jsonb_typeof(scan#>'{base,resource_slots_updated_since_start}')='number'
 AND scan#>>'{base,resource_slots_updated_since_start}'~'^[0-9]+$'
 AND scan#>>'{base,observation_refresh_slot_updates}'~'^[0-9]+$'
 AND scan#>'{base,resource_slots_updated_since_start}'=scan#>'{base,observation_refresh_slot_updates}'
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan->'base')x
  WHERE x.key NOT IN('schema','base_schema','clock_skew_margin_seconds','provider_read_performed','provider_quiescence_proved',
   'intents_updated_since_start','pure_assessment_intent_updates','resource_slots_updated_since_start','observation_refresh_slot_updates')AND (jsonb_typeof(x.value)IS DISTINCT FROM 'number' OR x.value::text<>'0')),false)
$$;
-- +goose StatementEnd

-- Error fields are separately authenticated whole originals, never cross-equal:
-- Finish final_clock may replace only return_error; markFinalizationUnknown
-- replaces workflow.error plus finalization_error while retaining return_error.
-- Neither message identity nor a human error category is authority.
-- Validate only immutable historical custody here. Current eligibility is
-- rederived separately by INSERT under the actual scope/row locks.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.preaction_failed_plan_valid(r jsonb,d bytea,w bytea,i bytea,m bytea,e bytea)
RETURNS boolean LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE dj jsonb; rw jsonb; intent jsonb; members jsonb; evidence jsonb; env jsonb; result jsonb; step jsonb; ord integer;
 j public.capacity_dispatch_jobs; run public.workflow_runs; a public.capacity_dispatch_installed_provision_timeout_dispositions;
 policy public.manifests; wf public.manifests;
 previous_step_finished numeric; response_start_ns numeric; response_finish_ns numeric; row_finish_ns numeric;
 ids text[]:=ARRAY['plan-original-guest','provision-original-notify','retire-original-guest','refresh-original-membership','complete-original-provision','finish-original-retirement','complete-original-retirement'];
 ops text[]:=ARRAY['capacity.plan_original_guest','capacity.provision_original_guest','capacity.retire_original_guest','capacity.complete_original_guest','capacity.complete_original_guest','capacity.finish_original_guest_retirement','capacity.complete_original_guest'];
BEGIN
 IF r IS NULL OR d IS NULL OR w IS NULL OR i IS NULL OR m IS NULL OR e IS NULL
 OR octet_length(d)NOT BETWEEN 1 AND 1048576 OR octet_length(w)NOT BETWEEN 1 AND 8388608
 OR octet_length(i)NOT BETWEEN 1 AND 1048576 OR octet_length(m)NOT BETWEEN 1 AND 1048576 OR octet_length(e)NOT BETWEEN 1 AND 8388608 THEN RETURN false; END IF;
 IF(jsonb_typeof(r)='object'AND(SELECT count(*)FROM jsonb_object_keys(r))=19
 AND r ?& ARRAY['schema','id','job_id','run_id','successor_job_id','successor_run_id','root_anchor_id','policy_id','policy_checksum','generation','fencing_token','original_dispatch_sha256','original_run_sha256','original_intent_sha256','members_sha256','evidence_sha256','original_deadline','original_returned_at','recorded_at']
 AND r->>'schema'='unknown_preaction_failed_plan_disposition_v1'
 AND jsonb_typeof(r->'generation')='number'AND r->>'generation'~'^[1-9][0-9]*$'AND(r->>'generation')::bigint<=9007199254740991
 AND jsonb_typeof(r->'fencing_token')='number'AND r->>'fencing_token'~'^[1-9][0-9]*$'AND(r->>'fencing_token')::bigint<=9007199254740991)IS NOT TRUE THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['id','job_id','run_id','successor_job_id','successor_run_id','root_anchor_id','policy_id'])k
  WHERE jsonb_typeof(r->k)IS DISTINCT FROM 'string'OR r->>k!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'OR r->>k='00000000-0000-0000-0000-000000000000')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['policy_checksum','original_dispatch_sha256','original_run_sha256','original_intent_sha256','members_sha256','evidence_sha256'])k
  WHERE jsonb_typeof(r->k)IS DISTINCT FROM 'string'OR r->>k!~'^[0-9a-f]{64}$')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['original_deadline','original_returned_at','recorded_at'])k
  WHERE jsonb_typeof(r->k)IS DISTINCT FROM 'string'OR NOT isfinite((r->>k)::timestamptz))
 THEN RETURN false; END IF;
 dj=convert_from(d,'UTF8')::jsonb; rw=convert_from(w,'UTF8')::jsonb; intent=convert_from(i,'UTF8')::jsonb;
 members=convert_from(m,'UTF8')::jsonb; evidence=convert_from(e,'UTF8')::jsonb;env=(dj->>'envelope')::jsonb;result=rw->'result';
 IF(encode(sha256(d),'hex')=r->>'original_dispatch_sha256'AND encode(sha256(w),'hex')=r->>'original_run_sha256'
 AND encode(sha256(i),'hex')=r->>'original_intent_sha256'AND encode(sha256(m),'hex')=r->>'members_sha256'
 AND encode(sha256(e),'hex')=r->>'evidence_sha256'AND public.preaction_failed_plan_effect_scan_tolerable(evidence)
 AND jsonb_typeof(dj)='object'AND jsonb_typeof(rw)='object'AND jsonb_typeof(intent)='object'
 AND jsonb_typeof(members)='array'AND jsonb_array_length(members)BETWEEN 2 AND 8
 AND r->>'job_id'<>r->>'successor_job_id'AND r->>'run_id'<>r->>'successor_run_id')IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE id=(r->>'job_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO run FROM public.workflow_runs WHERE id=(r->>'run_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO a FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=(r->>'root_anchor_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 IF(public.installed_provision_timeout_valid(a.original_record,a.original_dispatch_wire,a.original_run_wire,a.original_intent_wire,a.members_wire)
 AND convert_from(a.original_wire,'UTF8')::jsonb=a.original_record
 AND a.original_record->>'policy_id'=r->>'policy_id'AND a.original_record->>'policy_checksum'=r->>'policy_checksum'
 AND a.original_record->'generation'=r->'generation'AND a.original_record->'fencing_token'=r->'fencing_token'
 AND intent=convert_from(a.original_intent_wire,'UTF8')::jsonb AND m=a.members_wire
 AND a.recorded_at<=(dj->>'started_at')::timestamptz
 AND ((convert_from(a.original_dispatch_wire,'UTF8')::jsonb->>'envelope')::jsonb-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256'])
  =(env-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256'])
 AND (((convert_from(a.original_dispatch_wire,'UTF8')::jsonb->>'envelope')::jsonb->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id'])
  =((env->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id'])
 AND dj->>'id'=r->>'job_id'AND dj->>'run_id'=r->>'run_id'AND dj->>'state'='unknown'
 AND dj->'finalization_ack_at'='null'::jsonb AND dj->>'return_status'='failed'
 AND jsonb_typeof(dj->'return_error')IN('string','null') AND jsonb_typeof(dj->'finalization_error')IN('string','null')
 AND(coalesce(length(dj->>'return_error'),0)>0 OR coalesce(length(dj->>'finalization_error'),0)>0)
 AND(dj->>'started_at')::timestamptz<(dj->>'lease_expires_at')::timestamptz
 AND(dj->>'returned_at')::timestamptz>=(dj->>'started_at')::timestamptz
 AND(dj->>'lease_expires_at')::timestamptz=(r->>'original_deadline')::timestamptz
 AND(dj->>'returned_at')::timestamptz=(r->>'original_returned_at')::timestamptz
 AND(r->>'recorded_at')::timestamptz>=(r->>'original_deadline')::timestamptz
 AND(r->>'recorded_at')::timestamptz>=(r->>'original_returned_at')::timestamptz
 AND j.run_id=run.id AND j.finalization_ack_at IS NULL AND j.state IN('unknown','preaction_plan_disposed')
 AND(to_jsonb(j)-ARRAY['state','updated_at'])=(dj-ARRAY['state','updated_at'])
 AND(j.state='preaction_plan_disposed'OR to_jsonb(j)=dj)
 AND to_jsonb(run)=rw AND rw->>'status'='failed'AND jsonb_typeof(rw->'error')='string'AND length(rw->>'error')>0
 AND(rw->>'started_at')::timestamptz=(dj->>'started_at')::timestamptz
 AND(rw->>'finished_at')::timestamptz=(r->>'original_returned_at')::timestamptz
 AND rw#>>'{metadata,triggered_by}'='workflow_scheduler'AND rw#>>'{metadata,capacity_dispatch_job_id}'=j.id::text
 AND rw->'metadata'=env->'metadata'AND rw->'inputs'=env->'inputs'
 AND rw->>'workflow_namespace'=env#>>'{workflow,namespace}'AND rw->>'workflow_name'=env#>>'{workflow,name}'
 AND rw->'workflow_version'=env#>'{workflow,version}'
 AND(rw->'workflow_id'='null'::jsonb OR rw->>'workflow_id'=env#>>'{workflow,id}')
 AND(env->>'protocol')='capacity_dispatch_prestart_v1'AND env->>'protocol'=dj->>'protocol'
 AND env->>'job_id'=j.id::text AND env->>'run_id'=run.id::text
 AND encode(sha256(convert_to(dj->>'envelope','UTF8')),'hex')=dj->>'envelope_sha256'
 AND env#>>'{policy,id}'=r->>'policy_id'AND env#>>'{policy,checksum}'=r->>'policy_checksum'
 AND env#>>'{metadata,triggered_by}'='workflow_scheduler'AND env#>>'{metadata,capacity_dispatch_job_id}'=j.id::text
 AND intent->>'namespace'=j.realm AND intent->>'environment'=j.environment AND intent->>'domain'=j.domain AND intent->>'dimension'=j.dimension
 AND intent->'generation'=r->'generation'AND intent->'fencing_token'=r->'fencing_token'
 AND intent->>'policy_id'=r->>'policy_id'AND intent->>'policy_checksum'=r->>'policy_checksum')IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO policy FROM public.manifests WHERE id=(r->>'policy_id')::uuid AND kind='capacity_policy';
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO wf FROM public.manifests WHERE id=(env#>>'{workflow,id}')::uuid AND kind='workflow';
 IF NOT FOUND THEN RETURN false; END IF;
 IF(policy.namespace=j.realm AND policy.checksum=r->>'policy_checksum'
 AND wf.namespace=env#>>'{workflow,namespace}'AND wf.name=env#>>'{workflow,name}'AND to_jsonb(wf.version)=env#>'{workflow,version}'AND wf.checksum=env#>>'{workflow,checksum}'
 AND public.preaction_failed_plan_graph_valid(wf.spec,policy.namespace,policy.name,policy.spec#>>'{mutation_bindings,0,name}')
 AND jsonb_typeof(result)='object'AND result->>'status'='failed'AND jsonb_typeof(result->'steps')='array'AND jsonb_array_length(result->'steps')=7
 AND result->'metadata'=((env->'metadata')||jsonb_build_object('failed_step','plan-original-guest'))
 AND result->'workflow'=jsonb_build_object('kind','workflow','id',wf.id,'namespace',wf.namespace,'name',wf.name,'version',wf.version))IS NOT TRUE THEN RETURN false; END IF;
 response_start_ns=public.preaction_failed_plan_timestamp_ns(result->>'started_at');
 response_finish_ns=public.preaction_failed_plan_timestamp_ns(result->>'finished_at');
 row_finish_ns=public.preaction_failed_plan_timestamp_ns(rw->>'finished_at');
 IF(response_start_ns>=public.preaction_failed_plan_timestamp_ns(rw->>'started_at')
 AND response_start_ns<public.preaction_failed_plan_timestamp_ns(dj->>'lease_expires_at')
 AND response_finish_ns>=response_start_ns AND response_finish_ns<=row_finish_ns)IS NOT TRUE THEN RETURN false;END IF;
 previous_step_finished=response_start_ns;
 FOR step,ord IN SELECT value,n::integer FROM jsonb_array_elements(result->'steps')WITH ORDINALITY x(value,n) LOOP
  IF(step->>'id'=ids[ord]AND step->>'kind'='yggdrasil'AND step->>'operation'=ops[ord]AND step->>'capability'=ops[ord]
  AND NOT step ?| ARRAY['integration_instance','integration_type']
  AND public.preaction_failed_plan_timestamp_ns(step->>'started_at')>=previous_step_finished
  AND public.preaction_failed_plan_timestamp_ns(step->>'finished_at')>=public.preaction_failed_plan_timestamp_ns(step->>'started_at')
  AND public.preaction_failed_plan_timestamp_ns(step->>'finished_at')<=row_finish_ns)IS NOT TRUE THEN RETURN false; END IF;
  previous_step_finished=public.preaction_failed_plan_timestamp_ns(step->>'finished_at');
  IF ord=1 THEN
   IF(step->>'status'='failed'AND step->'attempts'='1'::jsonb
   AND public.preaction_failed_plan_timestamp_ns(step->>'finished_at')=response_finish_ns
   AND jsonb_typeof(step->'metadata')='object'AND(SELECT count(*)FROM jsonb_object_keys(step->'metadata'))=1
   AND jsonb_typeof(step#>'{metadata,original_guest_reconcile_refusal_stage}')='string'
   AND octet_length(step#>>'{metadata,original_guest_reconcile_refusal_stage}')BETWEEN 1 AND 128
   AND strpos(step#>>'{metadata,original_guest_reconcile_refusal_stage}',chr(13))=0 AND strpos(step#>>'{metadata,original_guest_reconcile_refusal_stage}',chr(10))=0
   AND btrim(step#>>'{metadata,original_guest_reconcile_refusal_stage}',chr(32)||chr(9)||chr(13)||chr(10)||chr(11)||chr(12))=step#>>'{metadata,original_guest_reconcile_refusal_stage}')IS NOT TRUE THEN RETURN false; END IF;
  ELSE
   IF(step->>'status'='skipped'AND coalesce(step->'attempts','0'::jsonb)='0'::jsonb
   AND coalesce(step->'metadata','{}'::jsonb)='{}'::jsonb
   AND step->>'error'='workflow aborted after step "plan-original-guest" failed'
   AND public.preaction_failed_plan_timestamp_ns(step->>'started_at')>=response_finish_ns)IS NOT TRUE THEN RETURN false; END IF;
  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

CREATE TABLE IF NOT EXISTS public.capacity_dispatch_preaction_plan_dispositions (
 id uuid PRIMARY KEY,
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
 successor_job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id) DEFERRABLE INITIALLY DEFERRED,
 successor_run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id) DEFERRABLE INITIALLY DEFERRED,
 original_record jsonb NOT NULL,
 original_wire bytea NOT NULL CHECK(octet_length(original_wire)BETWEEN 1 AND 1048576),
 original_dispatch_wire bytea NOT NULL CHECK(octet_length(original_dispatch_wire)BETWEEN 1 AND 1048576),
 original_run_wire bytea NOT NULL CHECK(octet_length(original_run_wire)BETWEEN 1 AND 8388608),
 original_intent_wire bytea NOT NULL CHECK(octet_length(original_intent_wire)BETWEEN 1 AND 1048576),
 members_wire bytea NOT NULL CHECK(octet_length(members_wire)BETWEEN 1 AND 1048576),
 evidence_wire bytea NOT NULL CHECK(octet_length(evidence_wire)BETWEEN 1 AND 8388608),
 recorded_at timestamptz NOT NULL,
 CHECK(original_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(id::text=original_record->>'id'AND job_id::text=original_record->>'job_id'AND run_id::text=original_record->>'run_id'
  AND successor_job_id::text=original_record->>'successor_job_id'AND successor_run_id::text=original_record->>'successor_run_id'),
 CHECK(recorded_at=(original_record->>'recorded_at')::timestamptz)
);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_preaction_failed_plan_insert()RETURNS trigger LANGUAGE plpgsql SET timezone='UTC'AS $$
DECLARE j public.capacity_dispatch_jobs; a public.capacity_dispatch_installed_provision_timeout_dispositions; env jsonb; it jsonb; actual jsonb; policy public.manifests;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[j.realm,j.environment,j.domain,j.dimension])v WHERE v IS NULL OR v!~'^[ -~]+$'OR v~'[<>&]')THEN RAISE EXCEPTION 'preaction plan requires exact shared scope encoding';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[j.realm,j.environment,j.domain,j.dimension])::text,0));
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 env=j.envelope::jsonb;
 PERFORM id FROM public.manifests WHERE id IN((env#>>'{policy,id}')::uuid,(env#>>'{workflow,id}')::uuid,(env#>>'{rbac,id}')::uuid,(env#>>'{authorization_policy,id}')::uuid)ORDER BY id FOR SHARE;
 SELECT * INTO STRICT policy FROM public.manifests WHERE id=(env#>>'{policy,id}')::uuid;
 SELECT intent INTO STRICT it FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension FOR UPDATE;
 PERFORM id FROM public.workflow_runs WHERE id=NEW.run_id FOR SHARE;
 PERFORM slot FROM public.capacity_resource_slots WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE;
 PERFORM id FROM public.capacity_mutation_grants WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY id FOR SHARE;
 SELECT * INTO STRICT a FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE id=(NEW.original_record->>'root_anchor_id')::uuid;
 IF j.state<>'unknown'OR j.run_id<>NEW.run_id OR j.finalization_ack_at IS NOT NULL
 OR to_jsonb(j)IS DISTINCT FROM convert_from(NEW.original_dispatch_wire,'UTF8')::jsonb
 OR it IS DISTINCT FROM convert_from(NEW.original_intent_wire,'UTF8')::jsonb
 OR it IS DISTINCT FROM convert_from(a.original_intent_wire,'UTF8')::jsonb
 OR NOT policy.active OR policy.checksum<>NEW.original_record->>'policy_checksum'
 OR NOT EXISTS(SELECT 1 FROM public.manifests x WHERE x.id=(env#>>'{workflow,id}')::uuid AND x.active AND x.checksum=env#>>'{workflow,checksum}')
 OR NOT EXISTS(SELECT 1 FROM public.manifests x WHERE x.id=(env#>>'{rbac,id}')::uuid AND x.active AND x.checksum=env#>>'{rbac,checksum}')
 OR env?'authorization_policy'AND NOT EXISTS(SELECT 1 FROM public.manifests x WHERE x.id=(env#>>'{authorization_policy,id}')::uuid AND x.active AND x.checksum=env#>>'{authorization_policy,checksum}')
 OR NEW.recorded_at<transaction_timestamp()OR NEW.recorded_at>clock_timestamp()
 OR j.lease_expires_at>NEW.recorded_at OR j.returned_at>NEW.recorded_at
 OR public.preaction_failed_plan_valid(NEW.original_record,NEW.original_dispatch_wire,NEW.original_run_wire,NEW.original_intent_wire,NEW.members_wire,NEW.evidence_wire)IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'preaction plan requires exact closed expired original and immutable anchor';END IF;
 actual=public.preaction_failed_plan_effect_scan(j.id,a.id);
 IF actual IS DISTINCT FROM convert_from(NEW.evidence_wire,'UTF8')::jsonb
 OR public.preaction_failed_plan_effect_scan_tolerable(actual)IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'preaction plan requires independently rederived complete no-claim evidence';END IF;
 RETURN NEW;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_preaction_failed_plan_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE receipt public.capacity_dispatch_preaction_plan_dispositions;
BEGIN
 IF old_row.state='preaction_plan_disposed'THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'preaction plan terminal is immutable';END IF;RETURN new_row;
 END IF;
 IF old_row.state<>'unknown'OR new_row.state<>'preaction_plan_disposed'OR old_row.finalization_ack_at IS NOT NULL
 OR(to_jsonb(new_row)-ARRAY['state','updated_at'])IS DISTINCT FROM(to_jsonb(old_row)-ARRAY['state','updated_at'])
 THEN RAISE EXCEPTION 'preaction plan terminal preserves every original dispatch field';END IF;
 SELECT * INTO STRICT receipt FROM public.capacity_dispatch_preaction_plan_dispositions WHERE job_id=old_row.id AND run_id=old_row.run_id;
 IF convert_from(receipt.original_dispatch_wire,'UTF8')::jsonb IS DISTINCT FROM to_jsonb(old_row)
 OR new_row.updated_at IS DISTINCT FROM receipt.recorded_at
 THEN RAISE EXCEPTION 'preaction plan terminal needs same transaction receipt';END IF;
 RETURN new_row;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_preaction_failed_plan_job_insert()RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='preaction_plan_disposed'THEN RAISE EXCEPTION 'preaction plan terminal needs retained original job';END IF;
 RETURN NEW;
END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.immutable_preaction_failed_plan()RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'preaction plan receipt is immutable';END;$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_preaction_failed_plan_workflow()RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions WHERE run_id=OLD.id)AND(TG_OP='DELETE'OR NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'preaction plan original workflow remains immutable';END IF;
 IF TG_OP='DELETE'THEN RETURN OLD;END IF;RETURN NEW;
END;$$;
-- +goose StatementEnd

-- Explicit successor IDs are linked only at the SAME transaction's commit.
-- Saved eligibility is historical; do not rerun current-effect checks here,
-- since that successor is now legitimately pending and later may advance.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.require_preaction_failed_plan_links()RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; s public.capacity_dispatch_jobs; w public.workflow_runs; original jsonb; env jsonb; next_env jsonb;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT * INTO STRICT s FROM public.capacity_dispatch_jobs WHERE id=NEW.successor_job_id;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=NEW.successor_run_id;
 original=convert_from(NEW.original_dispatch_wire,'UTF8')::jsonb;env=j.envelope::jsonb;next_env=s.envelope::jsonb;
 IF j.state<>'preaction_plan_disposed'OR j.run_id<>NEW.run_id OR j.finalization_ack_at IS NOT NULL OR j.updated_at IS DISTINCT FROM NEW.recorded_at
 OR(to_jsonb(j)-ARRAY['state','updated_at'])IS DISTINCT FROM(original-ARRAY['state','updated_at'])
 OR public.preaction_failed_plan_valid(NEW.original_record,NEW.original_dispatch_wire,NEW.original_run_wire,NEW.original_intent_wire,NEW.members_wire,NEW.evidence_wire)IS DISTINCT FROM true
 OR s.run_id<>NEW.successor_run_id OR s.id=j.id OR s.run_id=j.run_id OR s.source_tick=j.source_tick
 OR s.state<>'queued'OR s.started_at IS NOT NULL OR s.returned_at IS NOT NULL OR s.finalization_ack_at IS NOT NULL
 OR s.lease_owner IS NOT NULL OR s.lease_expires_at IS NOT NULL OR s.fencing_token<>0
 OR s.realm<>j.realm OR s.environment<>j.environment OR s.domain<>j.domain OR s.dimension<>j.dimension
 OR w.status<>'pending'OR w.started_at IS NOT NULL OR w.finished_at IS NOT NULL
 OR(next_env-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256'])IS DISTINCT FROM(env-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256'])
 OR((next_env->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id'])IS DISTINCT FROM((env->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id'])
 OR next_env->>'job_id'<>s.id::text OR next_env->>'run_id'<>s.run_id::text OR next_env->>'source_tick'<>s.source_tick
 OR next_env#>>'{metadata,capacity_dispatch_job_id}'<>s.id::text OR next_env#>>'{metadata,scheduled_for}'<>s.source_tick
 OR w.metadata IS DISTINCT FROM next_env->'metadata'OR w.inputs IS DISTINCT FROM next_env->'inputs'
 OR w.workflow_namespace IS DISTINCT FROM next_env#>>'{workflow,namespace}'OR w.workflow_name IS DISTINCT FROM next_env#>>'{workflow,name}'
 OR w.workflow_version IS DISTINCT FROM(next_env#>>'{workflow,version}')::integer
 OR encode(sha256(convert_to(s.envelope,'UTF8')),'hex')<>s.envelope_sha256
 OR NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_wakes x WHERE x.job_id=s.id AND x.realm=s.realm AND x.environment=s.environment AND x.domain=s.domain AND x.dimension=s.dimension AND x.source_tick=s.source_tick)
 THEN RAISE EXCEPTION 'preaction plan needs one exact distinct queued successor and unchanged originals in same commit';END IF;
 RETURN NULL;
END;$$;
-- +goose StatementEnd
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v10_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v10_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v11_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v11_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));

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

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_preaction_plan_dispositions'::regclass AND tgname='preaction_failed_plan_insert')THEN
  CREATE TRIGGER preaction_failed_plan_insert BEFORE INSERT ON public.capacity_dispatch_preaction_plan_dispositions FOR EACH ROW EXECUTE FUNCTION public.guard_preaction_failed_plan_insert();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_preaction_plan_dispositions'::regclass AND tgname='preaction_failed_plan_immutable')THEN
  CREATE TRIGGER preaction_failed_plan_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_preaction_plan_dispositions FOR EACH ROW EXECUTE FUNCTION public.immutable_preaction_failed_plan();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_preaction_plan_dispositions'::regclass AND tgname='preaction_failed_plan_complete_links')THEN
  CREATE CONSTRAINT TRIGGER preaction_failed_plan_complete_links AFTER INSERT ON public.capacity_dispatch_preaction_plan_dispositions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_preaction_failed_plan_links();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_jobs'::regclass AND tgname='preaction_failed_plan_job_insert')THEN
  CREATE TRIGGER preaction_failed_plan_job_insert BEFORE INSERT ON public.capacity_dispatch_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_preaction_failed_plan_job_insert();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.workflow_runs'::regclass AND tgname='preaction_failed_plan_workflow_immutable')THEN
  CREATE TRIGGER preaction_failed_plan_workflow_immutable BEFORE UPDATE OR DELETE ON public.workflow_runs FOR EACH ROW EXECUTE FUNCTION public.guard_preaction_failed_plan_workflow();
 END IF;
END;$idempotent$;
-- +goose StatementEnd

-- +goose Down
-- Never delete a retained historical proof or reinterpret a terminal to roll back.
-- +goose StatementBegin
DO $refuse$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions)
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE state='preaction_plan_disposed')
 THEN RAISE EXCEPTION 'retained preaction plan evidence prevents rollback';END IF;
END;$refuse$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS preaction_failed_plan_workflow_immutable ON public.workflow_runs;
DROP TRIGGER IF EXISTS preaction_failed_plan_job_insert ON public.capacity_dispatch_jobs;
DROP TRIGGER IF EXISTS preaction_failed_plan_complete_links ON public.capacity_dispatch_preaction_plan_dispositions;
DROP TRIGGER IF EXISTS preaction_failed_plan_immutable ON public.capacity_dispatch_preaction_plan_dispositions;
DROP TRIGGER IF EXISTS preaction_failed_plan_insert ON public.capacity_dispatch_preaction_plan_dispositions;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
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
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v10_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v10_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));
DROP FUNCTION IF EXISTS public.require_preaction_failed_plan_links();
DROP FUNCTION IF EXISTS public.guard_preaction_failed_plan_workflow();
DROP FUNCTION IF EXISTS public.immutable_preaction_failed_plan();
DROP FUNCTION IF EXISTS public.guard_preaction_failed_plan_job_insert();
DROP FUNCTION IF EXISTS public.check_preaction_failed_plan_transition(public.capacity_dispatch_jobs,public.capacity_dispatch_jobs);
DROP FUNCTION IF EXISTS public.guard_preaction_failed_plan_insert();
DROP TABLE IF EXISTS public.capacity_dispatch_preaction_plan_dispositions;
DROP FUNCTION IF EXISTS public.preaction_failed_plan_valid(jsonb,bytea,bytea,bytea,bytea,bytea);
DROP FUNCTION IF EXISTS public.preaction_failed_plan_effect_scan(uuid,uuid);
DROP FUNCTION IF EXISTS public.preaction_failed_plan_effect_scan_tolerable(jsonb);
DROP FUNCTION IF EXISTS public.preaction_failed_plan_graph_valid(jsonb,text,text,text);
DROP FUNCTION IF EXISTS public.preaction_failed_plan_timestamp_ns(text);
DROP INDEX IF EXISTS public.capacity_dispatch_failed_workflow_returned_idx;
