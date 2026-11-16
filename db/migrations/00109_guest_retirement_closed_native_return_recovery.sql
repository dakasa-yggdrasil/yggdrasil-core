-- +goose Up
-- A closed timely RPC return whose native content was rejected transfers
-- custody only. Its immutable missing plan never proves OFF; the admitted
-- owner still needs a new qualified native OFF read and every DELETE guard.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_normal_finish_recovery_valid(r jsonb, retirement uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE p jsonb=r->'normal_finish_recovery'; original public.capacity_vm_retirement_intents;
 caller public.capacity_guest_original_caller_returns; prepared public.capacity_guest_original_native_poweroff_reads;
 returned public.capacity_guest_original_native_poweroff_reads; context_row public.capacity_guest_original_retirement_contexts;
 w public.workflow_runs; j public.capacity_dispatch_jobs; parent public.capacity_guest_retirement_forwards;
 requested public.capacity_guest_retirement_forwards; nonce public.capacity_vm_retirement_original_returns;
 baseline jsonb; steps jsonb; rd jsonb; rv jsonb; finalized_intent_sha256 text;
 n integer; retired jsonb; finished jsonb; plan jsonb;
BEGIN
 IF r->>'mode'<>'normal_finish_recovery' THEN RETURN false; END IF;
 IF r->>'stage'<>'requested' THEN
  SELECT * INTO requested FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'id')::uuid AND stage='requested';
  IF NOT FOUND OR requested.original_record->'normal_finish_recovery' IS DISTINCT FROM p
   OR requested.original_record->'evidence' IS DISTINCT FROM r->'evidence'
   OR requested.original_record->'original' IS DISTINCT FROM r->'original'
   OR requested.original_record->>'original_intent_sha256' IS DISTINCT FROM r->>'original_intent_sha256'
  THEN RETURN false; END IF;
  r=requested.original_record; p=r->'normal_finish_recovery';
 END IF;
 IF (jsonb_typeof(p)='object' AND (SELECT count(*) FROM jsonb_object_keys(p))=10
  AND p-ARRAY['schema','requesting_run_id','failed_run_id','failed_run_sha256','failed_finish_ack_at','native_off_read_id','native_off_prepared_sha256','native_off_return_sha256','original_context_deadline','original_lease_expires_at']='{}'::jsonb
  AND p->>'schema'='original_normal_finish_recovery_v1'
  AND p->>'failed_run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND p->>'native_off_read_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND (p->>'failed_run_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND (p->>'native_off_read_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND (p->>'requesting_run_id'='' OR p->>'requesting_run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  AND p->>'failed_run_sha256' ~ '^[a-f0-9]{64}$'
  AND p->>'native_off_prepared_sha256' ~ '^[a-f0-9]{64}$'
  AND p->>'native_off_return_sha256' ~ '^[a-f0-9]{64}$'
  AND r->>'run_id'='' AND coalesce(r->>'destroy_grant_id','')=''
  AND (r#>>'{barrier,ProcessStartedAt}')::timestamptz='0001-01-01T00:00:00Z'::timestamptz
  AND r#>>'{barrier,PID}'='0' AND r#>>'{barrier,SourceCommit}'='' AND r#>>'{barrier,Hostname}'='') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO original FROM public.capacity_vm_retirement_intents WHERE id=retirement AND preregistration_id=(r->>'preregistration_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO nonce FROM public.capacity_vm_retirement_original_returns
  WHERE intent_id=retirement AND sequence=1 AND kind='production_clock_nonce_v2';
 IF NOT FOUND THEN RETURN false; END IF;
 IF (nonce.original_return_record=convert_from(nonce.original_wire,'UTF8')::jsonb
  AND encode(digest(nonce.original_wire,'sha256'),'hex')=nonce.return_sha256
  AND nonce.return_sha256=r#>>'{evidence,nonce_sha256}'
  AND nonce.original_return_record->>'schema'='original_core_guest_retirement_nonce_return_v2'
  AND nonce.original_return_record->>'preflight_sha256'=original.intent_sha256
  AND nonce.original_return_record->'final_request'=r#>'{original,Request}') IS NOT TRUE THEN RETURN false; END IF;
 -- json (not jsonb) retains the finalized intent token from the original Go
 -- wire. The preflight intent SHA intentionally predates the Guest nonce.
 finalized_intent_sha256=encode(digest(convert_to((convert_from(nonce.original_wire,'UTF8')::json->'final_request'->'intent')::text,'UTF8'),'sha256'),'hex');
 SELECT * INTO caller FROM public.capacity_guest_original_caller_returns WHERE intent_id=retirement AND return_sha256=r->>'original_caller_sha256';
 IF NOT FOUND THEN RETURN false; END IF;
 IF (caller.original_record=convert_from(caller.original_wire,'UTF8')::jsonb
  AND encode(digest(caller.original_wire,'sha256'),'hex')=caller.return_sha256
  AND caller.original_record->>'request_id'=retirement::text
  AND caller.original_record->>'attempt_id'=original.attempt_id::text
  AND caller.original_record->>'status'='200' AND caller.original_record->>'body_persisted'='true'
  AND caller.original_record->>'preflight_failed'='false' AND caller.original_record->>'do_failed'='false'
  AND caller.original_record->>'read_failed'='false' AND caller.original_record->>'close_failed'='false'
  AND caller.original_record->>'original_context_failed'='false'
  AND (caller.original_record->>'original_deadline')::timestamptz=original.original_deadline
  AND (caller.original_record->>'driver_returned_at')::timestamptz<original.original_deadline
  AND (caller.original_record->>'started_at')::timestamptz>=(original.intent_record->>'issued_at')::timestamptz
  AND (caller.original_record->>'do_started_at')::timestamptz>=(caller.original_record->>'started_at')::timestamptz
  AND (caller.original_record->>'do_returned_at')::timestamptz>=(caller.original_record->>'do_started_at')::timestamptz
  AND (caller.original_record->>'read_returned_at')::timestamptz>=(caller.original_record->>'do_returned_at')::timestamptz
  AND (caller.original_record->>'close_returned_at')::timestamptz>=(caller.original_record->>'read_returned_at')::timestamptz
  AND (caller.original_record->>'driver_returned_at')::timestamptz>=(caller.original_record->>'close_returned_at')::timestamptz) IS NOT TRUE THEN RETURN false; END IF;
 SELECT count(*) INTO n FROM public.capacity_vm_retirement_original_returns WHERE intent_id=retirement;
 IF n<>5 OR NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns v WHERE v.intent_id=retirement AND v.sequence=5
   AND v.kind='production_retirement_v2:poweroff_command_returned'
   AND v.original_return_record=convert_from(v.original_wire,'UTF8')::jsonb
   AND v.original_return_record=convert_from(decode(caller.original_record->>'body','base64'),'UTF8')::jsonb
   AND v.original_return_record->>'journal_complete'='true' AND v.original_return_record->'hold_reasons'='[]'::jsonb
   AND v.original_return_record#>>'{record,sequence}'='4'
   AND v.original_return_record#>>'{record,poweroff_command_returned}'='true'
   AND v.original_return_record#>>'{record,writer_quiescence_evidence}'='true'
   AND v.original_return_record#>>'{record,powered_off_observed}'='false') THEN RETURN false; END IF;
 baseline=convert_from(decode(r->>'original_intent_wire','base64'),'UTF8')::jsonb;
 IF (encode(digest(decode(r->>'original_intent_wire','base64'),'sha256'),'hex')=r->>'original_intent_sha256'
  AND baseline->>'phase' IN('draining','drained') AND coalesce(baseline->>'recovery_only','false')='false'
  AND coalesce(baseline->>'floor_degraded','false')='false'
  AND baseline->>'generation'=r->>'generation' AND baseline->>'fencing_token'=r->>'fence'
  AND baseline->>'lease_owner'=r->>'lease_owner' AND baseline->>'lease_executor_id'=r->>'executor_id'
  AND (baseline->>'lease_expires_at')::timestamptz=(p->>'original_lease_expires_at')::timestamptz
  AND (baseline->>'lease_expires_at')::timestamptz<=(r->>'recorded_at')::timestamptz
  AND r#>>'{original,Request,intent,policy_id}'=baseline->>'policy_id'
  AND r#>>'{original,Request,intent,policy_checksum}'=baseline->>'policy_checksum'
  AND (baseline#>>'{decision,units}')::integer=(r#>>'{original,Request,intent,slot}')::integer-1) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO context_row FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=retirement;
 IF NOT FOUND OR context_row.original_context_deadline<>(p->>'original_context_deadline')::timestamptz
  OR context_row.original_context_deadline>=(r->>'recorded_at')::timestamptz
  OR original.original_deadline>=(r->>'recorded_at')::timestamptz THEN RETURN false; END IF;
 SELECT * INTO prepared FROM public.capacity_guest_original_native_poweroff_reads
  WHERE id=(p->>'native_off_read_id')::uuid AND intent_id=retirement;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT count(*) INTO n FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=retirement;
 IF n<>2 THEN RETURN false; END IF;
 SELECT * INTO returned FROM public.capacity_guest_original_native_poweroff_reads
  WHERE intent_id=retirement AND observation_sha256=p->>'native_off_return_sha256';
 IF NOT FOUND THEN RETURN false; END IF;
 rd=prepared.original_record; rv=returned.original_record;
 IF (prepared.observation_sha256=p->>'native_off_prepared_sha256'
  AND prepared.original_record=convert_from(prepared.original_wire,'UTF8')::jsonb
  AND returned.original_record=convert_from(returned.original_wire,'UTF8')::jsonb
  AND encode(digest(prepared.original_wire,'sha256'),'hex')=prepared.observation_sha256
  AND encode(digest(returned.original_wire,'sha256'),'hex')=returned.observation_sha256
  AND returned.original_native_join_wire=prepared.original_wire AND rv->'challenge'=rd
  AND rd->>'schema'='original_core_guest_native_poweroff_read_challenge_v2'
  AND rd->>'read_id'=prepared.id::text AND rd->>'intent_id'=retirement::text
  AND rd->>'intent_sha256'=finalized_intent_sha256 AND rd->>'original_caller_sha256'=caller.return_sha256
  AND rd->'tuple'=original.intent_record->'tuple'
  AND rd->>'mutation_binding_sha256' ~ '^[a-f0-9]{64}$'
  AND rd->>'adapter_source_commit' ~ '^[a-f0-9]{40}$'
  AND EXISTS(SELECT 1 FROM public.capacity_vm_provisioning_preregistrations pre JOIN public.capacity_mutation_grants created ON created.id=pre.create_grant_id WHERE pre.id=original.preregistration_id AND created.grant_record#>>'{binding,original_provider_source_commit}'=rd->>'adapter_source_commit')
  AND (rd->>'original_deadline_core')::timestamptz>(rd->>'issued_at_core')::timestamptz
  AND (rd->>'original_deadline_core')::timestamptz<=(rd->>'issued_at_core')::timestamptz+interval '5 seconds'
  AND prepared.recorded_at>caller.recorded_at AND returned.recorded_at>=prepared.recorded_at
  AND rv->>'schema'='original_core_guest_native_poweroff_read_return_v2'
  AND ((rv->>'call_failed'='true' AND rv->>'original_context_failed'='false' AND rv->>'status' IN('','observed'))
   OR (rv->'call_failed'='false'::jsonb AND rv->'original_context_failed'='false'::jsonb AND rv->'status'='"observed"'::jsonb))
  AND NOT(rv ? 'plan')
  AND (rv->>'started_at_core')::timestamptz>=(rd->>'issued_at_core')::timestamptz
  AND (rv->>'original_returned_at_core')::timestamptz>=(rv->>'started_at_core')::timestamptz
  AND (rv->>'original_returned_at_core')::timestamptz<(rd->>'original_deadline_core')::timestamptz
  AND (rv->>'original_returned_at_core')::timestamptz<=returned.recorded_at) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO w FROM public.workflow_runs WHERE id=(p->>'failed_run_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE run_id=w.id;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed'
  AND j.finalization_ack_at>=j.returned_at AND j.finalization_ack_at=(p->>'failed_finish_ack_at')::timestamptz
  AND j.finalization_ack_at<=(r->>'recorded_at')::timestamptz AND returned.recorded_at<=j.returned_at
  AND encode(digest(convert_to(row_to_json(w)::text,'UTF8'),'sha256'),'hex')=p->>'failed_run_sha256'
  AND to_jsonb(w)=convert_from(decode(r->>'failed_run','base64'),'UTF8')::jsonb
  AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension'
  AND j.envelope::jsonb#>>'{workflow,id}'=original.intent_record->>'workflow_id'
  AND w.result->>'status'='failed' AND jsonb_typeof(w.result->'steps')='array'
  AND jsonb_array_length(w.result->'steps')=7) IS NOT TRUE THEN RETURN false; END IF;
 SELECT count(*) INTO n FROM public.workflow_runs candidate JOIN public.capacity_dispatch_jobs dispatch ON dispatch.run_id=candidate.id
  WHERE dispatch.envelope::jsonb#>>'{workflow,id}'=original.intent_record->>'workflow_id'
   AND candidate.status='failed' AND candidate.finished_at=dispatch.returned_at AND dispatch.state='returned'
   AND dispatch.return_status='failed' AND dispatch.finalization_ack_at IS NOT NULL
   AND candidate.result#>>'{steps,0,metadata,generation}'=r->>'generation'
   AND candidate.result#>>'{steps,0,metadata,fencing_token}'=r->>'fence'
   AND candidate.result#>>'{steps,0,metadata,lease_owner}'=r->>'lease_owner';
 IF n<>1 THEN RETURN false; END IF;
 SELECT count(DISTINCT s->>'id') INTO n FROM jsonb_array_elements(w.result->'steps')s;
 IF n<>7 THEN RETURN false; END IF;
 SELECT s INTO plan FROM jsonb_array_elements(w.result->'steps')s WHERE s->>'id'='plan-original-guest';
 SELECT s INTO retired FROM jsonb_array_elements(w.result->'steps')s WHERE s->>'id'='retire-original-guest';
 SELECT s INTO finished FROM jsonb_array_elements(w.result->'steps')s WHERE s->>'id'='finish-original-retirement';
 IF (plan->>'status'='succeeded' AND plan#>>'{metadata,generation}'=r->>'generation'
  AND plan#>>'{metadata,fencing_token}'=r->>'fence' AND plan#>>'{metadata,lease_owner}'=r->>'lease_owner'
  AND retired->>'status'='succeeded' AND retired#>>'{metadata,request_id}'=retirement::text
  AND finished->>'status'='failed'
  AND (SELECT count(*)=4 FROM jsonb_array_elements(w.result->'steps')s
    WHERE s->>'id' IN('provision-original-notify','complete-original-provision','refresh-original-membership','complete-original-retirement') AND s->>'status'='skipped')) IS NOT TRUE THEN RETURN false; END IF;
 IF coalesce(r->>'parent_admission_id','')='' THEN
  IF baseline ? 'retirement_forward' AND baseline->'retirement_forward'<>'null'::jsonb THEN RETURN false; END IF;
  IF (retired#>>'{metadata,intent_sha256}'=finalized_intent_sha256 AND retired#>>'{metadata,native_poweroff_known}'='false') IS NOT TRUE THEN RETURN false; END IF;
 ELSE
  SELECT * INTO parent FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'parent_admission_id')::uuid AND stage IN('admitted','off_qualified') AND record_sha256=r->>'parent_admission_sha256';
  IF NOT FOUND THEN RETURN false; END IF;
  IF (parent.original_record->>'mode'='normal_finish_recovery' AND parent.original_record->>'root_admission_id'=r->>'root_admission_id'
   AND parent.retirement_request_id=retirement AND parent.original_record->'evidence'=r->'evidence'
   AND baseline#>>'{retirement_forward,id}'=parent.id::text AND baseline#>>'{retirement_forward,stage}'=parent.stage
   AND retired#>>'{metadata,retirement_forward_id}'=parent.id::text) IS NOT TRUE THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.admission_id=parent.id AND
    (v.kind<>'off' OR v.recorded_at>j.returned_at OR v.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads q WHERE q.id=v.id AND q.stage='returned'))) THEN RETURN false; END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Do not remove permanent eligibility that a retained request has used.
-- The lock closes concurrent forward INSERTs until this migration commits.
-- +goose StatementBegin
LOCK TABLE public.capacity_guest_retirement_forwards IN SHARE MODE;
DO $$ BEGIN
 IF EXISTS(
  SELECT 1 FROM public.capacity_guest_retirement_forwards f
  JOIN public.capacity_guest_original_native_poweroff_reads n
   ON n.intent_id=f.retirement_request_id
   AND n.observation_sha256=f.original_record#>>'{normal_finish_recovery,native_off_return_sha256}'
  WHERE f.original_record ? 'normal_finish_recovery'
   AND n.original_record->'call_failed'='false'::jsonb
 ) THEN RAISE EXCEPTION 'retained closed successful native return recovery requires schema109'; END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_normal_finish_recovery_valid(r jsonb, retirement uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE p jsonb=r->'normal_finish_recovery'; original public.capacity_vm_retirement_intents;
 caller public.capacity_guest_original_caller_returns; prepared public.capacity_guest_original_native_poweroff_reads;
 returned public.capacity_guest_original_native_poweroff_reads; context_row public.capacity_guest_original_retirement_contexts;
 w public.workflow_runs; j public.capacity_dispatch_jobs; parent public.capacity_guest_retirement_forwards;
 requested public.capacity_guest_retirement_forwards; nonce public.capacity_vm_retirement_original_returns;
 baseline jsonb; steps jsonb; rd jsonb; rv jsonb; finalized_intent_sha256 text;
 n integer; retired jsonb; finished jsonb; plan jsonb;
BEGIN
 IF r->>'mode'<>'normal_finish_recovery' THEN RETURN false; END IF;
 IF r->>'stage'<>'requested' THEN
  SELECT * INTO requested FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'id')::uuid AND stage='requested';
  IF NOT FOUND OR requested.original_record->'normal_finish_recovery' IS DISTINCT FROM p
   OR requested.original_record->'evidence' IS DISTINCT FROM r->'evidence'
   OR requested.original_record->'original' IS DISTINCT FROM r->'original'
   OR requested.original_record->>'original_intent_sha256' IS DISTINCT FROM r->>'original_intent_sha256'
  THEN RETURN false; END IF;
  r=requested.original_record; p=r->'normal_finish_recovery';
 END IF;
 IF (jsonb_typeof(p)='object' AND (SELECT count(*) FROM jsonb_object_keys(p))=10
  AND p-ARRAY['schema','requesting_run_id','failed_run_id','failed_run_sha256','failed_finish_ack_at','native_off_read_id','native_off_prepared_sha256','native_off_return_sha256','original_context_deadline','original_lease_expires_at']='{}'::jsonb
  AND p->>'schema'='original_normal_finish_recovery_v1'
  AND p->>'failed_run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND p->>'native_off_read_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND (p->>'failed_run_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND (p->>'native_off_read_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND (p->>'requesting_run_id'='' OR p->>'requesting_run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  AND p->>'failed_run_sha256' ~ '^[a-f0-9]{64}$'
  AND p->>'native_off_prepared_sha256' ~ '^[a-f0-9]{64}$'
  AND p->>'native_off_return_sha256' ~ '^[a-f0-9]{64}$'
  AND r->>'run_id'='' AND coalesce(r->>'destroy_grant_id','')=''
  AND (r#>>'{barrier,ProcessStartedAt}')::timestamptz='0001-01-01T00:00:00Z'::timestamptz
  AND r#>>'{barrier,PID}'='0' AND r#>>'{barrier,SourceCommit}'='' AND r#>>'{barrier,Hostname}'='') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO original FROM public.capacity_vm_retirement_intents WHERE id=retirement AND preregistration_id=(r->>'preregistration_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO nonce FROM public.capacity_vm_retirement_original_returns
  WHERE intent_id=retirement AND sequence=1 AND kind='production_clock_nonce_v2';
 IF NOT FOUND THEN RETURN false; END IF;
 IF (nonce.original_return_record=convert_from(nonce.original_wire,'UTF8')::jsonb
  AND encode(digest(nonce.original_wire,'sha256'),'hex')=nonce.return_sha256
  AND nonce.return_sha256=r#>>'{evidence,nonce_sha256}'
  AND nonce.original_return_record->>'schema'='original_core_guest_retirement_nonce_return_v2'
  AND nonce.original_return_record->>'preflight_sha256'=original.intent_sha256
  AND nonce.original_return_record->'final_request'=r#>'{original,Request}') IS NOT TRUE THEN RETURN false; END IF;
 -- json (not jsonb) retains the finalized intent token from the original Go
 -- wire. The preflight intent SHA intentionally predates the Guest nonce.
 finalized_intent_sha256=encode(digest(convert_to((convert_from(nonce.original_wire,'UTF8')::json->'final_request'->'intent')::text,'UTF8'),'sha256'),'hex');
 SELECT * INTO caller FROM public.capacity_guest_original_caller_returns WHERE intent_id=retirement AND return_sha256=r->>'original_caller_sha256';
 IF NOT FOUND THEN RETURN false; END IF;
 IF (caller.original_record=convert_from(caller.original_wire,'UTF8')::jsonb
  AND encode(digest(caller.original_wire,'sha256'),'hex')=caller.return_sha256
  AND caller.original_record->>'request_id'=retirement::text
  AND caller.original_record->>'attempt_id'=original.attempt_id::text
  AND caller.original_record->>'status'='200' AND caller.original_record->>'body_persisted'='true'
  AND caller.original_record->>'preflight_failed'='false' AND caller.original_record->>'do_failed'='false'
  AND caller.original_record->>'read_failed'='false' AND caller.original_record->>'close_failed'='false'
  AND caller.original_record->>'original_context_failed'='false'
  AND (caller.original_record->>'original_deadline')::timestamptz=original.original_deadline
  AND (caller.original_record->>'driver_returned_at')::timestamptz<original.original_deadline
  AND (caller.original_record->>'started_at')::timestamptz>=(original.intent_record->>'issued_at')::timestamptz
  AND (caller.original_record->>'do_started_at')::timestamptz>=(caller.original_record->>'started_at')::timestamptz
  AND (caller.original_record->>'do_returned_at')::timestamptz>=(caller.original_record->>'do_started_at')::timestamptz
  AND (caller.original_record->>'read_returned_at')::timestamptz>=(caller.original_record->>'do_returned_at')::timestamptz
  AND (caller.original_record->>'close_returned_at')::timestamptz>=(caller.original_record->>'read_returned_at')::timestamptz
  AND (caller.original_record->>'driver_returned_at')::timestamptz>=(caller.original_record->>'close_returned_at')::timestamptz) IS NOT TRUE THEN RETURN false; END IF;
 SELECT count(*) INTO n FROM public.capacity_vm_retirement_original_returns WHERE intent_id=retirement;
 IF n<>5 OR NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns v WHERE v.intent_id=retirement AND v.sequence=5
   AND v.kind='production_retirement_v2:poweroff_command_returned'
   AND v.original_return_record=convert_from(v.original_wire,'UTF8')::jsonb
   AND v.original_return_record=convert_from(decode(caller.original_record->>'body','base64'),'UTF8')::jsonb
   AND v.original_return_record->>'journal_complete'='true' AND v.original_return_record->'hold_reasons'='[]'::jsonb
   AND v.original_return_record#>>'{record,sequence}'='4'
   AND v.original_return_record#>>'{record,poweroff_command_returned}'='true'
   AND v.original_return_record#>>'{record,writer_quiescence_evidence}'='true'
   AND v.original_return_record#>>'{record,powered_off_observed}'='false') THEN RETURN false; END IF;
 baseline=convert_from(decode(r->>'original_intent_wire','base64'),'UTF8')::jsonb;
 IF (encode(digest(decode(r->>'original_intent_wire','base64'),'sha256'),'hex')=r->>'original_intent_sha256'
  AND baseline->>'phase' IN('draining','drained') AND coalesce(baseline->>'recovery_only','false')='false'
  AND coalesce(baseline->>'floor_degraded','false')='false'
  AND baseline->>'generation'=r->>'generation' AND baseline->>'fencing_token'=r->>'fence'
  AND baseline->>'lease_owner'=r->>'lease_owner' AND baseline->>'lease_executor_id'=r->>'executor_id'
  AND (baseline->>'lease_expires_at')::timestamptz=(p->>'original_lease_expires_at')::timestamptz
  AND (baseline->>'lease_expires_at')::timestamptz<=(r->>'recorded_at')::timestamptz
  AND r#>>'{original,Request,intent,policy_id}'=baseline->>'policy_id'
  AND r#>>'{original,Request,intent,policy_checksum}'=baseline->>'policy_checksum'
  AND (baseline#>>'{decision,units}')::integer=(r#>>'{original,Request,intent,slot}')::integer-1) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO context_row FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=retirement;
 IF NOT FOUND OR context_row.original_context_deadline<>(p->>'original_context_deadline')::timestamptz
  OR context_row.original_context_deadline>=(r->>'recorded_at')::timestamptz
  OR original.original_deadline>=(r->>'recorded_at')::timestamptz THEN RETURN false; END IF;
 SELECT * INTO prepared FROM public.capacity_guest_original_native_poweroff_reads
  WHERE id=(p->>'native_off_read_id')::uuid AND intent_id=retirement;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT count(*) INTO n FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=retirement;
 IF n<>2 THEN RETURN false; END IF;
 SELECT * INTO returned FROM public.capacity_guest_original_native_poweroff_reads
  WHERE intent_id=retirement AND observation_sha256=p->>'native_off_return_sha256';
 IF NOT FOUND THEN RETURN false; END IF;
 rd=prepared.original_record; rv=returned.original_record;
 IF (prepared.observation_sha256=p->>'native_off_prepared_sha256'
  AND prepared.original_record=convert_from(prepared.original_wire,'UTF8')::jsonb
  AND returned.original_record=convert_from(returned.original_wire,'UTF8')::jsonb
  AND encode(digest(prepared.original_wire,'sha256'),'hex')=prepared.observation_sha256
  AND encode(digest(returned.original_wire,'sha256'),'hex')=returned.observation_sha256
  AND returned.original_native_join_wire=prepared.original_wire AND rv->'challenge'=rd
  AND rd->>'schema'='original_core_guest_native_poweroff_read_challenge_v2'
  AND rd->>'read_id'=prepared.id::text AND rd->>'intent_id'=retirement::text
  AND rd->>'intent_sha256'=finalized_intent_sha256 AND rd->>'original_caller_sha256'=caller.return_sha256
  AND rd->'tuple'=original.intent_record->'tuple'
  AND rd->>'mutation_binding_sha256' ~ '^[a-f0-9]{64}$'
  AND rd->>'adapter_source_commit' ~ '^[a-f0-9]{40}$'
  AND EXISTS(SELECT 1 FROM public.capacity_vm_provisioning_preregistrations pre JOIN public.capacity_mutation_grants created ON created.id=pre.create_grant_id WHERE pre.id=original.preregistration_id AND created.grant_record#>>'{binding,original_provider_source_commit}'=rd->>'adapter_source_commit')
  AND (rd->>'original_deadline_core')::timestamptz>(rd->>'issued_at_core')::timestamptz
  AND (rd->>'original_deadline_core')::timestamptz<=(rd->>'issued_at_core')::timestamptz+interval '5 seconds'
  AND prepared.recorded_at>caller.recorded_at AND returned.recorded_at>=prepared.recorded_at
  AND rv->>'schema'='original_core_guest_native_poweroff_read_return_v2'
  AND rv->>'call_failed'='true' AND rv->>'original_context_failed'='false'
  AND rv->>'status' IN('','observed') AND NOT(rv ? 'plan')
  AND (rv->>'started_at_core')::timestamptz>=(rd->>'issued_at_core')::timestamptz
  AND (rv->>'original_returned_at_core')::timestamptz>=(rv->>'started_at_core')::timestamptz
  AND (rv->>'original_returned_at_core')::timestamptz<(rd->>'original_deadline_core')::timestamptz
  AND (rv->>'original_returned_at_core')::timestamptz<=returned.recorded_at) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO w FROM public.workflow_runs WHERE id=(p->>'failed_run_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE run_id=w.id;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed'
  AND j.finalization_ack_at>=j.returned_at AND j.finalization_ack_at=(p->>'failed_finish_ack_at')::timestamptz
  AND j.finalization_ack_at<=(r->>'recorded_at')::timestamptz AND returned.recorded_at<=j.returned_at
  AND encode(digest(convert_to(row_to_json(w)::text,'UTF8'),'sha256'),'hex')=p->>'failed_run_sha256'
  AND to_jsonb(w)=convert_from(decode(r->>'failed_run','base64'),'UTF8')::jsonb
  AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension'
  AND j.envelope::jsonb#>>'{workflow,id}'=original.intent_record->>'workflow_id'
  AND w.result->>'status'='failed' AND jsonb_typeof(w.result->'steps')='array'
  AND jsonb_array_length(w.result->'steps')=7) IS NOT TRUE THEN RETURN false; END IF;
 SELECT count(*) INTO n FROM public.workflow_runs candidate JOIN public.capacity_dispatch_jobs dispatch ON dispatch.run_id=candidate.id
  WHERE dispatch.envelope::jsonb#>>'{workflow,id}'=original.intent_record->>'workflow_id'
   AND candidate.status='failed' AND candidate.finished_at=dispatch.returned_at AND dispatch.state='returned'
   AND dispatch.return_status='failed' AND dispatch.finalization_ack_at IS NOT NULL
   AND candidate.result#>>'{steps,0,metadata,generation}'=r->>'generation'
   AND candidate.result#>>'{steps,0,metadata,fencing_token}'=r->>'fence'
   AND candidate.result#>>'{steps,0,metadata,lease_owner}'=r->>'lease_owner';
 IF n<>1 THEN RETURN false; END IF;
 SELECT count(DISTINCT s->>'id') INTO n FROM jsonb_array_elements(w.result->'steps')s;
 IF n<>7 THEN RETURN false; END IF;
 SELECT s INTO plan FROM jsonb_array_elements(w.result->'steps')s WHERE s->>'id'='plan-original-guest';
 SELECT s INTO retired FROM jsonb_array_elements(w.result->'steps')s WHERE s->>'id'='retire-original-guest';
 SELECT s INTO finished FROM jsonb_array_elements(w.result->'steps')s WHERE s->>'id'='finish-original-retirement';
 IF (plan->>'status'='succeeded' AND plan#>>'{metadata,generation}'=r->>'generation'
  AND plan#>>'{metadata,fencing_token}'=r->>'fence' AND plan#>>'{metadata,lease_owner}'=r->>'lease_owner'
  AND retired->>'status'='succeeded' AND retired#>>'{metadata,request_id}'=retirement::text
  AND finished->>'status'='failed'
  AND (SELECT count(*)=4 FROM jsonb_array_elements(w.result->'steps')s
    WHERE s->>'id' IN('provision-original-notify','complete-original-provision','refresh-original-membership','complete-original-retirement') AND s->>'status'='skipped')) IS NOT TRUE THEN RETURN false; END IF;
 IF coalesce(r->>'parent_admission_id','')='' THEN
  IF baseline ? 'retirement_forward' AND baseline->'retirement_forward'<>'null'::jsonb THEN RETURN false; END IF;
  IF (retired#>>'{metadata,intent_sha256}'=finalized_intent_sha256 AND retired#>>'{metadata,native_poweroff_known}'='false') IS NOT TRUE THEN RETURN false; END IF;
 ELSE
  SELECT * INTO parent FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'parent_admission_id')::uuid AND stage IN('admitted','off_qualified') AND record_sha256=r->>'parent_admission_sha256';
  IF NOT FOUND THEN RETURN false; END IF;
  IF (parent.original_record->>'mode'='normal_finish_recovery' AND parent.original_record->>'root_admission_id'=r->>'root_admission_id'
   AND parent.retirement_request_id=retirement AND parent.original_record->'evidence'=r->'evidence'
   AND baseline#>>'{retirement_forward,id}'=parent.id::text AND baseline#>>'{retirement_forward,stage}'=parent.stage
   AND retired#>>'{metadata,retirement_forward_id}'=parent.id::text) IS NOT TRUE THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.admission_id=parent.id AND
    (v.kind<>'off' OR v.recorded_at>j.returned_at OR v.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads q WHERE q.id=v.id AND q.stage='returned'))) THEN RETURN false; END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
-- +goose StatementEnd
