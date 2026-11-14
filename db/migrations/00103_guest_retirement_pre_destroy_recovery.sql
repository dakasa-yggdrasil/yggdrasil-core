-- +goose Up
-- New Source-only authority for a CLOSED owner which never obtained DELETE.
-- Existing historical, normal-finish and settled read-only rules stay distinct.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_pre_destroy_authority_absent103(retirement uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
 WITH original AS (
  SELECT r.intent_record->'tuple' AS t,g.grant_record->'binding' AS b
  FROM public.capacity_vm_retirement_intents r
  JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=r.preregistration_id
  JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id
  WHERE r.id=retirement
 )
 SELECT COALESCE((SELECT
  jsonb_typeof(t)='object' AND jsonb_typeof(b)='object'
  AND coalesce(t->>'resource_id','')<>'' AND coalesce(t->>'resource_created_at','')<>''
  AND coalesce(b->>'ensure_capability','')<>'' AND coalesce(b->>'destroy_capability','')<>''
  AND b->>'ensure_capability'<>b->>'destroy_capability'
  AND (b->>'integration_instance_id',b->>'scope_checksum',b->>'profile_name')=(t->>'integration_instance_id',t->>'scope_checksum',t->>'profile')
  AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings d WHERE d.intent_id=retirement)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g
   WHERE (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(t->>'integration_instance_id',t->>'scope_checksum',t->>'profile')
   -- No state, epoch, realm or disposition filter can hide spent/unknown authority.
   -- Confirmed CREATE is ordinary ownership, not a permission to DELETE.
   AND NOT COALESCE(g.state='confirmed' AND g.grant_record#>>'{grant,capability}'=b->>'ensure_capability'
    AND coalesce(g.grant_record#>>'{grant,compensation_of}','')='',false)
   -- All slots of this LOCKED profile participate. A complete known pair
   -- identifies a different incarnation; a matching or incomplete pair cannot.
   AND ((g.grant_record#>>'{grant,expected_resource_id}'=t->>'resource_id'
     AND (g.grant_record#>>'{grant,expected_resource_created_at}'=t->>'resource_created_at' OR coalesce(g.grant_record#>>'{grant,expected_resource_created_at}','')=''))
    OR (g.grant_record#>>'{grant,expected_resource_created_at}'=t->>'resource_created_at' AND coalesce(g.grant_record#>>'{grant,expected_resource_id}','')='')
    OR (g.grant_record#>>'{settlement,resource_id}'=t->>'resource_id'
     AND (g.grant_record#>>'{settlement,resource_created_at}'=t->>'resource_created_at' OR coalesce(g.grant_record#>>'{settlement,resource_created_at}','')=''))
    OR (g.grant_record#>>'{settlement,resource_created_at}'=t->>'resource_created_at' AND coalesce(g.grant_record#>>'{settlement,resource_id}','')='')
    OR NOT ((coalesce(g.grant_record#>>'{grant,expected_resource_id}','')<>'' AND coalesce(g.grant_record#>>'{grant,expected_resource_created_at}','')<>'')
     OR (coalesce(g.grant_record#>>'{settlement,resource_id}','')<>'' AND coalesce(g.grant_record#>>'{settlement,resource_created_at}','')<>''))))
 FROM original),false)
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_pre_destroy_recovery_valid103(r jsonb, retirement uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE p jsonb; origin public.capacity_vm_retirement_intents;
 parent public.capacity_guest_retirement_forwards; admitted public.capacity_guest_retirement_forwards;
 requested public.capacity_guest_retirement_forwards;
 prepared public.capacity_guest_retirement_forward_reads; returned public.capacity_guest_retirement_forward_reads;
 w public.workflow_runs; j public.capacity_dispatch_jobs; c public.capacity_guest_original_retirement_contexts;
 baseline jsonb; rd jsonb; rv jsonb; steps jsonb; n integer;
BEGIN
 IF r->>'mode' IS DISTINCT FROM 'pre_destroy_recovery' OR r->>'recorded_at' IS NULL THEN RETURN false; END IF;
 IF r->>'stage'<>'requested' THEN
  SELECT * INTO requested FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'id')::uuid AND stage='requested';
  IF NOT FOUND OR requested.original_record->'pre_destroy_recovery' IS DISTINCT FROM r->'pre_destroy_recovery'
   OR requested.original_record->'evidence' IS DISTINCT FROM r->'evidence'
   OR requested.original_record->'original' IS DISTINCT FROM r->'original'
   OR requested.original_record->>'parent_admission_id' IS DISTINCT FROM r->>'parent_admission_id'
   OR requested.original_record->>'parent_admission_sha256' IS DISTINCT FROM r->>'parent_admission_sha256'
   OR requested.original_record->>'root_admission_id' IS DISTINCT FROM r->>'root_admission_id'
   OR requested.original_record->>'original_intent_sha256' IS DISTINCT FROM r->>'original_intent_sha256'
  THEN RETURN false; END IF;
  r=requested.original_record;
 END IF;
 p=r->'pre_destroy_recovery';
 IF (jsonb_typeof(p)='object' AND (SELECT count(*) FROM jsonb_object_keys(p))=11
  AND p-ARRAY['schema','requesting_run_id','failed_run_id','failed_run_sha256','dispatch_id','dispatch_sha256','native_off_read_id','native_off_prepared_sha256','native_off_return_sha256','original_context_deadline','original_lease_expires_at']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(p) kv WHERE jsonb_typeof(kv.value)<>'string')
  AND p->>'schema'='original_closed_pre_destroy_recovery_v1'
  AND p->>'requesting_run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND p->>'failed_run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND p->>'dispatch_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND p->>'native_off_read_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND (p->>'requesting_run_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND (p->>'failed_run_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND (p->>'dispatch_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND (p->>'native_off_read_id')::uuid<>'00000000-0000-0000-0000-000000000000'::uuid
  AND p->>'failed_run_sha256' ~ '^[a-f0-9]{64}$' AND p->>'dispatch_sha256' ~ '^[a-f0-9]{64}$'
  AND p->>'native_off_prepared_sha256' ~ '^[a-f0-9]{64}$' AND p->>'native_off_return_sha256' ~ '^[a-f0-9]{64}$'
  AND r->>'issuer'='source:pre-destroy-recovery' AND r->>'run_id'=''
  AND r->>'original_intent_sha256' ~ '^[a-f0-9]{64}$'
  AND encode(digest(decode(r->>'original_intent_wire','base64'),'sha256'),'hex')=r->>'original_intent_sha256'
  AND coalesce(r->>'destroy_grant_id','')='' AND NOT(r ? 'normal_finish_recovery') AND NOT(r ? 'continuation')
  AND (r#>>'{barrier,ProcessStartedAt}')::timestamptz='0001-01-01T00:00:00Z'::timestamptz
  AND r#>>'{barrier,PID}'='0' AND r#>>'{barrier,SourceCommit}'='' AND r#>>'{barrier,Hostname}'='') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO origin FROM public.capacity_vm_retirement_intents WHERE id=retirement AND preregistration_id=(r->>'preregistration_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO parent FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'parent_admission_id')::uuid AND stage='off_qualified' AND record_sha256=r->>'parent_admission_sha256';
 IF NOT FOUND OR parent.retirement_request_id<>retirement OR parent.original_record->>'mode' NOT IN('live','pre_destroy_recovery')
  OR parent.original_record->>'root_admission_id' IS DISTINCT FROM r->>'root_admission_id'
  OR parent.original_record->'evidence' IS DISTINCT FROM r->'evidence'
  OR parent.original_record->'original' IS DISTINCT FROM r->'original'
  OR parent.original_record->>'prefix_sha256' IS DISTINCT FROM r->>'prefix_sha256'
  OR parent.original_record->>'original_caller_sha256' IS DISTINCT FROM r->>'original_caller_sha256'
  OR parent.original_record->>'run_id' IS DISTINCT FROM p->>'failed_run_id'
  OR parent.original_record->>'generation' IS DISTINCT FROM r->>'generation'
  OR parent.original_record->>'fence' IS DISTINCT FROM r->>'fence'
  OR parent.original_record->>'lease_owner' IS DISTINCT FROM r->>'lease_owner'
  OR parent.original_record->>'executor_id' IS DISTINCT FROM r->>'executor_id'
  OR coalesce(parent.original_record->>'destroy_grant_id','')<>'' THEN RETURN false; END IF;
 SELECT * INTO admitted FROM public.capacity_guest_retirement_forwards WHERE id=parent.id AND stage='admitted';
 IF NOT FOUND OR parent.original_record->>'admission_sha256'<>admitted.record_sha256 THEN RETURN false; END IF;
 baseline=convert_from(decode(r->>'original_intent_wire','base64'),'UTF8')::jsonb;
 SELECT * INTO c FROM public.capacity_guest_original_retirement_contexts WHERE intent_id=retirement;
 IF NOT FOUND OR (p->>'original_context_deadline')::timestamptz<>c.original_context_deadline
  OR (p->>'original_lease_expires_at')::timestamptz IS DISTINCT FROM (baseline->>'lease_expires_at')::timestamptz
  OR baseline#>>'{retirement_forward,id}'<>parent.id::text OR baseline#>>'{retirement_forward,stage}'<>parent.stage
  OR baseline->>'generation'<>r->>'generation' OR baseline->>'fencing_token'<>r->>'fence'
  OR baseline->>'lease_owner'<>r->>'lease_owner' OR baseline->>'lease_executor_id'<>r->>'executor_id'
  OR (r->>'recorded_at')::timestamptz<=c.original_context_deadline
  OR (r->>'recorded_at')::timestamptz<=origin.original_deadline
  OR (r->>'recorded_at')::timestamptz<=(p->>'original_lease_expires_at')::timestamptz THEN RETURN false; END IF;
 SELECT * INTO w FROM public.workflow_runs WHERE id=(p->>'failed_run_id')::uuid;
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE id=(p->>'dispatch_id')::uuid;
 IF NOT FOUND OR w.id IS NULL OR j.id IS NULL OR j.run_id<>w.id OR (SELECT count(*) FROM public.capacity_dispatch_jobs z WHERE z.run_id=w.id)<>1
  OR w.status<>'failed' OR j.state<>'returned' OR j.return_status<>'failed'
  OR w.finished_at IS NULL OR w.finished_at IS DISTINCT FROM j.returned_at
  OR j.finalization_ack_at IS NULL OR j.finalization_ack_at<j.returned_at
  OR j.finalization_ack_at>(r->>'recorded_at')::timestamptz
  OR to_jsonb(w) IS DISTINCT FROM convert_from(decode(r->>'failed_run','base64'),'UTF8')::jsonb
  OR encode(digest(decode(r->>'failed_run','base64'),'sha256'),'hex')<>p->>'failed_run_sha256'
  OR encode(digest(to_jsonb(j)::text,'sha256'),'hex')<>p->>'dispatch_sha256'
  OR j.envelope::jsonb#>>'{workflow,id}'<>origin.intent_record->>'workflow_id'
  OR (j.realm,j.environment,j.domain,j.dimension)<>(r->>'namespace',r->>'environment',r->>'domain',r->>'dimension') THEN RETURN false; END IF;
 steps=w.result->'steps';
 IF jsonb_array_length(steps)<>7 OR (SELECT count(DISTINCT s->>'id') FROM jsonb_array_elements(steps)s)<>7
  OR (SELECT count(*) FROM jsonb_array_elements(steps)s WHERE s->>'id' IN('plan-original-guest','retire-original-guest','finish-original-retirement','provision-original-notify','complete-original-provision','refresh-original-membership','complete-original-retirement'))<>7 THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(steps)s WHERE s->>'id'='plan-original-guest' AND s->>'status'='succeeded'
  AND s#>>'{metadata,generation}'=parent.original_record->>'generation' AND s#>>'{metadata,fencing_token}'=parent.original_record->>'fence'
  AND s#>>'{metadata,lease_owner}'=parent.original_record->>'lease_owner')
  OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(steps)s WHERE s->>'id'='retire-original-guest' AND s->>'status'='succeeded'
   AND s#>>'{metadata,retirement_forward_id}'=parent.id::text AND s#>>'{metadata,request_id}'=retirement::text)
  OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(steps)s WHERE s->>'id'='finish-original-retirement' AND s->>'status'='failed')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(steps)s WHERE s->>'id' IN('provision-original-notify','complete-original-provision','refresh-original-membership','complete-original-retirement') AND s->>'status'<>'skipped') THEN RETURN false; END IF;
 SELECT * INTO prepared FROM public.capacity_guest_retirement_forward_reads WHERE id=(p->>'native_off_read_id')::uuid AND stage='prepared';
 SELECT * INTO returned FROM public.capacity_guest_retirement_forward_reads WHERE id=prepared.id AND stage='returned';
 rd=prepared.original_record; rv=returned.original_record;
 IF NOT FOUND OR prepared.retirement_request_id<>retirement OR prepared.admission_id<>admitted.id OR prepared.kind<>'off'
  OR returned.retirement_request_id<>retirement OR returned.admission_id<>admitted.id OR returned.kind<>'off'
  OR rd->>'read_id' IS DISTINCT FROM prepared.id::text OR rd->>'admission_id' IS DISTINCT FROM admitted.id::text
  OR rd->>'retirement_request_id' IS DISTINCT FROM retirement::text OR rd->>'kind' IS DISTINCT FROM 'off'
  OR prepared.record_sha256<>p->>'native_off_prepared_sha256' OR returned.record_sha256<>p->>'native_off_return_sha256'
  OR parent.original_record->>'native_off_read_id'<>prepared.id::text OR parent.original_record->>'native_off_sha256'<>returned.record_sha256
  OR prepared.record_sha256<>encode(digest(prepared.original_wire,'sha256'),'hex') OR prepared.original_record IS DISTINCT FROM convert_from(prepared.original_wire,'UTF8')::jsonb
  OR returned.record_sha256<>encode(digest(returned.original_wire,'sha256'),'hex') OR returned.original_record IS DISTINCT FROM convert_from(returned.original_wire,'UTF8')::jsonb
  OR rd->>'admission_sha256'<>admitted.record_sha256 OR rd->>'prefix_sha256'<>r->>'prefix_sha256' OR rd->>'original_caller_sha256'<>r->>'original_caller_sha256'
  OR rd->'tuple' IS DISTINCT FROM origin.intent_record->'tuple' OR rv->'read' IS DISTINCT FROM rd
  OR rv->>'schema' IS DISTINCT FROM 'original_core_guest_retirement_forward_read_return_v1'
  OR rd->>'schema' IS DISTINCT FROM 'original_core_guest_retirement_forward_read_v1'
  OR rv->>'status' IS DISTINCT FROM 'observed' OR rv->'call_failed' IS DISTINCT FROM 'false'::jsonb OR rv->'original_context_failed' IS DISTINCT FROM 'false'::jsonb
  OR rd->>'destroy_grant_id' IS DISTINCT FROM ''
  OR rv ?| ARRAY['observation','original_destroy_receipt','observer_source_commit','original_observer_return']
  OR rv->>'started_at_core' IS NULL OR rv->>'original_returned_at_core' IS NULL
  OR rd->>'issued_at_core' IS NULL OR rd->>'original_deadline_core' IS NULL
  OR (rv->>'started_at_core')::timestamptz<(rd->>'issued_at_core')::timestamptz
  OR (rv->>'original_returned_at_core')::timestamptz<(rv->>'started_at_core')::timestamptz
  OR (rd->>'original_deadline_core')::timestamptz<=(rd->>'issued_at_core')::timestamptz
  OR (rd->>'original_deadline_core')::timestamptz>(rd->>'issued_at_core')::timestamptz+interval '5 seconds'
  OR rv#>>'{plan,server,status}' NOT IN('off','stopped')
  OR (rv->>'original_returned_at_core')::timestamptz>=(rd->>'original_deadline_core')::timestamptz
  OR (r->>'recorded_at')::timestamptz<=(rd->>'original_deadline_core')::timestamptz
  OR returned.recorded_at<prepared.recorded_at OR returned.recorded_at>j.returned_at
  OR parent.recorded_at<returned.recorded_at THEN RETURN false; END IF;
 -- The absolute newest actual row must qualify; unknown/open later reads HOLD.
 IF r->>'stage'='requested' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'id')::uuid AND stage='requested') THEN
  IF public.retirement_forward_pre_destroy_authority_absent103(retirement) IS NOT TRUE
   OR EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads a WHERE a.retirement_request_id=retirement AND a.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads z WHERE z.id=a.id AND z.stage='returned'))
   OR (SELECT id FROM public.capacity_guest_retirement_forward_reads WHERE retirement_request_id=retirement AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1) IS DISTINCT FROM prepared.id THEN RETURN false; END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_mode103') THEN
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_mode97') THEN RAISE EXCEPTION 'exact prior mode97 required'; END IF;
  ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT retirement_forward_mode97;
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_mode103 CHECK((original_record->>'mode' IN('live','historical','settled_absence_continuation','normal_finish_recovery','pre_destroy_recovery') AND original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$') IS TRUE);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_pre_destroy103') THEN
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_pre_destroy103 CHECK((CASE
   WHEN original_record->>'mode'='pre_destroy_recovery' THEN jsonb_typeof(original_record->'pre_destroy_recovery')='object' AND original_record#>>'{pre_destroy_recovery,schema}'='original_closed_pre_destroy_recovery_v1'
   WHEN original_record->>'mode'='settled_absence_continuation' AND original_record ? 'pre_destroy_recovery' THEN jsonb_typeof(original_record->'pre_destroy_recovery')='object' AND original_record#>>'{pre_destroy_recovery,schema}'='original_closed_pre_destroy_recovery_v1'
   ELSE NOT(original_record ? 'pre_destroy_recovery') END) IS TRUE);
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_forward() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE original public.capacity_vm_retirement_intents; nonce public.capacity_vm_retirement_original_returns;
 parent public.capacity_guest_retirement_forwards; admitted public.capacity_guest_retirement_forwards;
 current_row jsonb; claim jsonb; observed public.capacity_guest_retirement_forward_reads; n integer;
BEGIN
 SELECT * INTO STRICT original FROM public.capacity_vm_retirement_intents WHERE id=NEW.retirement_request_id AND preregistration_id=NEW.preregistration_id FOR SHARE;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension])::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY['capacity-retirement-forward-profile',NEW.integration_instance_id,NEW.scope_checksum,NEW.profile_name])::text,0));
 SELECT intent INTO STRICT current_row FROM public.capacity_intents WHERE namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE p.id=original.preregistration_id AND g.namespace=NEW.namespace AND g.environment=NEW.environment AND g.domain=NEW.domain AND g.dimension=NEW.dimension AND g.integration_instance_id::text=NEW.integration_instance_id AND g.scope_checksum=NEW.scope_checksum AND g.profile_name=NEW.profile_name AND g.slot=NEW.slot) THEN RAISE EXCEPTION 'original create scope and physical profile required'; END IF;
 SELECT * INTO STRICT nonce FROM public.capacity_vm_retirement_original_returns WHERE intent_id=NEW.retirement_request_id AND sequence=1 AND kind='production_clock_nonce_v2';
 IF (NEW.original_record#>'{original,Request}'=nonce.original_return_record->'final_request' AND original.intent_record->>'schema'='original_guest_production_retirement_intent_v2' AND NEW.original_record#>>'{evidence,nonce_sha256}'=nonce.return_sha256 AND NEW.original_record->>'original_caller_sha256'=NEW.original_record#>>'{evidence,caller_sha256}') IS NOT TRUE THEN RAISE EXCEPTION 'exact original nonce and retained V2 request required'; END IF;
 SELECT count(*) INTO n FROM public.capacity_vm_retirement_original_returns WHERE intent_id=NEW.retirement_request_id;
 IF n NOT IN(4,5) OR (NEW.original_record#>'{evidence,journal_sha256}'=(SELECT jsonb_agg(return_sha256 ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=NEW.retirement_request_id AND sequence>1)) IS NOT TRUE THEN RAISE EXCEPTION 'entire original prefix including optional genuine fourth required'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns r WHERE r.intent_id=NEW.retirement_request_id AND r.sequence>1 AND (r.kind=CASE r.sequence WHEN 2 THEN 'production_retirement_v2:possible_start' WHEN 3 THEN 'production_retirement_v2:quiescent' WHEN 4 THEN 'production_retirement_v2:poweroff_possible_start' WHEN 5 THEN 'production_retirement_v2:poweroff_command_returned' END AND r.original_return_record->>'journal_complete'='true' AND r.original_return_record#>>'{record,powered_off_observed}'='false') IS NOT TRUE) THEN RAISE EXCEPTION 'unlinked uncertain or extra original cannot be filtered'; END IF;
 -- A read-only descendant must carry a parent's permanent origin proof,
 -- even when the new row tries to omit the key altogether. Neither JSON null
 -- nor a changed value is equivalent to that parent's authenticated object.
 IF NEW.original_record->>'mode'='settled_absence_continuation' THEN
  SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_record->>'parent_admission_id')::uuid AND stage IN('admitted','off_qualified') AND retirement_request_id=NEW.retirement_request_id AND record_sha256=NEW.original_record->>'parent_admission_sha256';
  IF ((parent.original_record ? 'pre_destroy_recovery') OR (NEW.original_record ? 'pre_destroy_recovery'))
   AND NEW.original_record->'pre_destroy_recovery' IS DISTINCT FROM parent.original_record->'pre_destroy_recovery' THEN RAISE EXCEPTION 'settled child preserves exact pre-DELETE origin'; END IF;
 END IF;
 IF NEW.original_record ? 'pre_destroy_recovery' THEN
  IF NEW.original_record->>'mode'='pre_destroy_recovery' THEN
   IF public.retirement_forward_pre_destroy_recovery_valid103(NEW.original_record,NEW.retirement_request_id) IS NOT TRUE THEN RAISE EXCEPTION 'closed failed pre-DELETE owner proof required'; END IF;
  ELSIF NEW.original_record->>'mode'='settled_absence_continuation' THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_record->>'parent_admission_id')::uuid AND stage IN('admitted','off_qualified') AND record_sha256=NEW.original_record->>'parent_admission_sha256';
   IF (parent.original_record->'pre_destroy_recovery'=NEW.original_record->'pre_destroy_recovery' AND parent.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND parent.retirement_request_id=NEW.retirement_request_id AND parent.original_record->'evidence'=NEW.original_record->'evidence') IS NOT TRUE THEN RAISE EXCEPTION 'settled child preserves exact pre-DELETE origin'; END IF;
  ELSE RAISE EXCEPTION 'pre-DELETE proof cannot relabel an existing mode';
  END IF;
 END IF;
 IF NEW.original_record ? 'normal_finish_recovery' THEN
  IF NEW.original_record->>'mode'='normal_finish_recovery' THEN
   IF public.retirement_forward_normal_finish_recovery_valid(NEW.original_record,NEW.retirement_request_id) IS NOT TRUE THEN RAISE EXCEPTION 'closed successful Guest and failed native-OFF finish proof required'; END IF;
  ELSIF NEW.original_record->>'mode'='settled_absence_continuation' THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_record->>'parent_admission_id')::uuid AND stage IN('admitted','off_qualified') AND record_sha256=NEW.original_record->>'parent_admission_sha256';
   IF (parent.original_record->'normal_finish_recovery'=NEW.original_record->'normal_finish_recovery' AND parent.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND parent.retirement_request_id=NEW.retirement_request_id AND parent.original_record->'evidence'=NEW.original_record->'evidence') IS NOT TRUE THEN RAISE EXCEPTION 'settled read-only child preserves normal-finish origin proof'; END IF;
  ELSE RAISE EXCEPTION 'normal successful caller never enters an old partial mode';
  END IF;
 ELSE
 IF NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_returns c WHERE c.intent_id=NEW.retirement_request_id AND c.return_sha256=NEW.original_record->>'original_caller_sha256' AND (c.original_record->>'preflight_failed'='false') IS TRUE AND NOT(c.original_record->>'status'='200' AND c.original_record->>'body_persisted'='true' AND c.original_record->>'do_failed'='false' AND c.original_record->>'read_failed'='false' AND c.original_record->>'close_failed'='false' AND c.original_record->>'original_context_failed'='false' AND (c.original_record->>'driver_returned_at')::timestamptz<original.original_deadline)) THEN RAISE EXCEPTION 'retained failed original caller required'; END IF;
 END IF;
 IF (NEW.original_record#>'{evidence,authority_sha256}'=(SELECT jsonb_agg(v.authority_sha256 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=NEW.retirement_request_id) AND (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=NEW.retirement_request_id)=4 AND (SELECT count(*) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=NEW.retirement_request_id)=4) IS NOT TRUE THEN RAISE EXCEPTION 'four exact original authorized reads required'; END IF;
 IF NEW.stage='requested' THEN
  IF NEW.original_record->>'mode'='pre_destroy_recovery' THEN
   IF ((current_row->>'lease_expires_at')::timestamptz<clock_timestamp()
    AND current_row->>'generation'=NEW.original_record->>'generation' AND current_row->>'fencing_token'=NEW.original_record->>'fence'
    AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id'
    AND current_row#>>'{retirement_forward,id}'=NEW.original_record->>'parent_admission_id' AND current_row#>>'{retirement_forward,stage}'='off_qualified'
    AND convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row
    AND public.retirement_forward_pre_destroy_authority_absent103(NEW.retirement_request_id)
    AND public.retirement_forward_pre_destroy_recovery_valid103(NEW.original_record,NEW.retirement_request_id)
    AND public.retirement_forward_continuation_quiet(NEW.original_record || jsonb_build_object('destroy_grant_id',''),(NEW.original_record#>>'{pre_destroy_recovery,requesting_run_id}')::uuid)) IS NOT TRUE THEN RAISE EXCEPTION 'exact quiet naturally closed pre-DELETE request required'; END IF;
  ELSE
  IF NEW.original_record->>'mode'='normal_finish_recovery' THEN
   IF ((current_row->>'lease_expires_at')::timestamptz<=clock_timestamp()
    AND current_row->>'generation'=NEW.original_record->>'generation' AND current_row->>'fencing_token'=NEW.original_record->>'fence'
    AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id'
    AND convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row
    AND public.retirement_forward_normal_finish_recovery_valid(NEW.original_record,NEW.retirement_request_id)) IS NOT TRUE THEN RAISE EXCEPTION 'exact naturally expired normal-finish request required'; END IF;
   IF EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=NEW.retirement_request_id)
    OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.integration_instance_id::text=NEW.integration_instance_id AND g.scope_checksum=NEW.scope_checksum AND g.profile_name=NEW.profile_name AND g.slot=NEW.slot AND g.generation=(NEW.original_record->>'generation')::bigint AND g.grant_record#>>'{grant,capability}'=g.grant_record#>>'{binding,destroy_capability}') THEN RAISE EXCEPTION 'normal-finish recovery never reopens DELETE authority'; END IF;
   IF NEW.original_record#>>'{normal_finish_recovery,requesting_run_id}'<>'' THEN
    IF (NEW.original_record->>'issuer'='source:normal-finish-recovery' AND public.retirement_forward_continuation_quiet(NEW.original_record || jsonb_build_object('destroy_grant_id',''),(NEW.original_record#>>'{normal_finish_recovery,requesting_run_id}')::uuid)) IS NOT TRUE THEN RAISE EXCEPTION 'exact current Source plan and quiet scope required'; END IF;
   ELSE
    IF EXISTS(SELECT 1 FROM public.workflow_runs w WHERE (w.workflow_id=(NEW.original_record#>>'{original,Request,intent,workflow_id}')::uuid OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(NEW.original_record#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
     OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(NEW.original_record#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
     OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(NEW.integration_instance_id,NEW.scope_checksum,NEW.profile_name) AND g.state IN('issued','redeemed','settled','compensating') AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL) THEN RAISE EXCEPTION 'normal-finish request requires whole current quiet scope'; END IF;
    IF NEW.original_record->>'issuer' NOT LIKE 'collaborator:%' THEN RAISE EXCEPTION 'named current operator required'; END IF;
    IF EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=NEW.namespace AND j.environment=NEW.environment AND j.domain=NEW.domain AND j.dimension=NEW.dimension AND (j.state IN('queued','started','unknown') OR j.finalization_ack_at IS NULL)) THEN RAISE EXCEPTION 'all original dispatches closed before manual normal-finish request'; END IF;
   END IF;
  ELSE
  IF NEW.original_record->>'mode'='settled_absence_continuation' THEN
   IF ((current_row->>'lease_expires_at')::timestamptz<=clock_timestamp()
    AND current_row->>'generation'=NEW.original_record->>'generation' AND current_row->>'fencing_token'=NEW.original_record->>'fence'
    AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id'
    AND current_row#>>'{retirement_forward,id}'=NEW.original_record->>'parent_admission_id' AND current_row#>>'{retirement_forward,stage}' IN('admitted','off_qualified')
    AND convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row
    AND public.retirement_forward_continuation_valid(NEW.original_record,NEW.retirement_request_id)) IS NOT TRUE THEN RAISE EXCEPTION 'exact closed owning settled Pending continuation required'; END IF;
  ELSE
  IF (NEW.original_record->>'mode'='historical' AND (current_row->>'lease_expires_at')::timestamptz<=clock_timestamp() AND (current_row->>'generation')::bigint=(NEW.original_record->>'generation')::bigint AND (current_row->>'fencing_token')::bigint=(NEW.original_record->>'fence')::bigint AND convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row) IS NOT TRUE THEN RAISE EXCEPTION 'closed historical exact CAS request required'; END IF;
  IF ((NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz>(current_row->>'lease_expires_at')::timestamptz AND (NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz>original.original_deadline AND (NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz<=clock_timestamp() AND NEW.original_record#>>'{barrier,SourceCommit}'=NEW.original_record->>'actual_core_source' AND (NEW.original_record#>>'{barrier,PID}')::bigint>0 AND length(NEW.original_record#>>'{barrier,Hostname}')>0 AND EXISTS(SELECT 1 FROM public.capacity_guest_original_retirement_contexts c WHERE c.intent_id=NEW.retirement_request_id AND (NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz>c.original_context_deadline)) IS NOT TRUE THEN RAISE EXCEPTION 'actual replacement Core after all original deadlines required'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE to_jsonb(w)=convert_from(decode(NEW.original_record->>'failed_run','base64'),'UTF8')::jsonb AND w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND j.finalization_ack_at IS NOT NULL AND j.envelope::jsonb#>>'{workflow,id}'=NEW.original_record#>>'{original,Request,intent,workflow_id}' AND w.result#>>'{steps,0,metadata,generation}'=NEW.original_record->>'generation' AND w.result#>>'{steps,0,metadata,fencing_token}'=NEW.original_record->>'fence' AND w.result#>>'{steps,0,metadata,lease_owner}'=current_row->>'lease_owner') THEN RAISE EXCEPTION 'historical admission needs exact closed failed original run'; END IF;
  IF coalesce(NEW.original_record->>'parent_admission_id','')<>'' THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_record->>'parent_admission_id')::uuid AND record_sha256=NEW.original_record->>'parent_admission_sha256' AND stage IN('admitted','off_qualified');
   IF (parent.retirement_request_id=NEW.retirement_request_id AND parent.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND current_row#>>'{retirement_forward,id}'=parent.id::text AND current_row#>>'{retirement_forward,stage}'=parent.stage AND parent.original_record->'evidence'=NEW.original_record->'evidence') IS NOT TRUE THEN RAISE EXCEPTION 'historical continuation preserves exact parent and root'; END IF;
   IF EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=NEW.retirement_request_id) AND NOT EXISTS(
    SELECT 1 FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id
     JOIN public.capacity_guest_retirement_forwards a ON a.id=(b.original_eligibility_record->>'admission_id')::uuid AND a.stage='admitted'
    WHERE b.intent_id=NEW.retirement_request_id AND b.destroy_grant_id::text=NEW.original_record->>'destroy_grant_id'
     AND b.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1'
     AND b.original_eligibility_record->>'admission_sha256'=a.record_sha256
     AND a.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND a.original_record->'evidence'=NEW.original_record->'evidence'
     AND g.state IN('settled','confirmed') AND (g.grant_record#>>'{settlement,outcome}'='accepted' AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true') IS TRUE
   ) THEN RAISE EXCEPTION 'only a known accepted owning DELETE permits read-only continuation'; END IF;
  ELSIF coalesce(NEW.original_record->>'destroy_grant_id','')<>'' THEN RAISE EXCEPTION 'new root cannot adopt an unrelated destroy';
  END IF;
  END IF;
  END IF;
  END IF;
 ELSIF NEW.stage='admitted' THEN
  IF NEW.original_record->>'mode'='pre_destroy_recovery' AND
   (public.retirement_forward_pre_destroy_authority_absent103(NEW.retirement_request_id) IS NOT TRUE OR
    public.retirement_forward_continuation_quiet(NEW.original_record || jsonb_build_object('destroy_grant_id',''),(NEW.original_record->>'run_id')::uuid) IS NOT TRUE) THEN RAISE EXCEPTION 'new pre-DELETE claimant requires absent authority and exact typed quiet'; END IF;
  IF NEW.original_record->>'mode'='settled_absence_continuation' AND public.retirement_forward_continuation_quiet(NEW.original_record,(NEW.original_record->>'run_id')::uuid) IS NOT TRUE THEN RAISE EXCEPTION 'new claimant requires exact current dispatch quiet'; END IF;
  IF NEW.original_record->>'mode' IN('historical','settled_absence_continuation','normal_finish_recovery','pre_destroy_recovery') THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=NEW.id AND stage='requested';
   IF ((NEW.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id'])=(parent.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id']) AND current_row#>>'{retirement_forward,id}'=NEW.id::text AND current_row#>>'{retirement_forward,stage}'='requested' AND (NEW.original_record->>'fence')::bigint=(current_row->>'fencing_token')::bigint+1 AND (current_row->>'lease_expires_at')::timestamptz<=clock_timestamp()) IS NOT TRUE THEN RAISE EXCEPTION 'new fenced claim preserves requested originals'; END IF;
  ELSIF (convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row AND (current_row->>'lease_expires_at')::timestamptz>clock_timestamp() AND (current_row->>'fencing_token')::bigint=(NEW.original_record->>'fence')::bigint AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id' AND NOT(current_row ? 'retirement_forward')) IS NOT TRUE THEN RAISE EXCEPTION 'same original live lease required'; END IF;
 ELSE
  SELECT * INTO STRICT admitted FROM public.capacity_guest_retirement_forwards WHERE id=NEW.id AND stage='admitted';
  IF (current_row#>>'{retirement_forward,id}'=NEW.id::text AND current_row#>>'{retirement_forward,stage}' IN('admitted','off_qualified') AND current_row->>'generation'=admitted.original_record->>'generation' AND current_row->>'fencing_token'=admitted.original_record->>'fence' AND current_row->>'lease_owner'=admitted.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=admitted.original_record->>'executor_id' AND (current_row->>'lease_expires_at')::timestamptz>clock_timestamp()) IS NOT TRUE THEN RAISE EXCEPTION 'qualification belongs to current live exact claimant'; END IF;
  IF ((NEW.original_record-ARRAY['stage','recorded_at','admission_sha256','native_off_read_id','native_off_sha256','destroy_grant_id','native_absence_sha256','terminal_intent_sha256','terminal_intent_wire'])=(admitted.original_record-ARRAY['stage','recorded_at','admission_sha256','native_off_read_id','native_off_sha256','destroy_grant_id','native_absence_sha256','terminal_intent_sha256','terminal_intent_wire']) AND NEW.original_record->>'admission_sha256'=admitted.record_sha256 AND NEW.original_record->'evidence'=admitted.original_record->'evidence' AND NEW.original_record->>'prefix_sha256'=admitted.original_record->>'prefix_sha256' AND NEW.original_record->'original'=admitted.original_record->'original' AND NEW.original_record->>'original_intent_sha256'=admitted.original_record->>'original_intent_sha256' AND (NEW.original_record->>'fence')::bigint=(admitted.original_record->>'fence')::bigint) IS NOT TRUE THEN RAISE EXCEPTION 'qualified stages preserve exact admitted frame'; END IF;
  IF NEW.stage='off_qualified' AND NEW.original_record->>'mode'='settled_absence_continuation' THEN RAISE EXCEPTION 'settled absence continuation cannot authorize OFF'; END IF;
  IF NEW.stage='off_qualified' THEN
   SELECT * INTO STRICT observed FROM public.capacity_guest_retirement_forward_reads WHERE id=(NEW.original_record->>'native_off_read_id')::uuid AND admission_id=NEW.id AND kind='off' AND stage='returned';
   IF (observed.record_sha256=NEW.original_record->>'native_off_sha256' AND observed.original_record->>'status'='observed' AND observed.original_record->>'call_failed'='false' AND observed.original_record->>'original_context_failed'='false' AND observed.original_record#>>'{plan,server,status}' IN('off','stopped')) IS NOT TRUE THEN RAISE EXCEPTION 'actual complete exact native OFF required'; END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id JOIN public.capacity_guest_retirement_forwards a ON a.id=(b.original_eligibility_record->>'admission_id')::uuid AND a.stage='admitted' WHERE b.intent_id=NEW.retirement_request_id AND b.destroy_grant_id::text=NEW.original_record->>'destroy_grant_id' AND b.original_eligibility_record->>'admission_sha256'=a.record_sha256 AND a.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND a.original_record->'evidence'=NEW.original_record->'evidence' AND b.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1' AND g.state='confirmed') THEN RAISE EXCEPTION 'own confirmed exact destroy required for terminal'; END IF;
  IF NEW.stage='terminal' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.admission_id=NEW.id AND v.kind='absence' AND v.stage='returned' AND v.record_sha256=NEW.original_record->>'native_absence_sha256' AND v.original_record#>>'{read,destroy_grant_id}'=NEW.original_record->>'destroy_grant_id' AND v.original_record->>'status'='observed' AND v.original_record->>'call_failed'='false' AND v.original_record->>'original_context_failed'='false') THEN RAISE EXCEPTION 'terminal needs its own retained fresh absence'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Immutable used proof cannot be erased, normalized or relabelled for downgrade.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards WHERE original_record ? 'pre_destroy_recovery' OR original_record->>'mode'='pre_destroy_recovery') THEN RAISE EXCEPTION 'used pre-DELETE recovery proof is permanent provenance'; END IF;
 ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT IF EXISTS retirement_forward_pre_destroy103;
 ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT IF EXISTS retirement_forward_mode103;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_mode97') THEN
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_mode97 CHECK((original_record->>'mode' IN('live','historical','settled_absence_continuation','normal_finish_recovery') AND original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$') IS TRUE);
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_forward() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE original public.capacity_vm_retirement_intents; nonce public.capacity_vm_retirement_original_returns;
 parent public.capacity_guest_retirement_forwards; admitted public.capacity_guest_retirement_forwards;
 current_row jsonb; claim jsonb; observed public.capacity_guest_retirement_forward_reads; n integer;
BEGIN
 SELECT * INTO STRICT original FROM public.capacity_vm_retirement_intents WHERE id=NEW.retirement_request_id AND preregistration_id=NEW.preregistration_id FOR SHARE;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension])::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY['capacity-retirement-forward-profile',NEW.integration_instance_id,NEW.scope_checksum,NEW.profile_name])::text,0));
 SELECT intent INTO STRICT current_row FROM public.capacity_intents WHERE namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE p.id=original.preregistration_id AND g.namespace=NEW.namespace AND g.environment=NEW.environment AND g.domain=NEW.domain AND g.dimension=NEW.dimension AND g.integration_instance_id::text=NEW.integration_instance_id AND g.scope_checksum=NEW.scope_checksum AND g.profile_name=NEW.profile_name AND g.slot=NEW.slot) THEN RAISE EXCEPTION 'original create scope and physical profile required'; END IF;
 SELECT * INTO STRICT nonce FROM public.capacity_vm_retirement_original_returns WHERE intent_id=NEW.retirement_request_id AND sequence=1 AND kind='production_clock_nonce_v2';
 IF (NEW.original_record#>'{original,Request}'=nonce.original_return_record->'final_request' AND original.intent_record->>'schema'='original_guest_production_retirement_intent_v2' AND NEW.original_record#>>'{evidence,nonce_sha256}'=nonce.return_sha256 AND NEW.original_record->>'original_caller_sha256'=NEW.original_record#>>'{evidence,caller_sha256}') IS NOT TRUE THEN RAISE EXCEPTION 'exact original nonce and retained V2 request required'; END IF;
 SELECT count(*) INTO n FROM public.capacity_vm_retirement_original_returns WHERE intent_id=NEW.retirement_request_id;
 IF n NOT IN(4,5) OR (NEW.original_record#>'{evidence,journal_sha256}'=(SELECT jsonb_agg(return_sha256 ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=NEW.retirement_request_id AND sequence>1)) IS NOT TRUE THEN RAISE EXCEPTION 'entire original prefix including optional genuine fourth required'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns r WHERE r.intent_id=NEW.retirement_request_id AND r.sequence>1 AND (r.kind=CASE r.sequence WHEN 2 THEN 'production_retirement_v2:possible_start' WHEN 3 THEN 'production_retirement_v2:quiescent' WHEN 4 THEN 'production_retirement_v2:poweroff_possible_start' WHEN 5 THEN 'production_retirement_v2:poweroff_command_returned' END AND r.original_return_record->>'journal_complete'='true' AND r.original_return_record#>>'{record,powered_off_observed}'='false') IS NOT TRUE) THEN RAISE EXCEPTION 'unlinked uncertain or extra original cannot be filtered'; END IF;
 IF NEW.original_record ? 'normal_finish_recovery' THEN
  IF NEW.original_record->>'mode'='normal_finish_recovery' THEN
   IF public.retirement_forward_normal_finish_recovery_valid(NEW.original_record,NEW.retirement_request_id) IS NOT TRUE THEN RAISE EXCEPTION 'closed successful Guest and failed native-OFF finish proof required'; END IF;
  ELSIF NEW.original_record->>'mode'='settled_absence_continuation' THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_record->>'parent_admission_id')::uuid AND stage IN('admitted','off_qualified') AND record_sha256=NEW.original_record->>'parent_admission_sha256';
   IF (parent.original_record->'normal_finish_recovery'=NEW.original_record->'normal_finish_recovery' AND parent.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND parent.retirement_request_id=NEW.retirement_request_id AND parent.original_record->'evidence'=NEW.original_record->'evidence') IS NOT TRUE THEN RAISE EXCEPTION 'settled read-only child preserves normal-finish origin proof'; END IF;
  ELSE RAISE EXCEPTION 'normal successful caller never enters an old partial mode';
  END IF;
 ELSE
 IF NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_returns c WHERE c.intent_id=NEW.retirement_request_id AND c.return_sha256=NEW.original_record->>'original_caller_sha256' AND (c.original_record->>'preflight_failed'='false') IS TRUE AND NOT(c.original_record->>'status'='200' AND c.original_record->>'body_persisted'='true' AND c.original_record->>'do_failed'='false' AND c.original_record->>'read_failed'='false' AND c.original_record->>'close_failed'='false' AND c.original_record->>'original_context_failed'='false' AND (c.original_record->>'driver_returned_at')::timestamptz<original.original_deadline)) THEN RAISE EXCEPTION 'retained failed original caller required'; END IF;
 END IF;
 IF (NEW.original_record#>'{evidence,authority_sha256}'=(SELECT jsonb_agg(v.authority_sha256 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=NEW.retirement_request_id) AND (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=NEW.retirement_request_id)=4 AND (SELECT count(*) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=NEW.retirement_request_id)=4) IS NOT TRUE THEN RAISE EXCEPTION 'four exact original authorized reads required'; END IF;
 IF NEW.stage='requested' THEN
  IF NEW.original_record->>'mode'='normal_finish_recovery' THEN
   IF ((current_row->>'lease_expires_at')::timestamptz<=clock_timestamp()
    AND current_row->>'generation'=NEW.original_record->>'generation' AND current_row->>'fencing_token'=NEW.original_record->>'fence'
    AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id'
    AND convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row
    AND public.retirement_forward_normal_finish_recovery_valid(NEW.original_record,NEW.retirement_request_id)) IS NOT TRUE THEN RAISE EXCEPTION 'exact naturally expired normal-finish request required'; END IF;
   IF EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=NEW.retirement_request_id)
    OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.integration_instance_id::text=NEW.integration_instance_id AND g.scope_checksum=NEW.scope_checksum AND g.profile_name=NEW.profile_name AND g.slot=NEW.slot AND g.generation=(NEW.original_record->>'generation')::bigint AND g.grant_record#>>'{grant,capability}'=g.grant_record#>>'{binding,destroy_capability}') THEN RAISE EXCEPTION 'normal-finish recovery never reopens DELETE authority'; END IF;
   IF NEW.original_record#>>'{normal_finish_recovery,requesting_run_id}'<>'' THEN
    IF (NEW.original_record->>'issuer'='source:normal-finish-recovery' AND public.retirement_forward_continuation_quiet(NEW.original_record || jsonb_build_object('destroy_grant_id',''),(NEW.original_record#>>'{normal_finish_recovery,requesting_run_id}')::uuid)) IS NOT TRUE THEN RAISE EXCEPTION 'exact current Source plan and quiet scope required'; END IF;
   ELSE
    IF EXISTS(SELECT 1 FROM public.workflow_runs w WHERE (w.workflow_id=(NEW.original_record#>>'{original,Request,intent,workflow_id}')::uuid OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(NEW.original_record#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
     OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(NEW.original_record#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
     OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(NEW.integration_instance_id,NEW.scope_checksum,NEW.profile_name) AND g.state IN('issued','redeemed','settled','compensating') AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL) THEN RAISE EXCEPTION 'normal-finish request requires whole current quiet scope'; END IF;
    IF NEW.original_record->>'issuer' NOT LIKE 'collaborator:%' THEN RAISE EXCEPTION 'named current operator required'; END IF;
    IF EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=NEW.namespace AND j.environment=NEW.environment AND j.domain=NEW.domain AND j.dimension=NEW.dimension AND (j.state IN('queued','started','unknown') OR j.finalization_ack_at IS NULL)) THEN RAISE EXCEPTION 'all original dispatches closed before manual normal-finish request'; END IF;
   END IF;
  ELSE
  IF NEW.original_record->>'mode'='settled_absence_continuation' THEN
   IF ((current_row->>'lease_expires_at')::timestamptz<=clock_timestamp()
    AND current_row->>'generation'=NEW.original_record->>'generation' AND current_row->>'fencing_token'=NEW.original_record->>'fence'
    AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id'
    AND current_row#>>'{retirement_forward,id}'=NEW.original_record->>'parent_admission_id' AND current_row#>>'{retirement_forward,stage}' IN('admitted','off_qualified')
    AND convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row
    AND public.retirement_forward_continuation_valid(NEW.original_record,NEW.retirement_request_id)) IS NOT TRUE THEN RAISE EXCEPTION 'exact closed owning settled Pending continuation required'; END IF;
  ELSE
  IF (NEW.original_record->>'mode'='historical' AND (current_row->>'lease_expires_at')::timestamptz<=clock_timestamp() AND (current_row->>'generation')::bigint=(NEW.original_record->>'generation')::bigint AND (current_row->>'fencing_token')::bigint=(NEW.original_record->>'fence')::bigint AND convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row) IS NOT TRUE THEN RAISE EXCEPTION 'closed historical exact CAS request required'; END IF;
  IF ((NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz>(current_row->>'lease_expires_at')::timestamptz AND (NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz>original.original_deadline AND (NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz<=clock_timestamp() AND NEW.original_record#>>'{barrier,SourceCommit}'=NEW.original_record->>'actual_core_source' AND (NEW.original_record#>>'{barrier,PID}')::bigint>0 AND length(NEW.original_record#>>'{barrier,Hostname}')>0 AND EXISTS(SELECT 1 FROM public.capacity_guest_original_retirement_contexts c WHERE c.intent_id=NEW.retirement_request_id AND (NEW.original_record#>>'{barrier,ProcessStartedAt}')::timestamptz>c.original_context_deadline)) IS NOT TRUE THEN RAISE EXCEPTION 'actual replacement Core after all original deadlines required'; END IF;
  IF NOT EXISTS(SELECT 1 FROM public.workflow_runs w JOIN public.capacity_dispatch_jobs j ON j.run_id=w.id WHERE to_jsonb(w)=convert_from(decode(NEW.original_record->>'failed_run','base64'),'UTF8')::jsonb AND w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed' AND j.returned_at IS NOT NULL AND j.finalization_ack_at IS NOT NULL AND j.envelope::jsonb#>>'{workflow,id}'=NEW.original_record#>>'{original,Request,intent,workflow_id}' AND w.result#>>'{steps,0,metadata,generation}'=NEW.original_record->>'generation' AND w.result#>>'{steps,0,metadata,fencing_token}'=NEW.original_record->>'fence' AND w.result#>>'{steps,0,metadata,lease_owner}'=current_row->>'lease_owner') THEN RAISE EXCEPTION 'historical admission needs exact closed failed original run'; END IF;
  IF coalesce(NEW.original_record->>'parent_admission_id','')<>'' THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_record->>'parent_admission_id')::uuid AND record_sha256=NEW.original_record->>'parent_admission_sha256' AND stage IN('admitted','off_qualified');
   IF (parent.retirement_request_id=NEW.retirement_request_id AND parent.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND current_row#>>'{retirement_forward,id}'=parent.id::text AND current_row#>>'{retirement_forward,stage}'=parent.stage AND parent.original_record->'evidence'=NEW.original_record->'evidence') IS NOT TRUE THEN RAISE EXCEPTION 'historical continuation preserves exact parent and root'; END IF;
   IF EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=NEW.retirement_request_id) AND NOT EXISTS(
    SELECT 1 FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id
     JOIN public.capacity_guest_retirement_forwards a ON a.id=(b.original_eligibility_record->>'admission_id')::uuid AND a.stage='admitted'
    WHERE b.intent_id=NEW.retirement_request_id AND b.destroy_grant_id::text=NEW.original_record->>'destroy_grant_id'
     AND b.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1'
     AND b.original_eligibility_record->>'admission_sha256'=a.record_sha256
     AND a.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND a.original_record->'evidence'=NEW.original_record->'evidence'
     AND g.state IN('settled','confirmed') AND (g.grant_record#>>'{settlement,outcome}'='accepted' AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true') IS TRUE
   ) THEN RAISE EXCEPTION 'only a known accepted owning DELETE permits read-only continuation'; END IF;
  ELSIF coalesce(NEW.original_record->>'destroy_grant_id','')<>'' THEN RAISE EXCEPTION 'new root cannot adopt an unrelated destroy';
  END IF;
  END IF;
  END IF;
 ELSIF NEW.stage='admitted' THEN
  IF NEW.original_record->>'mode'='settled_absence_continuation' AND public.retirement_forward_continuation_quiet(NEW.original_record,(NEW.original_record->>'run_id')::uuid) IS NOT TRUE THEN RAISE EXCEPTION 'new claimant requires exact current dispatch quiet'; END IF;
  IF NEW.original_record->>'mode' IN('historical','settled_absence_continuation','normal_finish_recovery') THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=NEW.id AND stage='requested';
   IF ((NEW.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id'])=(parent.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id']) AND current_row#>>'{retirement_forward,id}'=NEW.id::text AND current_row#>>'{retirement_forward,stage}'='requested' AND (NEW.original_record->>'fence')::bigint=(current_row->>'fencing_token')::bigint+1 AND (current_row->>'lease_expires_at')::timestamptz<=clock_timestamp()) IS NOT TRUE THEN RAISE EXCEPTION 'new fenced claim preserves requested originals'; END IF;
  ELSIF (convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row AND (current_row->>'lease_expires_at')::timestamptz>clock_timestamp() AND (current_row->>'fencing_token')::bigint=(NEW.original_record->>'fence')::bigint AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id' AND NOT(current_row ? 'retirement_forward')) IS NOT TRUE THEN RAISE EXCEPTION 'same original live lease required'; END IF;
 ELSE
  SELECT * INTO STRICT admitted FROM public.capacity_guest_retirement_forwards WHERE id=NEW.id AND stage='admitted';
  IF (current_row#>>'{retirement_forward,id}'=NEW.id::text AND current_row#>>'{retirement_forward,stage}' IN('admitted','off_qualified') AND current_row->>'generation'=admitted.original_record->>'generation' AND current_row->>'fencing_token'=admitted.original_record->>'fence' AND current_row->>'lease_owner'=admitted.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=admitted.original_record->>'executor_id' AND (current_row->>'lease_expires_at')::timestamptz>clock_timestamp()) IS NOT TRUE THEN RAISE EXCEPTION 'qualification belongs to current live exact claimant'; END IF;
  IF ((NEW.original_record-ARRAY['stage','recorded_at','admission_sha256','native_off_read_id','native_off_sha256','destroy_grant_id','native_absence_sha256','terminal_intent_sha256','terminal_intent_wire'])=(admitted.original_record-ARRAY['stage','recorded_at','admission_sha256','native_off_read_id','native_off_sha256','destroy_grant_id','native_absence_sha256','terminal_intent_sha256','terminal_intent_wire']) AND NEW.original_record->>'admission_sha256'=admitted.record_sha256 AND NEW.original_record->'evidence'=admitted.original_record->'evidence' AND NEW.original_record->>'prefix_sha256'=admitted.original_record->>'prefix_sha256' AND NEW.original_record->'original'=admitted.original_record->'original' AND NEW.original_record->>'original_intent_sha256'=admitted.original_record->>'original_intent_sha256' AND (NEW.original_record->>'fence')::bigint=(admitted.original_record->>'fence')::bigint) IS NOT TRUE THEN RAISE EXCEPTION 'qualified stages preserve exact admitted frame'; END IF;
  IF NEW.stage='off_qualified' AND NEW.original_record->>'mode'='settled_absence_continuation' THEN RAISE EXCEPTION 'settled absence continuation cannot authorize OFF'; END IF;
  IF NEW.stage='off_qualified' THEN
   SELECT * INTO STRICT observed FROM public.capacity_guest_retirement_forward_reads WHERE id=(NEW.original_record->>'native_off_read_id')::uuid AND admission_id=NEW.id AND kind='off' AND stage='returned';
   IF (observed.record_sha256=NEW.original_record->>'native_off_sha256' AND observed.original_record->>'status'='observed' AND observed.original_record->>'call_failed'='false' AND observed.original_record->>'original_context_failed'='false' AND observed.original_record#>>'{plan,server,status}' IN('off','stopped')) IS NOT TRUE THEN RAISE EXCEPTION 'actual complete exact native OFF required'; END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings b JOIN public.capacity_mutation_grants g ON g.id=b.destroy_grant_id JOIN public.capacity_guest_retirement_forwards a ON a.id=(b.original_eligibility_record->>'admission_id')::uuid AND a.stage='admitted' WHERE b.intent_id=NEW.retirement_request_id AND b.destroy_grant_id::text=NEW.original_record->>'destroy_grant_id' AND b.original_eligibility_record->>'admission_sha256'=a.record_sha256 AND a.original_record->>'root_admission_id'=NEW.original_record->>'root_admission_id' AND a.original_record->'evidence'=NEW.original_record->'evidence' AND b.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1' AND g.state='confirmed') THEN RAISE EXCEPTION 'own confirmed exact destroy required for terminal'; END IF;
  IF NEW.stage='terminal' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.admission_id=NEW.id AND v.kind='absence' AND v.stage='returned' AND v.record_sha256=NEW.original_record->>'native_absence_sha256' AND v.original_record#>>'{read,destroy_grant_id}'=NEW.original_record->>'destroy_grant_id' AND v.original_record->>'status'='observed' AND v.original_record->>'call_failed'='false' AND v.original_record->>'original_context_failed'='false') THEN RAISE EXCEPTION 'terminal needs its own retained fresh absence'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP FUNCTION IF EXISTS public.retirement_forward_pre_destroy_recovery_valid103(jsonb,uuid);
DROP FUNCTION IF EXISTS public.retirement_forward_pre_destroy_authority_absent103(uuid);
