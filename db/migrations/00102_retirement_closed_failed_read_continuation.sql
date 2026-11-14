-- +goose Up
-- A new finite read/Confirm owner may follow a CLOSED contextual read failure.
-- The absolute latest failure, accepted DELETE, old ACKs and clocks stay exact.
-- +goose StatementBegin
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation102') THEN
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation96') THEN RAISE EXCEPTION 'exact prior continuation96 constraint required'; END IF;
  ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT retirement_forward_continuation96;
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_continuation102 CHECK((CASE WHEN original_record->>'mode'='settled_absence_continuation' THEN jsonb_typeof(original_record->'continuation')='object' AND original_record#>>'{continuation,schema}' IN('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1','original_settled_absence_closed_failed_read_continuation_v1') ELSE NOT(original_record ? 'continuation') END) IS TRUE);
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_closed_failed_read102_pair_valid(prepared_row public.capacity_guest_retirement_forward_reads, returned_row public.capacity_guest_retirement_forward_reads) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE rd jsonb=prepared_row.original_record; rv jsonb=returned_row.original_record;
 wire_times text[]; clock_ns numeric[]=ARRAY[0::numeric,0::numeric,0::numeric,0::numeric]; clock_wire text; fraction text; ordinal integer;
 tuple_value jsonb=rd->'tuple'; canonical_tuple text; canonical_read text; canonical_return text; canonical_base text;
BEGIN
 IF (prepared_row.stage='prepared' AND returned_row.stage='returned'
  AND prepared_row.id=returned_row.id AND prepared_row.admission_id=returned_row.admission_id
  AND prepared_row.retirement_request_id=returned_row.retirement_request_id
  AND prepared_row.kind='absence' AND returned_row.kind='absence'
  AND octet_length(prepared_row.original_wire) BETWEEN 1 AND 2097152 AND octet_length(returned_row.original_wire) BETWEEN 1 AND 2097152
  AND prepared_row.record_sha256=encode(digest(prepared_row.original_wire,'sha256'),'hex')
  AND returned_row.record_sha256=encode(digest(returned_row.original_wire,'sha256'),'hex')
  AND rd=convert_from(prepared_row.original_wire,'UTF8')::jsonb AND rv=convert_from(returned_row.original_wire,'UTF8')::jsonb
  AND jsonb_typeof(rd)='object' AND (SELECT count(*) FROM jsonb_object_keys(rd))=14
  AND (SELECT count(*) FROM json_object_keys(convert_from(prepared_row.original_wire,'UTF8')::json))=14
  AND rd-ARRAY['schema','read_id','admission_id','retirement_request_id','kind','admission_sha256','prefix_sha256','original_caller_sha256','mutation_binding_sha256','adapter_source_commit','tuple','destroy_grant_id','issued_at_core','original_deadline_core']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(rd) read_field WHERE read_field.key<>'tuple' AND jsonb_typeof(read_field.value)<>'string')
  AND jsonb_typeof(rd->'tuple')='object'
  AND (SELECT count(*) FROM jsonb_object_keys(tuple_value))=11
  AND (SELECT count(*) FROM json_object_keys((convert_from(prepared_row.original_wire,'UTF8')::json)->'tuple'))=11
  AND tuple_value-ARRAY['provider','integration_instance_id','instance_checksum','integration_type_id','type_checksum','scope_checksum','profile_checksum','profile','slot','resource_id','resource_created_at']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(tuple_value) tuple_field WHERE tuple_field.key<>'slot' AND jsonb_typeof(tuple_field.value)<>'string')
  AND jsonb_typeof(tuple_value->'slot')='number'
  AND (((convert_from(prepared_row.original_wire,'UTF8')::json)->'tuple')->>'slot') ~ '^-?(0|[1-9][0-9]*)$'
  AND (tuple_value->>'slot')::numeric BETWEEN -9223372036854775808 AND 9223372036854775807
  AND rd->>'schema'='original_core_guest_retirement_forward_read_v1' AND rd->>'kind'='absence'
  AND rd->>'read_id'=prepared_row.id::text AND rd->>'admission_id'=prepared_row.admission_id::text
  AND rd->>'retirement_request_id'=prepared_row.retirement_request_id::text
  AND prepared_row.id<>'00000000-0000-0000-0000-000000000000'::uuid
  AND prepared_row.admission_id<>'00000000-0000-0000-0000-000000000000'::uuid
  AND prepared_row.retirement_request_id<>'00000000-0000-0000-0000-000000000000'::uuid
  AND rd->>'admission_sha256' ~ '^[0-9a-f]{64}$' AND rd->>'prefix_sha256' ~ '^[0-9a-f]{64}$'
  AND rd->>'original_caller_sha256' ~ '^[0-9a-f]{64}$' AND rd->>'mutation_binding_sha256' ~ '^[0-9a-f]{64}$'
  AND rd->>'adapter_source_commit' ~ '^[0-9a-f]{40}$' AND rd->>'destroy_grant_id' ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  AND rd->>'destroy_grant_id'<>'00000000-0000-0000-0000-000000000000'
  AND jsonb_typeof(rv)='object' AND (SELECT count(*) FROM jsonb_object_keys(rv))=7
  AND (SELECT count(*) FROM json_object_keys(convert_from(returned_row.original_wire,'UTF8')::json))=7
  AND (SELECT count(*) FROM json_object_keys((convert_from(returned_row.original_wire,'UTF8')::json)->'read'))=14
  AND (SELECT count(*) FROM json_object_keys(((convert_from(returned_row.original_wire,'UTF8')::json)->'read')->'tuple'))=11
  AND ((((convert_from(returned_row.original_wire,'UTF8')::json)->'read')->'tuple')->>'slot') ~ '^-?(0|[1-9][0-9]*)$'
  AND rv-ARRAY['schema','read','status','started_at_core','original_returned_at_core','call_failed','original_context_failed']='{}'::jsonb
  AND rv->'read'=rd AND rv->>'schema'='original_core_guest_retirement_forward_read_return_v1'
  AND rv->'status'='""'::jsonb AND rv->'call_failed'='true'::jsonb AND rv->'original_context_failed'='true'::jsonb
  AND jsonb_typeof(rv->'schema')='string' AND jsonb_typeof(rv->'started_at_core')='string' AND jsonb_typeof(rv->'original_returned_at_core')='string') IS NOT TRUE THEN RETURN false; END IF;
 -- Only these three CLOSED producer structs are reconstructed, in Go field
 -- order. This is not a general JSON canonicalizer or an input normalizer.
 canonical_tuple=
  '{"provider":'||(tuple_value->'provider')::text
  ||',"integration_instance_id":'||(tuple_value->'integration_instance_id')::text
  ||',"instance_checksum":'||(tuple_value->'instance_checksum')::text
  ||',"integration_type_id":'||(tuple_value->'integration_type_id')::text
  ||',"type_checksum":'||(tuple_value->'type_checksum')::text
  ||',"scope_checksum":'||(tuple_value->'scope_checksum')::text
  ||',"profile_checksum":'||(tuple_value->'profile_checksum')::text
  ||',"profile":'||(tuple_value->'profile')::text
  ||',"slot":'||(tuple_value->'slot')::text
  ||',"resource_id":'||(tuple_value->'resource_id')::text
  ||',"resource_created_at":'||(tuple_value->'resource_created_at')::text||'}';
 canonical_read=
  '{"schema":'||(rd->'schema')::text
  ||',"read_id":'||(rd->'read_id')::text
  ||',"admission_id":'||(rd->'admission_id')::text
  ||',"retirement_request_id":'||(rd->'retirement_request_id')::text
  ||',"kind":'||(rd->'kind')::text
  ||',"admission_sha256":'||(rd->'admission_sha256')::text
  ||',"prefix_sha256":'||(rd->'prefix_sha256')::text
  ||',"original_caller_sha256":'||(rd->'original_caller_sha256')::text
  ||',"mutation_binding_sha256":'||(rd->'mutation_binding_sha256')::text
  ||',"adapter_source_commit":'||(rd->'adapter_source_commit')::text
  ||',"tuple":'||canonical_tuple
  ||',"destroy_grant_id":'||(rd->'destroy_grant_id')::text
  ||',"issued_at_core":'||(rd->'issued_at_core')::text
  ||',"original_deadline_core":'||(rd->'original_deadline_core')::text||'}';
 canonical_return=
  '{"schema":'||(rv->'schema')::text
  ||',"read":'||canonical_read
  ||',"status":'||(rv->'status')::text
  ||',"started_at_core":'||(rv->'started_at_core')::text
  ||',"original_returned_at_core":'||(rv->'original_returned_at_core')::text
  ||',"call_failed":'||(rv->'call_failed')::text
  ||',"original_context_failed":'||(rv->'original_context_failed')::text||'}';
 -- encoding/json's default escapes apply to values, never to structural keys.
 canonical_read=replace(replace(replace(replace(replace(canonical_read,'&',chr(92)||'u0026'),'<',chr(92)||'u003c'),'>',chr(92)||'u003e'),chr(8232),chr(92)||'u2028'),chr(8233),chr(92)||'u2029');
 canonical_return=replace(replace(replace(replace(replace(canonical_return,'&',chr(92)||'u0026'),'<',chr(92)||'u003c'),'>',chr(92)||'u003e'),chr(8232),chr(92)||'u2028'),chr(8233),chr(92)||'u2029');
 IF (convert_to(canonical_read,'UTF8')=prepared_row.original_wire AND convert_to(canonical_return,'UTF8')=returned_row.original_wire) IS NOT TRUE THEN RETURN false; END IF;
 -- Core emits UTC RFC3339Nano. Do not round a 1ns deadline boundary to PG's
 -- microsecond timestamp precision. Parse the whole second and fraction apart.
 wire_times=ARRAY[rd->>'issued_at_core',rd->>'original_deadline_core',rv->>'started_at_core',rv->>'original_returned_at_core'];
 FOR ordinal IN 1..4 LOOP
  clock_wire=wire_times[ordinal];
  IF clock_wire !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{0,8}[1-9])?Z$' THEN RETURN false; END IF;
  canonical_base=regexp_replace(clock_wire,'\.[0-9]{1,9}Z$','Z');
  IF to_char(canonical_base::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"')<>canonical_base THEN RETURN false; END IF;
  fraction=substring(clock_wire FROM '\.([0-9]{1,9})Z$');
  clock_ns[ordinal]=extract(epoch FROM regexp_replace(clock_wire,'\.[0-9]{1,9}Z$','Z')::timestamptz)*1000000000
   +rpad(coalesce(fraction,''),9,'0')::numeric;
 END LOOP;
 RETURN (clock_ns[1]>extract(epoch FROM '0001-01-01T00:00:00Z'::timestamptz)*1000000000
  AND clock_ns[2]>clock_ns[1] AND clock_ns[2]<=clock_ns[1]+5000000000
  AND clock_ns[3]>=clock_ns[1] AND clock_ns[4]>=clock_ns[3] AND clock_ns[4]>=clock_ns[2]
  AND isfinite(prepared_row.recorded_at) AND isfinite(returned_row.recorded_at)
  AND prepared_row.recorded_at>'0001-01-01T00:00:00Z'::timestamptz AND returned_row.recorded_at>'0001-01-01T00:00:00Z'::timestamptz
  AND returned_row.recorded_at>=prepared_row.recorded_at
  AND extract(epoch FROM returned_row.recorded_at)*1000000000>=clock_ns[4]) IS TRUE;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_closed_failed_read102_valid(r jsonb, retirement uuid, allow_pre_read boolean) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE p jsonb=r->'continuation'; closed_read jsonb=p->'closed_failed_read';
 parent public.capacity_guest_retirement_forwards; admitted public.capacity_guest_retirement_forwards;
 b public.capacity_vm_retirement_delete_bindings; g public.capacity_mutation_grants;
 v public.capacity_guest_retirement_forward_reads; prepared public.capacity_guest_retirement_forward_reads;
 w public.workflow_runs; j public.capacity_dispatch_jobs; result jsonb;
 requested public.capacity_guest_retirement_forwards; origin public.capacity_guest_retirement_forwards;
 origin_id uuid; origin_count integer; owner_intent jsonb; rd jsonb; binding_sha text; adapter_source text; deadline_ns numeric;
BEGIN
 IF (allow_pre_read IS NOT NULL AND r->>'mode'='settled_absence_continuation' AND r->>'stage'='requested'
  AND jsonb_typeof(p)='object' AND (SELECT count(*) FROM jsonb_object_keys(p))=11
  AND p-ARRAY['schema','requesting_run_id','failed_run_id','failed_run_sha256','dispatch_id','dispatch_sha256','destroy_grant_sha256','delete_eligibility_sha256','pending_read_id','pending_read_sha256','closed_failed_read']='{}'::jsonb
  AND p->>'schema'='original_settled_absence_closed_failed_read_continuation_v1'
  AND p->'pending_read_id'='""'::jsonb AND p->'pending_read_sha256'='""'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(p) proof_field WHERE proof_field.key<>'closed_failed_read' AND jsonb_typeof(proof_field.value)<>'string')
  AND p->>'requesting_run_id' ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  AND p->>'failed_run_id' ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  AND p->>'dispatch_id' ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  AND p->>'requesting_run_id'<>'00000000-0000-0000-0000-000000000000'
  AND p->>'failed_run_id'<>'00000000-0000-0000-0000-000000000000'
  AND p->>'dispatch_id'<>'00000000-0000-0000-0000-000000000000'
  AND p->>'failed_run_sha256' ~ '^[0-9a-f]{64}$' AND p->>'dispatch_sha256' ~ '^[0-9a-f]{64}$'
  AND p->>'destroy_grant_sha256' ~ '^[0-9a-f]{64}$' AND p->>'delete_eligibility_sha256' ~ '^[0-9a-f]{64}$'
  AND jsonb_typeof(closed_read)='object' AND (SELECT count(*) FROM jsonb_object_keys(closed_read))=3
  AND closed_read-ARRAY['read_id','prepared_sha256','returned_sha256']='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(closed_read) closed_field WHERE jsonb_typeof(closed_field.value)<>'string')
  AND closed_read->>'read_id' ~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
  AND closed_read->>'prepared_sha256' ~ '^[0-9a-f]{64}$' AND closed_read->>'returned_sha256' ~ '^[0-9a-f]{64}$'
  AND r->>'issuer'='source:settled-absence-continuation' AND r->>'run_id'=''
  AND (r#>>'{barrier,ProcessStartedAt}')::timestamptz='0001-01-01T00:00:00Z'::timestamptz
  AND r#>>'{barrier,SourceCommit}'='' AND r#>>'{barrier,Hostname}'='' AND r#>>'{barrier,PID}'='0') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO parent FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'parent_admission_id')::uuid AND record_sha256=r->>'parent_admission_sha256' AND stage IN('admitted','off_qualified');
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO STRICT admitted FROM public.capacity_guest_retirement_forwards WHERE id=parent.id AND stage='admitted';
 IF (parent.retirement_request_id=retirement AND parent.original_record->>'root_admission_id'=r->>'root_admission_id' AND parent.original_record->'evidence'=r->'evidence'
  AND parent.original_record->>'generation'=r->>'generation' AND parent.original_record->>'fence'=r->>'fence'
  AND parent.original_record->>'lease_owner'=r->>'lease_owner' AND parent.original_record->>'executor_id'=r->>'executor_id'
  AND admitted.original_record->>'run_id'=p->>'failed_run_id' AND public.retirement_forward_continuation_quiet(r,(p->>'requesting_run_id')::uuid)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO w FROM public.workflow_runs WHERE id=(p->>'failed_run_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE id=(p->>'dispatch_id')::uuid AND run_id=w.id;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (to_jsonb(w)=convert_from(decode(r->>'failed_run','base64'),'UTF8')::jsonb
  AND encode(digest(decode(r->>'failed_run','base64'),'sha256'),'hex')=p->>'failed_run_sha256'
  AND encode(digest(to_jsonb(j)::text,'sha256'),'hex')=p->>'dispatch_sha256'
  AND w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed'
  AND j.returned_at IS NOT NULL AND j.finalization_ack_at>=j.returned_at AND (SELECT count(*) FROM public.capacity_dispatch_jobs z WHERE z.run_id=j.run_id)=1
  AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}'
  AND w.result#>>'{steps,0,metadata,generation}'=r->>'generation' AND w.result#>>'{steps,0,metadata,fencing_token}'=r->>'fence'
  AND w.result#>>'{steps,0,metadata,lease_owner}'=r->>'lease_owner') IS NOT TRUE THEN RETURN false; END IF;
 result=w.result;
 IF (result->>'status'='failed' AND jsonb_array_length(result->'steps')=7
  AND (SELECT count(DISTINCT step->>'id') FROM jsonb_array_elements(result->'steps') step)=7
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(result->'steps') step WHERE (CASE step->>'id'
   WHEN 'plan-original-guest' THEN step->>'status'='succeeded'
   WHEN 'retire-original-guest' THEN step->>'status'='succeeded' AND step#>>'{metadata,retirement_forward_id}'=parent.id::text AND step#>>'{metadata,request_id}'=retirement::text
   WHEN 'finish-original-retirement' THEN step->>'status'='failed'
   WHEN 'provision-original-notify' THEN step->>'status'='skipped'
   WHEN 'complete-original-provision' THEN step->>'status'='skipped'
   WHEN 'refresh-original-membership' THEN step->>'status'='skipped'
   WHEN 'complete-original-retirement' THEN step->>'status'='skipped' ELSE false END) IS NOT TRUE)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO b FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=retirement AND destroy_grant_id::text=r->>'destroy_grant_id' AND eligibility_sha256=p->>'delete_eligibility_sha256';
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT known.* INTO g FROM public.capacity_mutation_grants known WHERE known.id=b.destroy_grant_id AND known.state='settled' AND known.original_disposition_id IS NULL AND known.failed_original_disposition_id IS NULL AND known.native_denied_disposition_id IS NULL AND known.enrolled_failed_disposition_id IS NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (encode(digest(g.grant_record::text,'sha256'),'hex')=p->>'destroy_grant_sha256'
  AND b.eligibility_sha256=encode(digest(b.original_wire,'sha256'),'hex') AND b.original_eligibility_record=convert_from(b.original_wire,'UTF8')::jsonb
  AND b.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1'
  AND g.grant_record#>>'{grant,state}'='settled' AND g.grant_record#>>'{settlement,outcome}'='accepted'
  AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true'
  AND coalesce(g.grant_record#>>'{grant,compensation_of}','')=''
  AND EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards authority WHERE authority.id=(b.original_eligibility_record->>'admission_id')::uuid AND authority.stage='admitted' AND authority.record_sha256=b.original_eligibility_record->>'admission_sha256' AND authority.original_record->>'root_admission_id'=r->>'root_admission_id' AND authority.original_record->'evidence'=r->'evidence'
   AND g.generation=(authority.original_record->>'generation')::bigint AND g.grant_record->>'fencing_token'=authority.original_record->>'fence'
   AND g.grant_record->>'lease_owner'=authority.original_record->>'lease_owner' AND g.grant_record->>'executor_id'=authority.original_record->>'executor_id'
   AND g.integration_instance_id::text=authority.integration_instance_id AND g.scope_checksum=authority.scope_checksum AND g.profile_name=authority.profile_name AND g.slot=authority.slot)) IS NOT TRUE THEN RETURN false; END IF;
 IF (isfinite(j.returned_at) AND isfinite(j.finalization_ack_at) AND isfinite(w.finished_at)
  AND j.finalization_ack_at<=clock_timestamp()) IS NOT TRUE THEN RETURN false; END IF;
 -- Every historical owner remains an immutable whole frame.
 IF (parent.record_sha256=encode(digest(parent.original_wire,'sha256'),'hex')
  AND parent.original_record=convert_from(parent.original_wire,'UTF8')::jsonb
  AND admitted.record_sha256=encode(digest(admitted.original_wire,'sha256'),'hex')
  AND admitted.original_record=convert_from(admitted.original_wire,'UTF8')::jsonb
  AND parent.original_record->'original'=r->'original' AND parent.original_record->>'prefix_sha256'=r->>'prefix_sha256'
  AND parent.original_record->>'original_caller_sha256'=r->>'original_caller_sha256') IS NOT TRUE THEN RETURN false; END IF;
 owner_intent=convert_from(decode(r->>'original_intent_wire','base64'),'UTF8')::jsonb;
 IF (encode(digest(decode(r->>'original_intent_wire','base64'),'sha256'),'hex')=r->>'original_intent_sha256'
  AND isfinite((owner_intent->>'lease_expires_at')::timestamptz) AND (owner_intent->>'lease_expires_at')::timestamptz<=clock_timestamp()
  AND owner_intent#>>'{retirement_forward,id}'=parent.id::text
  AND owner_intent->>'generation'=parent.original_record->>'generation'
  AND owner_intent->>'fencing_token'=parent.original_record->>'fence'
  AND owner_intent->>'lease_owner'=parent.original_record->>'lease_owner'
  AND owner_intent->>'lease_executor_id'=parent.original_record->>'executor_id'
  AND EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents original_epoch WHERE original_epoch.id=retirement AND isfinite(original_epoch.original_deadline) AND original_epoch.original_deadline<=clock_timestamp())
  AND EXISTS(SELECT 1 FROM public.capacity_guest_original_retirement_contexts original_context WHERE original_context.intent_id=retirement AND isfinite(original_context.original_context_deadline) AND original_context.original_context_deadline<=clock_timestamp())) IS NOT TRUE THEN RETURN false; END IF;
 -- Never search backward for a Pending or a valid read. Select absolute latest.
 IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads open_read WHERE open_read.retirement_request_id=retirement AND open_read.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads closed_return WHERE closed_return.id=open_read.id AND closed_return.stage='returned')) THEN RETURN false; END IF;
 SELECT * INTO v FROM public.capacity_guest_retirement_forward_reads WHERE retirement_request_id=retirement AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO STRICT prepared FROM public.capacity_guest_retirement_forward_reads WHERE id=v.id AND stage='prepared';
 IF (v.id::text=closed_read->>'read_id' AND v.record_sha256=closed_read->>'returned_sha256'
  AND prepared.record_sha256=closed_read->>'prepared_sha256'
  AND public.retirement_forward_closed_failed_read102_pair_valid(prepared,v)) IS NOT TRUE THEN RETURN false; END IF;
 IF v.admission_id=parent.id THEN
  rd=prepared.original_record;
  deadline_ns=extract(epoch FROM regexp_replace(rd->>'original_deadline_core','\.[0-9]{1,9}Z$','Z')::timestamptz)*1000000000
   +rpad(coalesce(substring(rd->>'original_deadline_core' FROM '\.([0-9]{1,9})Z$'),''),9,'0')::numeric;
  -- The accepted DELETE's genuine original OFF qualification pins the same
  -- creator/binding hash. Do not invent a JSONB-text hash for a Go wire hash.
  SELECT off_prepared.original_record->>'mutation_binding_sha256',off_prepared.original_record->>'adapter_source_commit' INTO STRICT binding_sha,adapter_source
   FROM public.capacity_guest_retirement_forwards authority
   JOIN public.capacity_guest_retirement_forwards qualified ON qualified.id=authority.id AND qualified.stage='off_qualified'
   JOIN public.capacity_guest_retirement_forward_reads off_return ON off_return.id=(qualified.original_record->>'native_off_read_id')::uuid AND off_return.stage='returned'
   JOIN public.capacity_guest_retirement_forward_reads off_prepared ON off_prepared.id=off_return.id AND off_prepared.stage='prepared'
   WHERE authority.id=(b.original_eligibility_record->>'admission_id')::uuid AND authority.stage='admitted'
    AND authority.record_sha256=b.original_eligibility_record->>'admission_sha256'
    AND qualified.original_record->>'admission_sha256'=authority.record_sha256
    AND off_return.record_sha256=qualified.original_record->>'native_off_sha256'
    AND off_return.record_sha256=encode(digest(off_return.original_wire,'sha256'),'hex')
    AND off_return.original_record=convert_from(off_return.original_wire,'UTF8')::jsonb
    AND off_prepared.record_sha256=encode(digest(off_prepared.original_wire,'sha256'),'hex')
    AND off_prepared.original_record=convert_from(off_prepared.original_wire,'UTF8')::jsonb
    AND off_return.original_record->'read'=off_prepared.original_record;
  RETURN (rd->>'admission_sha256'=admitted.record_sha256 AND rd->>'prefix_sha256'=r->>'prefix_sha256'
   AND rd->>'original_caller_sha256'=r->>'original_caller_sha256'
   AND rd->'tuple'=r#>'{original,Request,intent,tuple}' AND rd->>'destroy_grant_id'=g.id::text
   AND rd->>'adapter_source_commit'=adapter_source
   AND rd->>'mutation_binding_sha256'=binding_sha
   AND deadline_ns<=extract(epoch FROM (owner_intent->>'lease_expires_at')::timestamptz)*1000000000
   AND prepared.recorded_at>=admitted.recorded_at AND v.recorded_at<=j.returned_at
   AND (v.original_record->>'original_returned_at_core')::timestamptz<=j.returned_at) IS TRUE;
 END IF;
 -- A failed zero-own-read child may retain exactly this failure anchor. The
 -- unique direct origin below is revalidated ONCE with pre-read disabled.
 IF (allow_pre_read AND parent.stage='admitted' AND parent.original_record->>'mode'='settled_absence_continuation'
  AND parent.original_record#>>'{continuation,schema}'='original_settled_absence_closed_failed_read_continuation_v1'
  AND parent.original_record#>'{continuation,closed_failed_read}'=closed_read
  AND parent.original_record#>'{continuation,pending_read_id}'='""'::jsonb AND parent.original_record#>'{continuation,pending_read_sha256}'='""'::jsonb
  AND parent.original_record#>>'{continuation,destroy_grant_sha256}'=p->>'destroy_grant_sha256'
  AND parent.original_record#>>'{continuation,delete_eligibility_sha256}'=p->>'delete_eligibility_sha256'
  AND parent.original_record->>'destroy_grant_id'=g.id::text
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads own_read WHERE own_read.admission_id=parent.id)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO STRICT requested FROM public.capacity_guest_retirement_forwards WHERE id=parent.id AND stage='requested';
 IF (requested.record_sha256=encode(digest(requested.original_wire,'sha256'),'hex')
  AND requested.original_record=convert_from(requested.original_wire,'UTF8')::jsonb
  AND requested.retirement_request_id=retirement AND requested.recorded_at<=admitted.recorded_at
  AND (requested.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id'])=(parent.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id'])) IS NOT TRUE THEN RETURN false; END IF;
 SELECT count(*),min(origin_frame.id::text)::uuid INTO origin_count,origin_id FROM public.capacity_guest_retirement_forwards origin_frame
  WHERE origin_frame.retirement_request_id=retirement AND origin_frame.stage='requested'
   AND origin_frame.original_record->>'mode'='settled_absence_continuation'
   AND origin_frame.original_record#>>'{continuation,schema}'='original_settled_absence_closed_failed_read_continuation_v1'
   AND origin_frame.original_record#>'{continuation,closed_failed_read}'=closed_read
   AND origin_frame.original_record->>'parent_admission_id'=v.admission_id::text
   AND origin_frame.original_record->>'root_admission_id'=r->>'root_admission_id';
 IF origin_count<>1 THEN RETURN false; END IF;
 SELECT * INTO STRICT origin FROM public.capacity_guest_retirement_forwards WHERE id=origin_id AND stage='requested';
 IF (origin.record_sha256=encode(digest(origin.original_wire,'sha256'),'hex')
  AND origin.original_record=convert_from(origin.original_wire,'UTF8')::jsonb
  AND origin.original_record->>'destroy_grant_id'=g.id::text AND origin.original_record->'evidence'=r->'evidence'
  AND v.recorded_at<=origin.recorded_at AND origin.recorded_at<=admitted.recorded_at) IS NOT TRUE THEN RETURN false; END IF;
 RETURN public.retirement_forward_closed_failed_read102_valid(jsonb_set(origin.original_record,'{continuation,requesting_run_id}',to_jsonb(p->>'requesting_run_id')),retirement,false) IS TRUE;
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_valid(r jsonb, retirement uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE p jsonb=r->'continuation'; parent public.capacity_guest_retirement_forwards;
 admitted public.capacity_guest_retirement_forwards; b public.capacity_vm_retirement_delete_bindings;
 g public.capacity_mutation_grants; v public.capacity_guest_retirement_forward_reads;
 prepared public.capacity_guest_retirement_forward_reads; w public.workflow_runs; j public.capacity_dispatch_jobs;
 anchor public.capacity_guest_retirement_forwards; requested public.capacity_guest_retirement_forwards; classic public.capacity_guest_retirement_forwards; classic_id uuid;
 receipt jsonb; o jsonb; rd jsonb; result jsonb; holds jsonb; observer jsonb; a jsonb; state text; absent boolean; n integer;
BEGIN
 IF p->>'schema'='original_settled_absence_closed_failed_read_continuation_v1' THEN
  RETURN public.retirement_forward_closed_failed_read102_valid(r,retirement,true) IS TRUE;
 END IF;
 IF (jsonb_typeof(p)='object' AND (SELECT count(*) FROM jsonb_object_keys(p))=10 AND p->>'schema' IN('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1')
  AND p-ARRAY['schema','requesting_run_id','failed_run_id','failed_run_sha256','dispatch_id','dispatch_sha256','destroy_grant_sha256','delete_eligibility_sha256','pending_read_id','pending_read_sha256']='{}'::jsonb
  AND p->>'failed_run_id' ~ '^[0-9a-f-]{36}$' AND p->>'requesting_run_id' ~ '^[0-9a-f-]{36}$'
  AND p->>'failed_run_sha256' ~ '^[0-9a-f]{64}$' AND p->>'dispatch_sha256' ~ '^[0-9a-f]{64}$'
  AND p->>'destroy_grant_sha256' ~ '^[0-9a-f]{64}$' AND p->>'delete_eligibility_sha256' ~ '^[0-9a-f]{64}$'
  AND p->>'pending_read_sha256' ~ '^[0-9a-f]{64}$'
  AND r->>'issuer'='source:settled-absence-continuation' AND r->>'run_id'=''
  AND (r#>>'{barrier,ProcessStartedAt}')::timestamptz='0001-01-01T00:00:00Z'::timestamptz
  AND r#>>'{barrier,SourceCommit}'='' AND r#>>'{barrier,Hostname}'='' AND r#>>'{barrier,PID}'='0') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO parent FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'parent_admission_id')::uuid AND record_sha256=r->>'parent_admission_sha256' AND stage IN('admitted','off_qualified');
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO STRICT admitted FROM public.capacity_guest_retirement_forwards WHERE id=parent.id AND stage='admitted';
 IF (parent.retirement_request_id=retirement AND parent.original_record->>'root_admission_id'=r->>'root_admission_id' AND parent.original_record->'evidence'=r->'evidence'
  AND parent.original_record->>'generation'=r->>'generation' AND parent.original_record->>'fence'=r->>'fence'
  AND parent.original_record->>'lease_owner'=r->>'lease_owner' AND parent.original_record->>'executor_id'=r->>'executor_id'
  AND admitted.original_record->>'run_id'=p->>'failed_run_id' AND public.retirement_forward_continuation_quiet(r,(p->>'requesting_run_id')::uuid)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO w FROM public.workflow_runs WHERE id=(p->>'failed_run_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE id=(p->>'dispatch_id')::uuid AND run_id=w.id;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (to_jsonb(w)=convert_from(decode(r->>'failed_run','base64'),'UTF8')::jsonb
  AND encode(digest(decode(r->>'failed_run','base64'),'sha256'),'hex')=p->>'failed_run_sha256'
  AND encode(digest(to_jsonb(j)::text,'sha256'),'hex')=p->>'dispatch_sha256'
  AND w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed'
  AND j.returned_at IS NOT NULL AND j.finalization_ack_at>=j.returned_at AND (SELECT count(*) FROM public.capacity_dispatch_jobs z WHERE z.run_id=j.run_id)=1
  AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}'
  AND w.result#>>'{steps,0,metadata,generation}'=r->>'generation' AND w.result#>>'{steps,0,metadata,fencing_token}'=r->>'fence'
  AND w.result#>>'{steps,0,metadata,lease_owner}'=r->>'lease_owner') IS NOT TRUE THEN RETURN false; END IF;
 result=w.result;
 IF (result->>'status'='failed' AND jsonb_array_length(result->'steps')=7
  AND (SELECT count(DISTINCT step->>'id') FROM jsonb_array_elements(result->'steps') step)=7
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(result->'steps') step WHERE (CASE step->>'id'
   WHEN 'plan-original-guest' THEN step->>'status'='succeeded'
   WHEN 'retire-original-guest' THEN step->>'status'='succeeded' AND step#>>'{metadata,retirement_forward_id}'=parent.id::text AND step#>>'{metadata,request_id}'=retirement::text
   WHEN 'finish-original-retirement' THEN step->>'status'='failed'
   WHEN 'provision-original-notify' THEN step->>'status'='skipped'
   WHEN 'complete-original-provision' THEN step->>'status'='skipped'
   WHEN 'refresh-original-membership' THEN step->>'status'='skipped'
   WHEN 'complete-original-retirement' THEN step->>'status'='skipped' ELSE false END) IS NOT TRUE)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO b FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=retirement AND destroy_grant_id::text=r->>'destroy_grant_id' AND eligibility_sha256=p->>'delete_eligibility_sha256';
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT known.* INTO g FROM public.capacity_mutation_grants known WHERE known.id=b.destroy_grant_id AND known.state='settled' AND known.original_disposition_id IS NULL AND known.failed_original_disposition_id IS NULL AND known.native_denied_disposition_id IS NULL AND known.enrolled_failed_disposition_id IS NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (encode(digest(g.grant_record::text,'sha256'),'hex')=p->>'destroy_grant_sha256'
  AND b.eligibility_sha256=encode(digest(b.original_wire,'sha256'),'hex') AND b.original_eligibility_record=convert_from(b.original_wire,'UTF8')::jsonb
  AND b.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1'
  AND g.grant_record#>>'{grant,state}'='settled' AND g.grant_record#>>'{settlement,outcome}'='accepted'
  AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true'
  AND coalesce(g.grant_record#>>'{grant,compensation_of}','')=''
  AND EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards authority WHERE authority.id=(b.original_eligibility_record->>'admission_id')::uuid AND authority.stage='admitted' AND authority.record_sha256=b.original_eligibility_record->>'admission_sha256' AND authority.original_record->>'root_admission_id'=r->>'root_admission_id' AND authority.original_record->'evidence'=r->'evidence'
   AND g.generation=(authority.original_record->>'generation')::bigint AND g.grant_record->>'fencing_token'=authority.original_record->>'fence'
   AND g.grant_record->>'lease_owner'=authority.original_record->>'lease_owner' AND g.grant_record->>'executor_id'=authority.original_record->>'executor_id'
   AND g.integration_instance_id::text=authority.integration_instance_id AND g.scope_checksum=authority.scope_checksum AND g.profile_name=authority.profile_name AND g.slot=authority.slot)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO v FROM public.capacity_guest_retirement_forward_reads WHERE retirement_request_id=retirement AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1;
 IF NOT FOUND THEN RETURN false; END IF;
 -- The classic branch below remains byte-for-byte unchanged. A pre-read
 -- failure has a DIFFERENT closed proof schema: current failure/ACK/SDK and
 -- current requester quiet were checked above; its old Pending is only a
 -- historical anchor, never a fresh absence or an extended old deadline.
 IF p->>'schema'='original_settled_absence_pre_read_continuation_v1' THEN
  IF (parent.stage='admitted' AND parent.original_record->>'mode'='settled_absence_continuation'
   AND parent.original_record#>>'{continuation,schema}' IN('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1')
   AND parent.original_record#>>'{continuation,pending_read_id}'=p->>'pending_read_id'
   AND parent.original_record#>>'{continuation,pending_read_sha256}'=p->>'pending_read_sha256'
   AND parent.original_record#>>'{continuation,destroy_grant_sha256}'=p->>'destroy_grant_sha256'
   AND parent.original_record#>>'{continuation,delete_eligibility_sha256}'=p->>'delete_eligibility_sha256'
   AND parent.original_record->>'destroy_grant_id'=g.id::text
   AND v.id::text=p->>'pending_read_id' AND v.record_sha256=p->>'pending_read_sha256' AND v.kind='absence'
   AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads own_read WHERE own_read.admission_id=parent.id)) IS NOT TRUE THEN RETURN false; END IF;
  SELECT * INTO requested FROM public.capacity_guest_retirement_forwards WHERE id=parent.id AND stage='requested';
  IF NOT FOUND THEN RETURN false; END IF;
  IF (requested.original_record->>'mode'='settled_absence_continuation'
   AND requested.original_record->'continuation'=parent.original_record->'continuation'
   AND requested.original_record->>'root_admission_id'=parent.original_record->>'root_admission_id'
   AND requested.original_record->>'parent_admission_id'=parent.original_record->>'parent_admission_id'
   AND requested.original_record->>'parent_admission_sha256'=parent.original_record->>'parent_admission_sha256'
   AND requested.retirement_request_id=retirement AND requested.original_record->>'destroy_grant_id'=g.id::text
   AND requested.original_record->'evidence'=parent.original_record->'evidence' AND requested.recorded_at<=admitted.recorded_at
   AND requested.record_sha256=encode(digest(requested.original_wire,'sha256'),'hex')
   AND requested.original_record=convert_from(requested.original_wire,'UTF8')::jsonb) IS NOT TRUE THEN RETURN false; END IF;
  SELECT * INTO anchor FROM public.capacity_guest_retirement_forwards WHERE id=v.admission_id AND stage='admitted';
  IF NOT FOUND THEN RETURN false; END IF;
  IF (anchor.id<>parent.id AND anchor.retirement_request_id=retirement
   AND anchor.original_record->>'root_admission_id'=r->>'root_admission_id' AND anchor.original_record->'evidence'=r->'evidence'
   AND anchor.original_record->>'prefix_sha256'=r->>'prefix_sha256' AND anchor.original_record->>'original_caller_sha256'=r->>'original_caller_sha256'
   AND anchor.recorded_at<admitted.recorded_at AND (v.original_record->>'original_returned_at_core')::timestamptz<admitted.recorded_at
   AND anchor.record_sha256=v.original_record#>>'{read,admission_sha256}'
   AND anchor.record_sha256=encode(digest(anchor.original_wire,'sha256'),'hex')
   AND anchor.original_record=convert_from(anchor.original_wire,'UTF8')::jsonb) IS NOT TRUE THEN RETURN false; END IF;
  -- Find one REAL classic requested frame, not a caller-supplied proof and not
  -- a recursive chain of typed frames. Its source custody is rechecked below.
  SELECT count(*),min(f.id::text)::uuid INTO n,classic_id FROM public.capacity_guest_retirement_forwards f
   WHERE f.retirement_request_id=retirement AND f.stage='requested'
   AND f.original_record->>'mode'='settled_absence_continuation'
   AND f.original_record#>>'{continuation,schema}'='original_settled_absence_continuation_v1'
   AND f.original_record#>>'{continuation,pending_read_id}'=p->>'pending_read_id'
   AND f.original_record#>>'{continuation,pending_read_sha256}'=p->>'pending_read_sha256'
   AND f.original_record->>'parent_admission_id'=anchor.id::text AND f.original_record->>'root_admission_id'=r->>'root_admission_id';
  IF n<>1 THEN RETURN false; END IF;
  SELECT * INTO STRICT classic FROM public.capacity_guest_retirement_forwards WHERE id=classic_id AND stage='requested';
  IF (classic.record_sha256=encode(digest(classic.original_wire,'sha256'),'hex')
   AND classic.original_record=convert_from(classic.original_wire,'UTF8')::jsonb
   AND classic.original_record->>'destroy_grant_id'=g.id::text AND classic.original_record->'evidence'=r->'evidence') IS NOT TRUE THEN RETURN false; END IF;
  -- Only requesting_run_id is substituted in this validation VALUE. Every
  -- stored original remains exact. Quiet belongs to the NEW live requester;
  -- the classic failed owner/read/ACK retain their own historical clocks.
  -- The explicitly OLD schema guarantees one bounded recursion, never v96.
  RETURN public.retirement_forward_continuation_valid(jsonb_set(classic.original_record,'{continuation,requesting_run_id}',to_jsonb(p->>'requesting_run_id')),retirement) IS TRUE;
 END IF;
 SELECT * INTO STRICT prepared FROM public.capacity_guest_retirement_forward_reads WHERE id=v.id AND stage='prepared';
 rd=v.original_record->'read'; o=v.original_record->'observation'; receipt=v.original_record->'original_destroy_receipt';
 IF (v.id::text=p->>'pending_read_id' AND v.record_sha256=p->>'pending_read_sha256'
  AND v.admission_id=parent.id AND v.kind='absence' AND v.record_sha256=encode(digest(v.original_wire,'sha256'),'hex') AND prepared.record_sha256=encode(digest(prepared.original_wire,'sha256'),'hex')
  AND v.original_record=convert_from(v.original_wire,'UTF8')::jsonb AND prepared.original_record=convert_from(prepared.original_wire,'UTF8')::jsonb AND rd=prepared.original_record
  AND rd->>'admission_sha256'=admitted.record_sha256 AND rd->>'prefix_sha256'=r->>'prefix_sha256' AND rd->>'original_caller_sha256'=r->>'original_caller_sha256'
  AND rd->'tuple'=r#>'{original,Request,intent,tuple}' AND rd->>'destroy_grant_id'=g.id::text
  AND v.original_record->>'schema'='original_core_guest_retirement_forward_read_return_v1' AND v.original_record->>'status'='observed'
  AND v.original_record->>'call_failed'='false' AND v.original_record->>'original_context_failed'='false' AND NOT(v.original_record ? 'plan')
  AND (v.original_record->>'started_at_core')::timestamptz>=(rd->>'issued_at_core')::timestamptz
  AND (v.original_record->>'original_returned_at_core')::timestamptz>=(v.original_record->>'started_at_core')::timestamptz
  AND (v.original_record->>'original_returned_at_core')::timestamptz<(rd->>'original_deadline_core')::timestamptz
  AND (rd->>'original_deadline_core')::timestamptz<=(rd->>'issued_at_core')::timestamptz+interval '5 seconds'
  AND v.recorded_at>=prepared.recorded_at AND v.recorded_at>=admitted.recorded_at AND v.recorded_at<=j.returned_at
  AND (v.original_record->>'original_returned_at_core')::timestamptz<=j.returned_at
  AND receipt->'grant'=g.grant_record->'grant' AND receipt->'attempt_id'=g.grant_record->'attempt_id'
  AND receipt->>'outcome'='accepted' AND receipt->>'transport_completed'='true'
  AND receipt->'resource_id'=g.grant_record#>'{settlement,resource_id}' AND receipt->'resource_created_at'=g.grant_record#>'{settlement,resource_created_at}'
  AND receipt->'resource_id'=g.grant_record#>'{grant,expected_resource_id}' AND receipt->'resource_created_at'=g.grant_record#>'{grant,expected_resource_created_at}'
  AND receipt->'action_id'=g.grant_record#>'{settlement,action_id}' AND coalesce(receipt->'next_action_ids','[]'::jsonb)=coalesce(g.grant_record#>'{settlement,next_action_ids}','[]'::jsonb)
  AND receipt->'auxiliary_resources'=g.grant_record#>'{settlement,auxiliary_resources}' AND receipt->>'auxiliary_inventory_complete'='true'
  AND o->>'destroy_grant_id'=g.id::text AND o->>'destroy_grant_state'='settled' AND o->'id'=receipt->'resource_id' AND o->'created_at'=receipt->'resource_created_at'
  AND o->>'original_outcome'='accepted' AND o->>'original_transport_completed'='true' AND o->>'auxiliary_inventory_complete'='true'
  AND o->>'retirement_complete'='false' AND coalesce(o->>'writer_quiescence_evidence','false')='false' AND coalesce(o->>'provider_fencing_evidence','false')='false' AND coalesce(o->>'invoice_reconciled','false')='false'
  AND NOT(o ? 'billing_exposure') AND coalesce(o->>'compensation_of','')=''
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['server_absent','server_absence_complete','original_transport_completed','auxiliary_inventory_complete','billable_resources_absent','retirement_complete','invoice_reconciled','writer_quiescence_evidence','provider_fencing_evidence']) field WHERE jsonb_typeof(o->field) IS DISTINCT FROM 'boolean')
  AND jsonb_array_length(o->'auxiliary_resources')=jsonb_array_length(receipt->'auxiliary_resources')
  AND jsonb_array_length(o->'hold_reasons') BETWEEN 1 AND 3
  AND (SELECT count(DISTINCT h) FROM jsonb_array_elements_text(o->'hold_reasons') h)=jsonb_array_length(o->'hold_reasons')) IS NOT TRUE THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads q WHERE q.retirement_request_id=retirement AND q.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads z WHERE z.id=q.id AND z.stage='returned')) THEN RETURN false; END IF;
 holds=o->'hold_reasons';
 IF rd#>>'{tuple,provider}'='aws' THEN
  observer=convert_from(decode(v.original_record->>'original_observer_return','base64'),'UTF8')::jsonb;
  IF (v.original_record->>'observer_source_commit' ~ '^[0-9a-f]{40}$'
   AND v.original_record->>'observer_source_commit'<>rd->>'adapter_source_commit'
   AND jsonb_typeof(observer)='object' AND (SELECT count(*) FROM jsonb_object_keys(observer))=7
   AND observer-ARRAY['schema','observer_source_commit','original_adapter_source_commit','read_id','read_sha256','original_receipt_sha256','observation']='{}'::jsonb
   AND observer->>'schema'='original_settled_retirement_absence_read_return_v1'
   AND observer->>'observer_source_commit'=v.original_record->>'observer_source_commit'
   AND observer->>'original_adapter_source_commit'=rd->>'adapter_source_commit'
   AND observer->>'read_id'=v.id::text AND observer->>'read_sha256'=prepared.record_sha256
   AND observer->>'original_receipt_sha256' ~ '^[0-9a-f]{64}$' AND observer->'observation'=o) IS NOT TRUE THEN RETURN false; END IF;
  -- Go checks the exact published observer pin and canonical receipt hash;
  -- SQL retains the complete raw wrapper and its exact challenge/DTO join.
  state=o#>>'{aws_retirement_lifecycle,ec2_state}'; absent=state IN('terminated','not_found');
  IF (o#>>'{aws_retirement_lifecycle,schema}'='aws_original_terminate_and_native_absence_v1' AND o#>'{aws_retirement_lifecycle,request_id}'=receipt->'action_id'
   AND state IN('pending','running','stopping','stopped','shutting-down','terminated','not_found')
   AND (o->>'server_absent')::boolean=absent AND (o->>'server_absence_complete')::boolean=absent
   AND CASE WHEN absent THEN coalesce(o->>'server_status','')='' ELSE o->>'server_status'=state END
   AND o->>'billable_resources_absent'='false' AND jsonb_array_length(receipt->'auxiliary_resources')=2
   AND coalesce(o->'delete_action','{}'::jsonb) IN('{}'::jsonb,'{"known":false,"observed":false}'::jsonb)
   AND o->'next_actions'='[]'::jsonb
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(holds) h WHERE h NOT IN('instance_not_terminated','aws_ebs_volume_still_present','aws_network_interface_still_present'))
   AND (holds ? 'instance_not_terminated')<>absent) IS NOT TRUE THEN RETURN false; END IF;
  FOR n IN 0..1 LOOP
   a=o->'auxiliary_resources'->n;
   IF (a->'kind'=receipt->'auxiliary_resources'->n->'kind' AND a->'id'=receipt->'auxiliary_resources'->n->'id' AND (holds ? ((a->>'kind')||'_still_present'))<>(a->>'absent')::boolean) IS NOT TRUE THEN RETURN false; END IF;
  END LOOP;
 ELSE
  -- The exact Hetzner Pending classifier remains mandatory in Go. Storage
  -- additionally refuses non-original action/aux identity and unknown statuses.
  IF (rd#>>'{tuple,provider}'='hetzner' AND NOT(o ? 'aws_retirement_lifecycle')
   AND o->>'server_absence_complete'='true' AND jsonb_array_length(receipt->'auxiliary_resources') BETWEEN 1 AND 2
   AND o#>'{delete_action,id}'=receipt->'action_id' AND o#>>'{delete_action,known}'='true' AND o#>>'{delete_action,observed}'='true'
   AND o#>>'{delete_action,command}'='delete_server' AND o#>>'{delete_action,status}' IN('running','success') AND coalesce(o#>>'{delete_action,error_code}','')=''
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(holds) h WHERE h NOT IN('native_server_present','original_delete_actions_not_successful','native_billable_resources_present'))
   AND (holds ? 'native_server_present')<>(o->>'server_absent')::boolean
   AND (holds ? 'native_billable_resources_present')<>(o->>'billable_resources_absent')::boolean
   AND jsonb_array_length(o->'next_actions')=jsonb_array_length(coalesce(receipt->'next_action_ids','[]'::jsonb))) IS NOT TRUE THEN RETURN false; END IF;
  FOR n IN 0..jsonb_array_length(o->'auxiliary_resources')-1 LOOP
   a=o->'auxiliary_resources'->n;
   IF (a->'kind'=receipt->'auxiliary_resources'->n->'kind' AND a->'id'=receipt->'auxiliary_resources'->n->'id') IS NOT TRUE THEN RETURN false; END IF;
  END LOOP;
 END IF;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Retained proof is permanent history; never strand it under the old CHECK.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards WHERE original_record#>>'{continuation,schema}'='original_settled_absence_closed_failed_read_continuation_v1') THEN RAISE EXCEPTION 'retained closed failed-read continuation prevents migration102 down'; END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_valid(r jsonb, retirement uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE p jsonb=r->'continuation'; parent public.capacity_guest_retirement_forwards;
 admitted public.capacity_guest_retirement_forwards; b public.capacity_vm_retirement_delete_bindings;
 g public.capacity_mutation_grants; v public.capacity_guest_retirement_forward_reads;
 prepared public.capacity_guest_retirement_forward_reads; w public.workflow_runs; j public.capacity_dispatch_jobs;
 anchor public.capacity_guest_retirement_forwards; requested public.capacity_guest_retirement_forwards; classic public.capacity_guest_retirement_forwards; classic_id uuid;
 receipt jsonb; o jsonb; rd jsonb; result jsonb; holds jsonb; observer jsonb; a jsonb; state text; absent boolean; n integer;
BEGIN
 IF (jsonb_typeof(p)='object' AND (SELECT count(*) FROM jsonb_object_keys(p))=10 AND p->>'schema' IN('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1')
  AND p-ARRAY['schema','requesting_run_id','failed_run_id','failed_run_sha256','dispatch_id','dispatch_sha256','destroy_grant_sha256','delete_eligibility_sha256','pending_read_id','pending_read_sha256']='{}'::jsonb
  AND p->>'failed_run_id' ~ '^[0-9a-f-]{36}$' AND p->>'requesting_run_id' ~ '^[0-9a-f-]{36}$'
  AND p->>'failed_run_sha256' ~ '^[0-9a-f]{64}$' AND p->>'dispatch_sha256' ~ '^[0-9a-f]{64}$'
  AND p->>'destroy_grant_sha256' ~ '^[0-9a-f]{64}$' AND p->>'delete_eligibility_sha256' ~ '^[0-9a-f]{64}$'
  AND p->>'pending_read_sha256' ~ '^[0-9a-f]{64}$'
  AND r->>'issuer'='source:settled-absence-continuation' AND r->>'run_id'=''
  AND (r#>>'{barrier,ProcessStartedAt}')::timestamptz='0001-01-01T00:00:00Z'::timestamptz
  AND r#>>'{barrier,SourceCommit}'='' AND r#>>'{barrier,Hostname}'='' AND r#>>'{barrier,PID}'='0') IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO parent FROM public.capacity_guest_retirement_forwards WHERE id=(r->>'parent_admission_id')::uuid AND record_sha256=r->>'parent_admission_sha256' AND stage IN('admitted','off_qualified');
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO STRICT admitted FROM public.capacity_guest_retirement_forwards WHERE id=parent.id AND stage='admitted';
 IF (parent.retirement_request_id=retirement AND parent.original_record->>'root_admission_id'=r->>'root_admission_id' AND parent.original_record->'evidence'=r->'evidence'
  AND parent.original_record->>'generation'=r->>'generation' AND parent.original_record->>'fence'=r->>'fence'
  AND parent.original_record->>'lease_owner'=r->>'lease_owner' AND parent.original_record->>'executor_id'=r->>'executor_id'
  AND admitted.original_record->>'run_id'=p->>'failed_run_id' AND public.retirement_forward_continuation_quiet(r,(p->>'requesting_run_id')::uuid)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO w FROM public.workflow_runs WHERE id=(p->>'failed_run_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE id=(p->>'dispatch_id')::uuid AND run_id=w.id;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (to_jsonb(w)=convert_from(decode(r->>'failed_run','base64'),'UTF8')::jsonb
  AND encode(digest(decode(r->>'failed_run','base64'),'sha256'),'hex')=p->>'failed_run_sha256'
  AND encode(digest(to_jsonb(j)::text,'sha256'),'hex')=p->>'dispatch_sha256'
  AND w.status='failed' AND w.finished_at=j.returned_at AND j.state='returned' AND j.return_status='failed'
  AND j.returned_at IS NOT NULL AND j.finalization_ack_at>=j.returned_at AND (SELECT count(*) FROM public.capacity_dispatch_jobs z WHERE z.run_id=j.run_id)=1
  AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}'
  AND w.result#>>'{steps,0,metadata,generation}'=r->>'generation' AND w.result#>>'{steps,0,metadata,fencing_token}'=r->>'fence'
  AND w.result#>>'{steps,0,metadata,lease_owner}'=r->>'lease_owner') IS NOT TRUE THEN RETURN false; END IF;
 result=w.result;
 IF (result->>'status'='failed' AND jsonb_array_length(result->'steps')=7
  AND (SELECT count(DISTINCT step->>'id') FROM jsonb_array_elements(result->'steps') step)=7
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(result->'steps') step WHERE (CASE step->>'id'
   WHEN 'plan-original-guest' THEN step->>'status'='succeeded'
   WHEN 'retire-original-guest' THEN step->>'status'='succeeded' AND step#>>'{metadata,retirement_forward_id}'=parent.id::text AND step#>>'{metadata,request_id}'=retirement::text
   WHEN 'finish-original-retirement' THEN step->>'status'='failed'
   WHEN 'provision-original-notify' THEN step->>'status'='skipped'
   WHEN 'complete-original-provision' THEN step->>'status'='skipped'
   WHEN 'refresh-original-membership' THEN step->>'status'='skipped'
   WHEN 'complete-original-retirement' THEN step->>'status'='skipped' ELSE false END) IS NOT TRUE)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO b FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=retirement AND destroy_grant_id::text=r->>'destroy_grant_id' AND eligibility_sha256=p->>'delete_eligibility_sha256';
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT known.* INTO g FROM public.capacity_mutation_grants known WHERE known.id=b.destroy_grant_id AND known.state='settled' AND known.original_disposition_id IS NULL AND known.failed_original_disposition_id IS NULL AND known.native_denied_disposition_id IS NULL AND known.enrolled_failed_disposition_id IS NULL;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (encode(digest(g.grant_record::text,'sha256'),'hex')=p->>'destroy_grant_sha256'
  AND b.eligibility_sha256=encode(digest(b.original_wire,'sha256'),'hex') AND b.original_eligibility_record=convert_from(b.original_wire,'UTF8')::jsonb
  AND b.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1'
  AND g.grant_record#>>'{grant,state}'='settled' AND g.grant_record#>>'{settlement,outcome}'='accepted'
  AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true'
  AND coalesce(g.grant_record#>>'{grant,compensation_of}','')=''
  AND EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards authority WHERE authority.id=(b.original_eligibility_record->>'admission_id')::uuid AND authority.stage='admitted' AND authority.record_sha256=b.original_eligibility_record->>'admission_sha256' AND authority.original_record->>'root_admission_id'=r->>'root_admission_id' AND authority.original_record->'evidence'=r->'evidence'
   AND g.generation=(authority.original_record->>'generation')::bigint AND g.grant_record->>'fencing_token'=authority.original_record->>'fence'
   AND g.grant_record->>'lease_owner'=authority.original_record->>'lease_owner' AND g.grant_record->>'executor_id'=authority.original_record->>'executor_id'
   AND g.integration_instance_id::text=authority.integration_instance_id AND g.scope_checksum=authority.scope_checksum AND g.profile_name=authority.profile_name AND g.slot=authority.slot)) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO v FROM public.capacity_guest_retirement_forward_reads WHERE retirement_request_id=retirement AND stage='returned' ORDER BY recorded_at DESC,id DESC LIMIT 1;
 IF NOT FOUND THEN RETURN false; END IF;
 -- The classic branch below remains byte-for-byte unchanged. A pre-read
 -- failure has a DIFFERENT closed proof schema: current failure/ACK/SDK and
 -- current requester quiet were checked above; its old Pending is only a
 -- historical anchor, never a fresh absence or an extended old deadline.
 IF p->>'schema'='original_settled_absence_pre_read_continuation_v1' THEN
  IF (parent.stage='admitted' AND parent.original_record->>'mode'='settled_absence_continuation'
   AND parent.original_record#>>'{continuation,schema}' IN('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1')
   AND parent.original_record#>>'{continuation,pending_read_id}'=p->>'pending_read_id'
   AND parent.original_record#>>'{continuation,pending_read_sha256}'=p->>'pending_read_sha256'
   AND parent.original_record#>>'{continuation,destroy_grant_sha256}'=p->>'destroy_grant_sha256'
   AND parent.original_record#>>'{continuation,delete_eligibility_sha256}'=p->>'delete_eligibility_sha256'
   AND parent.original_record->>'destroy_grant_id'=g.id::text
   AND v.id::text=p->>'pending_read_id' AND v.record_sha256=p->>'pending_read_sha256' AND v.kind='absence'
   AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads own_read WHERE own_read.admission_id=parent.id)) IS NOT TRUE THEN RETURN false; END IF;
  SELECT * INTO requested FROM public.capacity_guest_retirement_forwards WHERE id=parent.id AND stage='requested';
  IF NOT FOUND THEN RETURN false; END IF;
  IF (requested.original_record->>'mode'='settled_absence_continuation'
   AND requested.original_record->'continuation'=parent.original_record->'continuation'
   AND requested.original_record->>'root_admission_id'=parent.original_record->>'root_admission_id'
   AND requested.original_record->>'parent_admission_id'=parent.original_record->>'parent_admission_id'
   AND requested.original_record->>'parent_admission_sha256'=parent.original_record->>'parent_admission_sha256'
   AND requested.retirement_request_id=retirement AND requested.original_record->>'destroy_grant_id'=g.id::text
   AND requested.original_record->'evidence'=parent.original_record->'evidence' AND requested.recorded_at<=admitted.recorded_at
   AND requested.record_sha256=encode(digest(requested.original_wire,'sha256'),'hex')
   AND requested.original_record=convert_from(requested.original_wire,'UTF8')::jsonb) IS NOT TRUE THEN RETURN false; END IF;
  SELECT * INTO anchor FROM public.capacity_guest_retirement_forwards WHERE id=v.admission_id AND stage='admitted';
  IF NOT FOUND THEN RETURN false; END IF;
  IF (anchor.id<>parent.id AND anchor.retirement_request_id=retirement
   AND anchor.original_record->>'root_admission_id'=r->>'root_admission_id' AND anchor.original_record->'evidence'=r->'evidence'
   AND anchor.original_record->>'prefix_sha256'=r->>'prefix_sha256' AND anchor.original_record->>'original_caller_sha256'=r->>'original_caller_sha256'
   AND anchor.recorded_at<admitted.recorded_at AND (v.original_record->>'original_returned_at_core')::timestamptz<admitted.recorded_at
   AND anchor.record_sha256=v.original_record#>>'{read,admission_sha256}'
   AND anchor.record_sha256=encode(digest(anchor.original_wire,'sha256'),'hex')
   AND anchor.original_record=convert_from(anchor.original_wire,'UTF8')::jsonb) IS NOT TRUE THEN RETURN false; END IF;
  -- Find one REAL classic requested frame, not a caller-supplied proof and not
  -- a recursive chain of typed frames. Its source custody is rechecked below.
  SELECT count(*),min(f.id::text)::uuid INTO n,classic_id FROM public.capacity_guest_retirement_forwards f
   WHERE f.retirement_request_id=retirement AND f.stage='requested'
   AND f.original_record->>'mode'='settled_absence_continuation'
   AND f.original_record#>>'{continuation,schema}'='original_settled_absence_continuation_v1'
   AND f.original_record#>>'{continuation,pending_read_id}'=p->>'pending_read_id'
   AND f.original_record#>>'{continuation,pending_read_sha256}'=p->>'pending_read_sha256'
   AND f.original_record->>'parent_admission_id'=anchor.id::text AND f.original_record->>'root_admission_id'=r->>'root_admission_id';
  IF n<>1 THEN RETURN false; END IF;
  SELECT * INTO STRICT classic FROM public.capacity_guest_retirement_forwards WHERE id=classic_id AND stage='requested';
  IF (classic.record_sha256=encode(digest(classic.original_wire,'sha256'),'hex')
   AND classic.original_record=convert_from(classic.original_wire,'UTF8')::jsonb
   AND classic.original_record->>'destroy_grant_id'=g.id::text AND classic.original_record->'evidence'=r->'evidence') IS NOT TRUE THEN RETURN false; END IF;
  -- Only requesting_run_id is substituted in this validation VALUE. Every
  -- stored original remains exact. Quiet belongs to the NEW live requester;
  -- the classic failed owner/read/ACK retain their own historical clocks.
  -- The explicitly OLD schema guarantees one bounded recursion, never v96.
  RETURN public.retirement_forward_continuation_valid(jsonb_set(classic.original_record,'{continuation,requesting_run_id}',to_jsonb(p->>'requesting_run_id')),retirement) IS TRUE;
 END IF;
 SELECT * INTO STRICT prepared FROM public.capacity_guest_retirement_forward_reads WHERE id=v.id AND stage='prepared';
 rd=v.original_record->'read'; o=v.original_record->'observation'; receipt=v.original_record->'original_destroy_receipt';
 IF (v.id::text=p->>'pending_read_id' AND v.record_sha256=p->>'pending_read_sha256'
  AND v.admission_id=parent.id AND v.kind='absence' AND v.record_sha256=encode(digest(v.original_wire,'sha256'),'hex') AND prepared.record_sha256=encode(digest(prepared.original_wire,'sha256'),'hex')
  AND v.original_record=convert_from(v.original_wire,'UTF8')::jsonb AND prepared.original_record=convert_from(prepared.original_wire,'UTF8')::jsonb AND rd=prepared.original_record
  AND rd->>'admission_sha256'=admitted.record_sha256 AND rd->>'prefix_sha256'=r->>'prefix_sha256' AND rd->>'original_caller_sha256'=r->>'original_caller_sha256'
  AND rd->'tuple'=r#>'{original,Request,intent,tuple}' AND rd->>'destroy_grant_id'=g.id::text
  AND v.original_record->>'schema'='original_core_guest_retirement_forward_read_return_v1' AND v.original_record->>'status'='observed'
  AND v.original_record->>'call_failed'='false' AND v.original_record->>'original_context_failed'='false' AND NOT(v.original_record ? 'plan')
  AND (v.original_record->>'started_at_core')::timestamptz>=(rd->>'issued_at_core')::timestamptz
  AND (v.original_record->>'original_returned_at_core')::timestamptz>=(v.original_record->>'started_at_core')::timestamptz
  AND (v.original_record->>'original_returned_at_core')::timestamptz<(rd->>'original_deadline_core')::timestamptz
  AND (rd->>'original_deadline_core')::timestamptz<=(rd->>'issued_at_core')::timestamptz+interval '5 seconds'
  AND v.recorded_at>=prepared.recorded_at AND v.recorded_at>=admitted.recorded_at AND v.recorded_at<=j.returned_at
  AND (v.original_record->>'original_returned_at_core')::timestamptz<=j.returned_at
  AND receipt->'grant'=g.grant_record->'grant' AND receipt->'attempt_id'=g.grant_record->'attempt_id'
  AND receipt->>'outcome'='accepted' AND receipt->>'transport_completed'='true'
  AND receipt->'resource_id'=g.grant_record#>'{settlement,resource_id}' AND receipt->'resource_created_at'=g.grant_record#>'{settlement,resource_created_at}'
  AND receipt->'resource_id'=g.grant_record#>'{grant,expected_resource_id}' AND receipt->'resource_created_at'=g.grant_record#>'{grant,expected_resource_created_at}'
  AND receipt->'action_id'=g.grant_record#>'{settlement,action_id}' AND coalesce(receipt->'next_action_ids','[]'::jsonb)=coalesce(g.grant_record#>'{settlement,next_action_ids}','[]'::jsonb)
  AND receipt->'auxiliary_resources'=g.grant_record#>'{settlement,auxiliary_resources}' AND receipt->>'auxiliary_inventory_complete'='true'
  AND o->>'destroy_grant_id'=g.id::text AND o->>'destroy_grant_state'='settled' AND o->'id'=receipt->'resource_id' AND o->'created_at'=receipt->'resource_created_at'
  AND o->>'original_outcome'='accepted' AND o->>'original_transport_completed'='true' AND o->>'auxiliary_inventory_complete'='true'
  AND o->>'retirement_complete'='false' AND coalesce(o->>'writer_quiescence_evidence','false')='false' AND coalesce(o->>'provider_fencing_evidence','false')='false' AND coalesce(o->>'invoice_reconciled','false')='false'
  AND NOT(o ? 'billing_exposure') AND coalesce(o->>'compensation_of','')=''
  AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['server_absent','server_absence_complete','original_transport_completed','auxiliary_inventory_complete','billable_resources_absent','retirement_complete','invoice_reconciled','writer_quiescence_evidence','provider_fencing_evidence']) field WHERE jsonb_typeof(o->field) IS DISTINCT FROM 'boolean')
  AND jsonb_array_length(o->'auxiliary_resources')=jsonb_array_length(receipt->'auxiliary_resources')
  AND jsonb_array_length(o->'hold_reasons') BETWEEN 1 AND 3
  AND (SELECT count(DISTINCT h) FROM jsonb_array_elements_text(o->'hold_reasons') h)=jsonb_array_length(o->'hold_reasons')) IS NOT TRUE THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads q WHERE q.retirement_request_id=retirement AND q.stage='prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads z WHERE z.id=q.id AND z.stage='returned')) THEN RETURN false; END IF;
 holds=o->'hold_reasons';
 IF rd#>>'{tuple,provider}'='aws' THEN
  observer=convert_from(decode(v.original_record->>'original_observer_return','base64'),'UTF8')::jsonb;
  IF (v.original_record->>'observer_source_commit' ~ '^[0-9a-f]{40}$'
   AND v.original_record->>'observer_source_commit'<>rd->>'adapter_source_commit'
   AND jsonb_typeof(observer)='object' AND (SELECT count(*) FROM jsonb_object_keys(observer))=7
   AND observer-ARRAY['schema','observer_source_commit','original_adapter_source_commit','read_id','read_sha256','original_receipt_sha256','observation']='{}'::jsonb
   AND observer->>'schema'='original_settled_retirement_absence_read_return_v1'
   AND observer->>'observer_source_commit'=v.original_record->>'observer_source_commit'
   AND observer->>'original_adapter_source_commit'=rd->>'adapter_source_commit'
   AND observer->>'read_id'=v.id::text AND observer->>'read_sha256'=prepared.record_sha256
   AND observer->>'original_receipt_sha256' ~ '^[0-9a-f]{64}$' AND observer->'observation'=o) IS NOT TRUE THEN RETURN false; END IF;
  -- Go checks the exact published observer pin and canonical receipt hash;
  -- SQL retains the complete raw wrapper and its exact challenge/DTO join.
  state=o#>>'{aws_retirement_lifecycle,ec2_state}'; absent=state IN('terminated','not_found');
  IF (o#>>'{aws_retirement_lifecycle,schema}'='aws_original_terminate_and_native_absence_v1' AND o#>'{aws_retirement_lifecycle,request_id}'=receipt->'action_id'
   AND state IN('pending','running','stopping','stopped','shutting-down','terminated','not_found')
   AND (o->>'server_absent')::boolean=absent AND (o->>'server_absence_complete')::boolean=absent
   AND CASE WHEN absent THEN coalesce(o->>'server_status','')='' ELSE o->>'server_status'=state END
   AND o->>'billable_resources_absent'='false' AND jsonb_array_length(receipt->'auxiliary_resources')=2
   AND coalesce(o->'delete_action','{}'::jsonb) IN('{}'::jsonb,'{"known":false,"observed":false}'::jsonb)
   AND o->'next_actions'='[]'::jsonb
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(holds) h WHERE h NOT IN('instance_not_terminated','aws_ebs_volume_still_present','aws_network_interface_still_present'))
   AND (holds ? 'instance_not_terminated')<>absent) IS NOT TRUE THEN RETURN false; END IF;
  FOR n IN 0..1 LOOP
   a=o->'auxiliary_resources'->n;
   IF (a->'kind'=receipt->'auxiliary_resources'->n->'kind' AND a->'id'=receipt->'auxiliary_resources'->n->'id' AND (holds ? ((a->>'kind')||'_still_present'))<>(a->>'absent')::boolean) IS NOT TRUE THEN RETURN false; END IF;
  END LOOP;
 ELSE
  -- The exact Hetzner Pending classifier remains mandatory in Go. Storage
  -- additionally refuses non-original action/aux identity and unknown statuses.
  IF (rd#>>'{tuple,provider}'='hetzner' AND NOT(o ? 'aws_retirement_lifecycle')
   AND o->>'server_absence_complete'='true' AND jsonb_array_length(receipt->'auxiliary_resources') BETWEEN 1 AND 2
   AND o#>'{delete_action,id}'=receipt->'action_id' AND o#>>'{delete_action,known}'='true' AND o#>>'{delete_action,observed}'='true'
   AND o#>>'{delete_action,command}'='delete_server' AND o#>>'{delete_action,status}' IN('running','success') AND coalesce(o#>>'{delete_action,error_code}','')=''
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(holds) h WHERE h NOT IN('native_server_present','original_delete_actions_not_successful','native_billable_resources_present'))
   AND (holds ? 'native_server_present')<>(o->>'server_absent')::boolean
   AND (holds ? 'native_billable_resources_present')<>(o->>'billable_resources_absent')::boolean
   AND jsonb_array_length(o->'next_actions')=jsonb_array_length(coalesce(receipt->'next_action_ids','[]'::jsonb))) IS NOT TRUE THEN RETURN false; END IF;
  FOR n IN 0..jsonb_array_length(o->'auxiliary_resources')-1 LOOP
   a=o->'auxiliary_resources'->n;
   IF (a->'kind'=receipt->'auxiliary_resources'->n->'kind' AND a->'id'=receipt->'auxiliary_resources'->n->'id') IS NOT TRUE THEN RETURN false; END IF;
  END LOOP;
 END IF;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ BEGIN
 ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT IF EXISTS retirement_forward_continuation102;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation96') THEN
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_continuation96 CHECK((CASE WHEN original_record->>'mode'='settled_absence_continuation' THEN jsonb_typeof(original_record->'continuation')='object' AND original_record#>>'{continuation,schema}' IN('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1') ELSE NOT(original_record ? 'continuation') END) IS TRUE);
 END IF;
END $$;
-- +goose StatementEnd

DROP FUNCTION IF EXISTS public.retirement_forward_closed_failed_read102_valid(jsonb,uuid,boolean);
DROP FUNCTION IF EXISTS public.retirement_forward_closed_failed_read102_pair_valid(public.capacity_guest_retirement_forward_reads,public.capacity_guest_retirement_forward_reads);
