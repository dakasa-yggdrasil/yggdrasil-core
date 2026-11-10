-- +goose Up
-- A failed read-only continuation with ZERO own reads may receive a new finite
-- read/confirm owner. The accepted DELETE, old failures and clocks never move.
-- +goose StatementBegin
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation96') THEN
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation93') THEN RAISE EXCEPTION 'exact prior continuation proof constraint required'; END IF;
  ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT retirement_forward_continuation93;
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_continuation96 CHECK((CASE WHEN original_record->>'mode'='settled_absence_continuation' THEN jsonb_typeof(original_record->'continuation')='object' AND original_record#>>'{continuation,schema}' IN('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1') ELSE NOT(original_record ? 'continuation') END) IS TRUE);
 END IF;
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

-- +goose Down
-- Never relabel/delete already retained typed custody merely to make rollback
-- fit the older closed schema. An unused migration restores the exact M93 ABI.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forwards WHERE original_record#>>'{continuation,schema}'='original_settled_absence_pre_read_continuation_v1') THEN RAISE EXCEPTION 'retained pre-read continuation proof requires schema96'; END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_valid(r jsonb, retirement uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE p jsonb=r->'continuation'; parent public.capacity_guest_retirement_forwards;
 admitted public.capacity_guest_retirement_forwards; b public.capacity_vm_retirement_delete_bindings;
 g public.capacity_mutation_grants; v public.capacity_guest_retirement_forward_reads;
 prepared public.capacity_guest_retirement_forward_reads; w public.workflow_runs; j public.capacity_dispatch_jobs;
 receipt jsonb; o jsonb; rd jsonb; result jsonb; holds jsonb; observer jsonb; a jsonb; state text; absent boolean; n integer;
BEGIN
 IF (jsonb_typeof(p)='object' AND (SELECT count(*) FROM jsonb_object_keys(p))=10 AND p->>'schema'='original_settled_absence_continuation_v1'
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
 IF EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation96') THEN
  ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT retirement_forward_continuation96;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation93') THEN
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_continuation93 CHECK((CASE WHEN original_record->>'mode'='settled_absence_continuation' THEN jsonb_typeof(original_record->'continuation')='object' AND original_record#>>'{continuation,schema}'='original_settled_absence_continuation_v1' ELSE NOT(original_record ? 'continuation') END) IS TRUE);
 END IF;
END $$;
-- +goose StatementEnd
