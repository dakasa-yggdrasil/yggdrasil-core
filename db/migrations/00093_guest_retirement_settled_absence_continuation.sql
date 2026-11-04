-- +goose Up
-- A new source-owned owner may continue ONLY authenticated Pending absence
-- after an accepted SETTLED owning DELETE. M90 originals and leases never move.
-- +goose StatementBegin
DO $$ DECLARE c text; n integer;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_mode93') THEN
  SELECT count(*),min(conname) INTO n,c FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND contype='c' AND position('mode' in pg_get_constraintdef(oid))>0 AND position('actual_core_source' in pg_get_constraintdef(oid))>0;
  IF n<>1 THEN RAISE EXCEPTION 'exact original mode constraint required'; END IF;
  EXECUTE format('ALTER TABLE public.capacity_guest_retirement_forwards DROP CONSTRAINT %I',c);
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_mode93 CHECK((original_record->>'mode' IN('live','historical','settled_absence_continuation') AND original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$') IS TRUE);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_guest_retirement_forwards'::regclass AND conname='retirement_forward_continuation93') THEN
  ALTER TABLE public.capacity_guest_retirement_forwards ADD CONSTRAINT retirement_forward_continuation93 CHECK((CASE WHEN original_record->>'mode'='settled_absence_continuation' THEN jsonb_typeof(original_record->'continuation')='object' AND original_record#>>'{continuation,schema}'='original_settled_absence_continuation_v1' ELSE NOT(original_record ? 'continuation') END) IS TRUE);
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (SELECT count(*)=1 FROM public.capacity_dispatch_jobs j WHERE j.run_id=own AND j.state='started' AND j.started_at IS NOT NULL AND j.returned_at IS NULL AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND (j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' OR (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}')=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed') OR (j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL))))
 AND NOT EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.id<>own AND (w.workflow_id IN(SELECT id FROM public.manifests WHERE kind='workflow' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(r#>>'{original,Request,intent,tuple,integration_instance_id}',r#>>'{original,Request,intent,tuple,scope_checksum}',r#>>'{original,Request,intent,tuple,profile}') AND g.state IN('issued','redeemed','settled','compensating') AND g.id::text<>r->>'destroy_grant_id')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(r#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
$$;
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
 IF NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_returns c WHERE c.intent_id=NEW.retirement_request_id AND c.return_sha256=NEW.original_record->>'original_caller_sha256' AND (c.original_record->>'preflight_failed'='false') IS TRUE AND NOT(c.original_record->>'status'='200' AND c.original_record->>'body_persisted'='true' AND c.original_record->>'do_failed'='false' AND c.original_record->>'read_failed'='false' AND c.original_record->>'close_failed'='false' AND c.original_record->>'original_context_failed'='false' AND (c.original_record->>'driver_returned_at')::timestamptz<original.original_deadline)) THEN RAISE EXCEPTION 'retained failed original caller required'; END IF;
 IF (NEW.original_record#>'{evidence,authority_sha256}'=(SELECT jsonb_agg(v.authority_sha256 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=NEW.retirement_request_id) AND (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=NEW.retirement_request_id)=4 AND (SELECT count(*) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=NEW.retirement_request_id)=4) IS NOT TRUE THEN RAISE EXCEPTION 'four exact original authorized reads required'; END IF;
 IF NEW.stage='requested' THEN
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
 ELSIF NEW.stage='admitted' THEN
  IF NEW.original_record->>'mode'='settled_absence_continuation' AND public.retirement_forward_continuation_quiet(NEW.original_record,(NEW.original_record->>'run_id')::uuid) IS NOT TRUE THEN RAISE EXCEPTION 'new claimant requires exact current dispatch quiet'; END IF;
  IF NEW.original_record->>'mode' IN('historical','settled_absence_continuation') THEN
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_forward_read() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission public.capacity_guest_retirement_forwards; prepared public.capacity_guest_retirement_forward_reads; r jsonb;
BEGIN
 SELECT * INTO STRICT admission FROM public.capacity_guest_retirement_forwards WHERE id=NEW.admission_id AND stage='admitted' FOR SHARE;
 IF (admission.retirement_request_id=NEW.retirement_request_id) IS NOT TRUE THEN RAISE EXCEPTION 'read cannot change original retirement'; END IF;
 IF admission.original_record->>'mode'='settled_absence_continuation' AND (NEW.kind<>'absence' OR (CASE WHEN NEW.stage='prepared' THEN NEW.original_record->>'destroy_grant_id' ELSE NEW.original_record#>>'{read,destroy_grant_id}' END) IS DISTINCT FROM admission.original_record->>'destroy_grant_id') THEN RAISE EXCEPTION 'continuation only reads the same settled destroy'; END IF;
 r=NEW.original_record;
 IF NEW.stage='prepared' THEN
  IF (r->>'schema'='original_core_guest_retirement_forward_read_v1' AND r->>'read_id'=NEW.id::text AND r->>'admission_id'=NEW.admission_id::text AND r->>'retirement_request_id'=NEW.retirement_request_id::text AND r->>'kind'=NEW.kind AND r->>'admission_sha256'=admission.record_sha256 AND r->>'prefix_sha256'=admission.original_record->>'prefix_sha256' AND r->>'original_caller_sha256'=admission.original_record->>'original_caller_sha256' AND r->'tuple'=admission.original_record#>'{original,Request,intent,tuple}' AND (r->>'original_deadline_core')::timestamptz>(r->>'issued_at_core')::timestamptz AND (r->>'original_deadline_core')::timestamptz<=(r->>'issued_at_core')::timestamptz+interval '5 seconds') IS NOT TRUE THEN RAISE EXCEPTION 'closed five-second original forward read required'; END IF;
 ELSE
  SELECT * INTO STRICT prepared FROM public.capacity_guest_retirement_forward_reads WHERE id=NEW.id AND stage='prepared';
  IF (r->>'schema'='original_core_guest_retirement_forward_read_return_v1' AND r->'read'=prepared.original_record AND NEW.admission_id=prepared.admission_id AND NEW.kind=prepared.kind AND jsonb_typeof(r->'call_failed')='boolean' AND jsonb_typeof(r->'original_context_failed')='boolean') IS NOT TRUE THEN RAISE EXCEPTION 'return cannot replace original challenge or failure'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_forward_delete_binding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a public.capacity_guest_retirement_forwards; g public.capacity_mutation_grants;
BEGIN
 IF NEW.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1' THEN
  SELECT * INTO STRICT a FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_eligibility_record->>'admission_id')::uuid AND stage='admitted' AND retirement_request_id=NEW.intent_id;
  IF a.original_record->>'mode'='settled_absence_continuation' THEN RAISE EXCEPTION 'continuation creates no delete authority'; END IF;
  SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.destroy_grant_id;
  IF (NEW.original_eligibility_record->>'admission_sha256'=a.record_sha256 AND NEW.eligibility_sha256=encode(digest(NEW.original_wire,'sha256'),'hex') AND NEW.original_eligibility_record=convert_from(NEW.original_wire,'UTF8')::jsonb AND g.integration_instance_id::text=a.integration_instance_id AND g.scope_checksum=a.scope_checksum AND g.profile_name=a.profile_name AND g.slot=a.slot AND g.generation=(a.original_record->>'generation')::bigint AND g.grant_record->>'fencing_token'=a.original_record->>'fence' AND g.grant_record->'grant'->>'expected_resource_id'=a.original_record#>>'{original,Request,intent,tuple,resource_id}' AND g.grant_record->'grant'->>'expected_resource_created_at'=a.original_record#>>'{original,Request,intent,tuple,resource_created_at}'
   AND g.grant_record->>'lease_owner'=a.original_record->>'lease_owner' AND g.grant_record->>'executor_id'=a.original_record->>'executor_id'
   AND EXISTS(SELECT 1 FROM public.capacity_intents c WHERE c.namespace=a.namespace AND c.environment=a.environment AND c.domain=a.domain AND c.dimension=a.dimension AND c.intent#>>'{retirement_forward,id}'=a.id::text AND c.intent#>>'{retirement_forward,stage}'='off_qualified' AND c.intent->>'phase'='drained' AND c.intent->>'fencing_token'=a.original_record->>'fence' AND c.intent->>'lease_owner'=a.original_record->>'lease_owner' AND (c.intent->>'lease_expires_at')::timestamptz>clock_timestamp())
   AND EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.id=(NEW.original_eligibility_record->>'native_off_read_id')::uuid AND v.admission_id=a.id AND v.kind='off' AND v.stage='returned' AND v.record_sha256=NEW.original_eligibility_record->>'native_off_sha256' AND v.original_record->>'status'='observed' AND v.original_record->>'call_failed'='false' AND v.original_record->>'original_context_failed'='false' AND v.original_record#>>'{plan,server,status}' IN('off','stopped'))) IS NOT TRUE THEN RAISE EXCEPTION 'narrow forward destroy binding cannot change epoch or tuple'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'permanent settled continuation provenance cannot be rolled back destructively'; END $$;
