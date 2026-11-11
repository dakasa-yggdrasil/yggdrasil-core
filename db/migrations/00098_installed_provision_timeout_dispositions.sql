-- +goose Up
-- ADR-0111: preserve the UNKNOWN original; permit only a distinct, fenced
-- installed-readiness observation. No original ACK, deadline or VM action is made.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.installed_provision_timeout_valid(r jsonb,d bytea,w bytea,i bytea,m bytea)
RETURNS boolean LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE dj jsonb; rw jsonb; old_intent jsonb; members jsonb; env jsonb; result jsonb;
 j public.capacity_dispatch_jobs; run public.workflow_runs; policy public.manifests;
 pre public.capacity_vm_provisioning_preregistrations; witness public.capacity_guest_original_create_witnesses;
 enrollment public.capacity_vm_original_enrollments; installation public.capacity_guest_original_installations;
 grant_row public.capacity_mutation_grants; member jsonb; pr jsonb; wr jsonb; receipt jsonb; installed jsonb;
 binding jsonb; selected jsonb; n integer; ordinal integer; selected_count integer:=0; step jsonb;
BEGIN
 IF r IS NULL OR d IS NULL OR w IS NULL OR i IS NULL OR m IS NULL
 OR octet_length(d) NOT BETWEEN 1 AND 1048576 OR octet_length(w) NOT BETWEEN 1 AND 8388608
 OR octet_length(i) NOT BETWEEN 1 AND 1048576 OR octet_length(m) NOT BETWEEN 1 AND 1048576
 THEN RETURN false; END IF;
 IF (jsonb_typeof(r)='object' AND (SELECT count(*) FROM jsonb_object_keys(r))=21
 AND r ?& ARRAY['schema','id','job_id','run_id','policy_id','policy_checksum','generation','fencing_token','lease_owner','executor_id','preregistration_id','create_grant_id','original_dispatch_sha256','original_run_sha256','original_intent_sha256','members_sha256','original_deadline','original_intent_lease_expires_at','original_returned_at','recorded_at','members']
 AND r->>'schema'='unknown_installed_provision_timeout_disposition_v1'
 AND jsonb_typeof(r->'generation')='number' AND r->>'generation' ~ '^[1-9][0-9]*$'
 AND (r->>'generation')::bigint<=9007199254740991
 AND jsonb_typeof(r->'fencing_token')='number' AND r->>'fencing_token' ~ '^[1-9][0-9]*$'
 AND (r->>'fencing_token')::bigint<9007199254740991) IS NOT TRUE THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['id','job_id','run_id','policy_id','lease_owner','executor_id','preregistration_id','create_grant_id']) k
  WHERE jsonb_typeof(r->k) IS DISTINCT FROM 'string' OR r->>k !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR r->>k='00000000-0000-0000-0000-000000000000')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['policy_checksum','original_dispatch_sha256','original_run_sha256','original_intent_sha256','members_sha256']) k
  WHERE jsonb_typeof(r->k) IS DISTINCT FROM 'string' OR r->>k !~ '^[a-f0-9]{64}$')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['original_deadline','original_intent_lease_expires_at','original_returned_at','recorded_at']) k
  WHERE jsonb_typeof(r->k) IS DISTINCT FROM 'string' OR NOT isfinite((r->>k)::timestamptz))
 THEN RETURN false; END IF;
 dj=convert_from(d,'UTF8')::jsonb; rw=convert_from(w,'UTF8')::jsonb;
 old_intent=convert_from(i,'UTF8')::jsonb; members=convert_from(m,'UTF8')::jsonb;
 IF (encode(sha256(d),'hex')=r->>'original_dispatch_sha256'
 AND encode(sha256(w),'hex')=r->>'original_run_sha256'
 AND encode(sha256(i),'hex')=r->>'original_intent_sha256'
 AND encode(sha256(m),'hex')=r->>'members_sha256' AND members=r->'members'
 AND jsonb_typeof(dj)='object' AND jsonb_typeof(rw)='object' AND jsonb_typeof(old_intent)='object'
 AND jsonb_typeof(members)='array' AND jsonb_array_length(members) BETWEEN 2 AND 8) IS NOT TRUE THEN RETURN false; END IF;
 n=jsonb_array_length(members); env=(dj->>'envelope')::jsonb; result=rw->'result';
 SELECT * INTO j FROM public.capacity_dispatch_jobs WHERE id=(r->>'job_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO run FROM public.workflow_runs WHERE id=(r->>'run_id')::uuid;
 IF NOT FOUND THEN RETURN false; END IF;
 IF (dj->>'state'='unknown' AND dj->>'id'=r->>'job_id' AND dj->>'run_id'=r->>'run_id'
 AND dj->'finalization_ack_at'='null'::jsonb AND dj->>'return_status'='failed'
 AND dj->>'return_error'='capacity dispatch original deadline exceeded'
 AND (dj->>'lease_expires_at')::timestamptz=(r->>'original_deadline')::timestamptz
 AND (dj->>'returned_at')::timestamptz=(r->>'original_returned_at')::timestamptz
 AND (dj->>'started_at')::timestamptz<(r->>'original_deadline')::timestamptz
 AND (r->>'original_returned_at')::timestamptz>=(r->>'original_deadline')::timestamptz
 AND (r->>'recorded_at')::timestamptz>=(r->>'original_returned_at')::timestamptz
 AND (r->>'recorded_at')::timestamptz>=(r->>'original_intent_lease_expires_at')::timestamptz
 AND j.run_id=run.id AND j.finalization_ack_at IS NULL AND j.state IN('unknown','installed_timeout_disposed')
 AND (to_jsonb(j)-ARRAY['state','updated_at'])=(dj-ARRAY['state','updated_at'])
 AND (j.state='installed_timeout_disposed' OR to_jsonb(j)=dj)
 AND to_jsonb(run)=rw AND rw->>'status'='failed'
 AND rw->>'error'='capacity dispatch original deadline exceeded'
 AND (rw->>'started_at')::timestamptz=(dj->>'started_at')::timestamptz
 AND (rw->>'finished_at')::timestamptz=(r->>'original_returned_at')::timestamptz
 AND rw#>>'{metadata,triggered_by}'='workflow_scheduler'
 AND rw#>>'{metadata,capacity_dispatch_job_id}'=r->>'job_id'
 AND env->>'protocol'=dj->>'protocol' AND env->>'protocol'='capacity_dispatch_prestart_v1'
 AND env->>'job_id'=r->>'job_id' AND env->>'run_id'=r->>'run_id'
 AND encode(sha256(convert_to(dj->>'envelope','UTF8')),'hex')=dj->>'envelope_sha256'
 AND env#>>'{policy,id}'=r->>'policy_id' AND env#>>'{policy,checksum}'=r->>'policy_checksum'
 AND env#>>'{metadata,triggered_by}'='workflow_scheduler'
 AND env#>>'{metadata,capacity_dispatch_job_id}'=r->>'job_id'
 AND old_intent->>'namespace'=dj->>'realm' AND old_intent->>'environment'=dj->>'environment'
 AND old_intent->>'domain'=dj->>'domain' AND old_intent->>'dimension'=dj->>'dimension'
 AND old_intent->>'policy_id'=r->>'policy_id' AND old_intent->>'policy_checksum'=r->>'policy_checksum'
 AND old_intent->'generation'=r->'generation' AND old_intent->'fencing_token'=r->'fencing_token'
 AND old_intent->>'lease_owner'=r->>'lease_owner' AND old_intent->>'lease_executor_id'=r->>'executor_id'
 AND (old_intent->>'lease_expires_at')::timestamptz=(r->>'original_intent_lease_expires_at')::timestamptz
 AND old_intent->>'phase'='preparing' AND old_intent->'recovery_only'='false'::jsonb
 AND coalesce(old_intent->'floor_degraded','false'::jsonb)='false'::jsonb
 AND NOT old_intent ?| ARRAY['installed_guest_reconcile','failed_installed_disposal','failed_serving_disposal','failed_expansion_terminal_reconcile','failed_unwitnessed_expansion_cleanup_id','retirement_forward','original_notify_window']
 AND old_intent#>>'{decision,action}'='expand' AND old_intent#>'{decision,units}'=to_jsonb(n)
 AND old_intent#>'{baseline_snapshot,units}'=to_jsonb(n-1)
 AND old_intent#>'{assessment,snapshot,units}' IN(to_jsonb(n-1),to_jsonb(n))) IS NOT TRUE THEN RETURN false; END IF;
 SELECT * INTO policy FROM public.manifests WHERE id=(r->>'policy_id')::uuid AND kind='capacity_policy';
 IF NOT FOUND THEN RETURN false; END IF;
 IF (policy.checksum=r->>'policy_checksum' AND policy.namespace=dj->>'realm'
 AND policy.spec->>'environment'=dj->>'environment' AND policy.spec->>'domain'=dj->>'domain'
 AND policy.spec->>'dimension'=dj->>'dimension' AND policy.spec->'execution_enabled'='true'::jsonb
 AND (policy.spec->>'ceiling')::integer>=n AND jsonb_array_length(policy.spec->'mutation_bindings')=1
 AND jsonb_typeof(policy.spec->'guest_retirement_binding')='object'
 AND jsonb_typeof(policy.spec->'guest_notify_reconcile_binding')='object') IS NOT TRUE THEN RETURN false; END IF;
 binding=policy.spec#>'{mutation_bindings,0}';
 FOR member,ordinal IN SELECT value,ord::integer FROM jsonb_array_elements(members) WITH ORDINALITY a(value,ord) LOOP
  IF (jsonb_typeof(member)='object' AND (SELECT count(*) FROM jsonb_object_keys(member))=10
   AND member ?& ARRAY['slot','preregistration_id','create_grant_id','tuple','request_sha256','preregistration_sha256','witness_sha256','enrollment_sha256','installation_sha256','receipt_sha256']
   AND jsonb_typeof(member->'slot')='number' AND member->>'slot' ~ '^[1-8]$'
   AND member->'slot'=to_jsonb(ordinal) AND jsonb_typeof(member->'tuple')='object'
   AND (SELECT count(*) FROM jsonb_object_keys(member->'tuple'))=11
   AND member->'tuple' ?& ARRAY['provider','integration_instance_id','instance_checksum','integration_type_id','type_checksum','scope_checksum','profile_checksum','profile','slot','resource_id','resource_created_at']
   AND jsonb_typeof(member#>'{tuple,slot}')='number' AND member#>>'{tuple,slot}' ~ '^[1-8]$'
   AND member#>'{tuple,slot}'=to_jsonb(ordinal)) IS NOT TRUE THEN RETURN false; END IF;
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['request_sha256','preregistration_sha256','witness_sha256','enrollment_sha256','installation_sha256','receipt_sha256']) k
    WHERE jsonb_typeof(member->k) IS DISTINCT FROM 'string' OR member->>k !~ '^[a-f0-9]{64}$') THEN RETURN false; END IF;
  SELECT * INTO pre FROM public.capacity_vm_provisioning_preregistrations WHERE id=(member->>'preregistration_id')::uuid;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT * INTO witness FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=pre.id;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT * INTO enrollment FROM public.capacity_vm_original_enrollments WHERE preregistration_id=pre.id;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT * INTO installation FROM public.capacity_guest_original_installations WHERE preregistration_id=pre.id;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT * INTO grant_row FROM public.capacity_mutation_grants WHERE id=pre.create_grant_id;
  IF NOT FOUND THEN RETURN false; END IF;
  pr=convert_from(pre.original_wire,'UTF8')::jsonb; wr=convert_from(witness.original_wire,'UTF8')::jsonb;
  receipt=convert_from(enrollment.receipt_wire,'UTF8')::jsonb; installed=convert_from(installation.original_wire,'UTF8')::jsonb;
  IF (pr=pre.preregistration_record AND convert_from(pre.binding_wire,'UTF8')::jsonb=policy.spec->'guest_retirement_binding'
   AND pre.id::text=member->>'preregistration_id' AND pre.create_grant_id::text=member->>'create_grant_id'
   AND pr->>'preregistration_id'=pre.id::text AND pr->>'original_create_grant_id'=pre.create_grant_id::text
   AND pr->'slot'=member->'slot' AND pr->>'original_create_request_sha256'=member->>'request_sha256'
   AND encode(sha256(pre.original_wire),'hex')=member->>'preregistration_sha256'
   AND witness.original_record=wr AND encode(sha256(witness.original_wire),'hex')=member->>'witness_sha256'
   AND witness.witness_sha256=member->>'witness_sha256' AND wr->>'preregistration_id'=pre.id::text
   AND wr->'tuple'=member->'tuple' AND wr->>'original_create_grant_id'=pre.create_grant_id::text
   AND wr->>'original_create_request_sha256'=member->>'request_sha256'
   AND receipt->>'preregistration_id'=pre.id::text AND receipt->'enrollment'=enrollment.enrollment_record
   AND receipt#>'{enrollment,statement,tuple}'=member->'tuple'
   AND enrollment.enrollment_sha256=member->>'enrollment_sha256'
   AND encode(sha256(enrollment.receipt_wire),'hex')=member->>'receipt_sha256'
   AND installation.confirmation_sha256=member->>'installation_sha256'
   AND encode(sha256(installation.original_wire),'hex')=member->>'installation_sha256'
   AND installed->>'preregistration_id'=pre.id::text AND installed->>'original_receipt_sha256'=member->>'receipt_sha256'
   AND installed->>'enrollment_sha256'=member->>'enrollment_sha256'
   AND (installed->>'installed_at')::timestamptz<=installation.recorded_at AND installation.recorded_at<=pre.original_deadline
   AND (wr->>'original_create_returned_at')::timestamptz<pre.original_deadline
   AND grant_row.namespace=dj->>'realm' AND grant_row.environment=dj->>'environment' AND grant_row.domain=dj->>'domain' AND grant_row.dimension=dj->>'dimension'
   AND grant_row.state='confirmed' AND NOT grant_row.grant_record ? 'authority_kind'
   AND grant_row.generation=(pr->>'generation')::bigint
   AND grant_row.grant_record->'generation'=pr->'generation' AND grant_row.grant_record->'fencing_token'=pr->'fence'
   AND grant_row.grant_record->>'lease_owner'=pr->>'lease_owner' AND grant_row.grant_record->>'executor_id'=pr->>'executor_id'
   AND grant_row.grant_record->>'policy_id'=pr->>'policy_id' AND grant_row.grant_record->>'policy_checksum'=pr->>'policy_checksum'
   AND grant_row.grant_record->>'workflow_id'=pr->>'workflow_id' AND grant_row.grant_record->>'attempt_id'=wr->>'original_create_attempt_id'
   AND grant_row.integration_instance_id::text=binding->>'integration_instance_id'
   AND grant_row.scope_checksum=binding->>'scope_checksum' AND grant_row.profile_name=binding->>'profile_name' AND grant_row.slot=ordinal
   AND grant_row.grant_record->'binding'=binding AND grant_row.grant_record#>>'{grant,grant_id}'=pre.create_grant_id::text
   AND grant_row.grant_record#>>'{grant,state}'='confirmed' AND grant_row.grant_record#>>'{grant,capability}'=binding->>'ensure_capability'
   AND coalesce(grant_row.grant_record#>>'{grant,compensation_of}','')=''
   AND grant_row.grant_record#>>'{grant,request_sha256}'=member->>'request_sha256'
   AND grant_row.grant_record#>>'{settlement,outcome}'='accepted' AND grant_row.grant_record#>'{settlement,transport_completed}'='true'::jsonb
   AND grant_row.grant_record#>>'{settlement,resource_id}'=member#>>'{tuple,resource_id}'
   AND grant_row.grant_record#>>'{settlement,resource_created_at}'=member#>>'{tuple,resource_created_at}'
   AND member#>>'{tuple,integration_instance_id}'=binding->>'integration_instance_id'
   AND member#>>'{tuple,instance_checksum}'=binding->>'integration_checksum'
   AND member#>>'{tuple,integration_type_id}'=binding->>'integration_type_id'
   AND member#>>'{tuple,type_checksum}'=binding->>'integration_type_checksum'
   AND member#>>'{tuple,scope_checksum}'=binding->>'scope_checksum' AND member#>>'{tuple,profile}'=binding->>'profile_name'
   AND member#>>'{tuple,resource_id}'<>'' AND member#>>'{tuple,provider}' IN('aws','hetzner')
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(policy.spec#>'{guest_retirement_binding,members}') x WHERE x->'slot'=member->'slot')) IS NOT TRUE THEN RETURN false; END IF;
  IF pr->'generation'=r->'generation' AND pr->'fence'=r->'fencing_token' THEN
   selected_count=selected_count+1; selected=pr;
   IF (ordinal=n AND pre.id::text=r->>'preregistration_id' AND pre.create_grant_id::text=r->>'create_grant_id'
    AND pr->>'policy_id'=r->>'policy_id' AND pr->>'policy_checksum'=r->>'policy_checksum'
    AND pr->>'workflow_id'=env#>>'{workflow,id}' AND pr->>'workflow_checksum'=env#>>'{workflow,checksum}'
    AND pr->>'lease_owner'=r->>'lease_owner' AND pr->>'executor_id'=r->>'executor_id'
    AND pre.created_at=(pr->>'reserved_at')::timestamptz AND pre.created_at>=(dj->>'started_at')::timestamptz
    AND pre.original_deadline=(pr->>'original_deadline')::timestamptz AND pre.created_at<pre.original_deadline
    AND pre.original_deadline<=(r->>'original_deadline')::timestamptz) IS NOT TRUE THEN RETURN false; END IF;
  END IF;
 END LOOP;
 IF selected_count<>1 THEN RETURN false; END IF;
 IF (jsonb_typeof(result)='object' AND result->>'status'='failed' AND jsonb_typeof(result->'steps')='array'
 AND jsonb_array_length(result->'steps')=7 AND result#>>'{workflow,id}'=env#>>'{workflow,id}'
 AND result#>>'{workflow,kind}'='workflow' AND result#>>'{workflow,namespace}'=env#>>'{workflow,namespace}'
 AND result#>>'{workflow,name}'=env#>>'{workflow,name}' AND result#>'{workflow,version}'=env#>'{workflow,version}') IS NOT TRUE THEN RETURN false; END IF;
 FOR step,ordinal IN SELECT value,ord::integer FROM jsonb_array_elements(result->'steps') WITH ORDINALITY a(value,ord) LOOP
  IF (step->>'id'=(ARRAY['plan-original-guest','provision-original-notify','retire-original-guest','refresh-original-membership','complete-original-provision','finish-original-retirement','complete-original-retirement'])[ordinal]
   AND step->>'kind'='yggdrasil'
   AND step->>'operation'=(ARRAY['capacity.plan_original_guest','capacity.provision_original_guest','capacity.retire_original_guest','capacity.complete_original_guest','capacity.complete_original_guest','capacity.finish_original_guest_retirement','capacity.complete_original_guest'])[ordinal]
   AND step->>'capability'=step->>'operation'
   AND step->>'status'=(ARRAY['succeeded','succeeded','skipped','skipped','failed','skipped','skipped'])[ordinal]
   AND NOT step ?| ARRAY['integration_instance','integration_type']
   AND (step->>'started_at')::timestamptz>=(rw->>'started_at')::timestamptz
   AND (step->>'finished_at')::timestamptz>=(step->>'started_at')::timestamptz
   AND (step->>'finished_at')::timestamptz<=(rw->>'finished_at')::timestamptz) IS NOT TRUE THEN RETURN false; END IF;
  IF ordinal IN(1,2,5) THEN
   IF step->'attempts' IS DISTINCT FROM '1'::jsonb THEN RETURN false; END IF;
  ELSE
   IF coalesce(step->'attempts','0'::jsonb) IS DISTINCT FROM '0'::jsonb THEN RETURN false; END IF;
   IF ordinal IN(3,4) THEN
    IF step->'metadata' IS DISTINCT FROM jsonb_build_object(
     'condition',CASE ordinal WHEN 3 THEN '{{ steps.plan-original-guest.metadata.mode }} == retire' ELSE '{{ steps.plan-original-guest.metadata.mode }} == refresh' END,
     'skip_reason','condition') THEN RETURN false; END IF;
   ELSIF coalesce(step->'metadata','{}'::jsonb)<>'{}'::jsonb THEN RETURN false; END IF;
  END IF;
 END LOOP;
 IF (result#>>'{steps,0,metadata,mode}'='provision' AND result#>'{steps,0,metadata,slot}'=to_jsonb(n)
 AND result#>'{steps,0,metadata,generation}'=r->'generation' AND result#>'{steps,0,metadata,fencing_token}'=r->'fencing_token'
 AND result#>>'{steps,0,metadata,lease_owner}'=r->>'lease_owner'
 AND result#>'{steps,1,metadata,preregistration}'=selected
 AND result#>'{steps,4,metadata}'='{"original_guest_reconcile_refusal_stage":"source_assessment"}'::jsonb
 AND result#>>'{steps,4,error}'='original Guest reconciliation held'
 AND (result#>>'{steps,0,finished_at}')::timestamptz<=(result#>>'{steps,1,started_at}')::timestamptz
 AND (result#>>'{steps,1,finished_at}')::timestamptz<(selected->>'original_deadline')::timestamptz
 AND (result#>>'{steps,4,started_at}')::timestamptz>=(result#>>'{steps,1,finished_at}')::timestamptz) IS NOT TRUE THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
-- +goose StatementEnd

CREATE TABLE IF NOT EXISTS public.capacity_dispatch_installed_provision_timeout_dispositions (
 id uuid PRIMARY KEY,
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
 original_record jsonb NOT NULL,
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 1048576),
 original_dispatch_wire bytea NOT NULL,
 original_run_wire bytea NOT NULL,
 original_intent_wire bytea NOT NULL,
 members_wire bytea NOT NULL,
 recorded_at timestamptz NOT NULL,
 CHECK(original_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(id::text=original_record->>'id' AND job_id::text=original_record->>'job_id' AND run_id::text=original_record->>'run_id'),
 CHECK(recorded_at=(original_record->>'recorded_at')::timestamptz)
);

ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v9_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v9_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v10_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v10_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v10_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v10_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_provision_timeout_insert() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE j public.capacity_dispatch_jobs; current_intent jsonb; policy public.manifests; member jsonb; n integer; occupied integer;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[j.realm,j.environment,j.domain,j.dimension]) v WHERE v IS NULL OR v !~ '^[ -~]+$' OR v ~ '[<>&]') THEN RAISE EXCEPTION 'installed timeout requires exact scope encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[j.realm,j.environment,j.domain,j.dimension])::text,0));
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT policy FROM public.manifests WHERE id=(NEW.original_record->>'policy_id')::uuid FOR SHARE;
 SELECT intent INTO STRICT current_intent FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension FOR UPDATE;
 PERFORM id FROM public.workflow_runs WHERE id=NEW.run_id FOR SHARE;
 PERFORM slot FROM public.capacity_resource_slots WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE;
 PERFORM id FROM public.capacity_mutation_grants WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY id FOR SHARE;
 IF j.state<>'unknown' OR j.finalization_ack_at IS NOT NULL OR j.run_id<>NEW.run_id OR NOT policy.active
 OR current_intent IS DISTINCT FROM convert_from(NEW.original_intent_wire,'UTF8')::jsonb
 OR to_jsonb(j) IS DISTINCT FROM convert_from(NEW.original_dispatch_wire,'UTF8')::jsonb
 OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 OR j.lease_expires_at>NEW.recorded_at OR (current_intent->>'lease_expires_at')::timestamptz>NEW.recorded_at
 OR public.installed_provision_timeout_valid(NEW.original_record,NEW.original_dispatch_wire,NEW.original_run_wire,NEW.original_intent_wire,NEW.members_wire) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'installed timeout requires exact expired installed original'; END IF;
 n=jsonb_array_length(NEW.original_record->'members');
 SELECT count(*) INTO occupied FROM public.capacity_resource_slots WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension AND resource_id<>'' AND slot_record->'tombstone'='false'::jsonb;
 IF occupied<>n OR EXISTS(SELECT 1 FROM public.capacity_resource_slots s WHERE s.namespace=j.realm AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension
  AND (s.slot_record ? 'authority_kind' OR s.resource_id<>'' AND s.slot_record->'tombstone'='false'::jsonb AND NOT EXISTS(
   SELECT 1 FROM jsonb_array_elements(NEW.original_record->'members') x WHERE s.integration_instance_id::text=x#>>'{tuple,integration_instance_id}' AND s.scope_checksum=x#>>'{tuple,scope_checksum}' AND s.profile_name=x#>>'{tuple,profile}' AND s.slot=(x->>'slot')::integer
   AND s.resource_id=x#>>'{tuple,resource_id}' AND s.slot_record->>'resource_id'=s.resource_id AND s.slot_record->>'resource_created_at'=x#>>'{tuple,resource_created_at}' AND s.slot_record->>'desired_spec_sha256'=x->>'request_sha256')))
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND NOT(g.grant_record ? 'authority_kind') AND g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension AND g.state IN('issued','redeemed','settled','compensating'))
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension AND g.generation=(NEW.original_record->>'generation')::bigint AND NOT(g.grant_record ? 'authority_kind') AND g.id::text<>NEW.original_record->>'create_grant_id')
 OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=policy.id AND c.generation=(NEW.original_record->>'generation')::bigint AND c.fence=(NEW.original_record->>'fencing_token')::bigint AND c.lease_owner::text=NEW.original_record->>'lease_owner' AND c.executor_id::text=NEW.original_record->>'executor_id')
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents t JOIN jsonb_array_elements(NEW.original_record->'members') x ON t.preregistration_id::text=x->>'preregistration_id')
 THEN RAISE EXCEPTION 'installed timeout requires complete installed roster without new effects'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_installed_provision_timeout_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE receipt public.capacity_dispatch_installed_provision_timeout_dispositions;
BEGIN
 IF old_row.state='installed_timeout_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'installed timeout terminal is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'unknown' OR new_row.state<>'installed_timeout_disposed' OR old_row.finalization_ack_at IS NOT NULL
 OR (to_jsonb(new_row)-ARRAY['state','updated_at']) IS DISTINCT FROM(to_jsonb(old_row)-ARRAY['state','updated_at'])
 THEN RAISE EXCEPTION 'installed timeout must preserve original dispatch'; END IF;
 SELECT * INTO STRICT receipt FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE job_id=old_row.id AND run_id=old_row.run_id;
 IF convert_from(receipt.original_dispatch_wire,'UTF8')::jsonb IS DISTINCT FROM to_jsonb(old_row) OR new_row.updated_at IS DISTINCT FROM receipt.recorded_at
 THEN RAISE EXCEPTION 'installed timeout requires same transaction receipt'; END IF;
 RETURN new_row;
END; $$;
-- +goose StatementEnd

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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_provision_timeout_job_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='installed_timeout_disposed' THEN RAISE EXCEPTION 'installed timeout requires retained original job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.immutable_installed_provision_timeout() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'installed timeout disposition is immutable'; END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_provision_timeout_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_installed_provision_timeout_dispositions WHERE run_id=OLD.id) AND (TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'installed timeout original workflow is immutable'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.require_installed_provision_timeout_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; original jsonb; successor public.capacity_dispatch_jobs;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 original=convert_from(NEW.original_dispatch_wire,'UTF8')::jsonb;
 IF j.state<>'installed_timeout_disposed' OR j.finalization_ack_at IS NOT NULL OR j.run_id<>NEW.run_id
 OR j.updated_at IS DISTINCT FROM NEW.recorded_at
 OR (to_jsonb(j)-ARRAY['state','updated_at']) IS DISTINCT FROM(original-ARRAY['state','updated_at'])
 OR public.installed_provision_timeout_valid(NEW.original_record,NEW.original_dispatch_wire,NEW.original_run_wire,NEW.original_intent_wire,NEW.members_wire) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'installed timeout requires terminal job and unchanged originals in same commit'; END IF;
 SELECT * INTO STRICT successor FROM public.capacity_dispatch_jobs s WHERE s.realm=j.realm AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension AND s.state='queued';
 IF successor.id=j.id OR successor.run_id=j.run_id OR successor.source_tick=j.source_tick
 OR (successor.envelope::jsonb-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256']) IS DISTINCT FROM(j.envelope::jsonb-ARRAY['job_id','run_id','source_tick','metadata','metadata_sha256'])
 OR ((successor.envelope::jsonb->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id']) IS DISTINCT FROM((j.envelope::jsonb->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id'])
 OR successor.envelope::jsonb#>>'{metadata,capacity_dispatch_job_id}'<>successor.id::text
 THEN RAISE EXCEPTION 'installed timeout requires distinct queued readiness successor'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_installed_timeout_origin() RETURNS trigger LANGUAGE plpgsql AS $$
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
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_installed_provision_timeout_dispositions'::regclass AND tgname='installed_timeout_insert') THEN
  CREATE TRIGGER installed_timeout_insert BEFORE INSERT ON public.capacity_dispatch_installed_provision_timeout_dispositions FOR EACH ROW EXECUTE FUNCTION public.guard_installed_provision_timeout_insert();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_installed_provision_timeout_dispositions'::regclass AND tgname='installed_timeout_immutable') THEN
  CREATE TRIGGER installed_timeout_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_installed_provision_timeout_dispositions FOR EACH ROW EXECUTE FUNCTION public.immutable_installed_provision_timeout();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_installed_provision_timeout_dispositions'::regclass AND tgname='installed_timeout_complete_links') THEN
  CREATE CONSTRAINT TRIGGER installed_timeout_complete_links AFTER INSERT ON public.capacity_dispatch_installed_provision_timeout_dispositions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_installed_provision_timeout_links();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_jobs'::regclass AND tgname='installed_timeout_job_insert') THEN
  CREATE TRIGGER installed_timeout_job_insert BEFORE INSERT ON public.capacity_dispatch_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_installed_provision_timeout_job_insert();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.workflow_runs'::regclass AND tgname='installed_timeout_workflow_immutable') THEN
  CREATE TRIGGER installed_timeout_workflow_immutable BEFORE UPDATE OR DELETE ON public.workflow_runs FOR EACH ROW EXECUTE FUNCTION public.guard_installed_provision_timeout_workflow();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_intents'::regclass AND tgname='installed_timeout_readiness_origin') THEN
  CREATE TRIGGER installed_timeout_readiness_origin BEFORE INSERT OR UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION public.guard_installed_timeout_origin();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_installed_provision_timeout_dispositions)
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs WHERE state='installed_timeout_disposed')
 OR EXISTS(SELECT 1 FROM public.capacity_intents WHERE intent->'installed_guest_reconcile' ? 'installed_provision_timeout_disposition_id')
 THEN RAISE EXCEPTION 'installed timeout provenance is retained; rollback refused'; END IF;
END; $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS installed_timeout_readiness_origin ON public.capacity_intents;
DROP TRIGGER IF EXISTS installed_timeout_workflow_immutable ON public.workflow_runs;
DROP TRIGGER IF EXISTS installed_timeout_job_insert ON public.capacity_dispatch_jobs;
DROP FUNCTION IF EXISTS public.guard_installed_timeout_origin();
DROP TRIGGER IF EXISTS installed_timeout_complete_links ON public.capacity_dispatch_installed_provision_timeout_dispositions;
DROP TRIGGER IF EXISTS installed_timeout_immutable ON public.capacity_dispatch_installed_provision_timeout_dispositions;
DROP TRIGGER IF EXISTS installed_timeout_insert ON public.capacity_dispatch_installed_provision_timeout_dispositions;
DROP FUNCTION IF EXISTS public.require_installed_provision_timeout_links();
DROP FUNCTION IF EXISTS public.guard_installed_provision_timeout_workflow();
DROP FUNCTION IF EXISTS public.immutable_installed_provision_timeout();
DROP FUNCTION IF EXISTS public.guard_installed_provision_timeout_job_insert();
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
DROP FUNCTION IF EXISTS public.check_installed_provision_timeout_transition(public.capacity_dispatch_jobs,public.capacity_dispatch_jobs);
DROP TABLE IF EXISTS public.capacity_dispatch_installed_provision_timeout_dispositions;
DROP FUNCTION IF EXISTS public.guard_installed_provision_timeout_insert();
DROP FUNCTION IF EXISTS public.installed_provision_timeout_valid(jsonb,bytea,bytea,bytea,bytea);
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v10_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v10_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v9_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v9_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));
