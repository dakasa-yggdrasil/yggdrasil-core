-- +goose Up
-- A failed SDK-accepted expansion is not an enrolled Guest retirement and is
-- not a never-started original. The parent remains SETTLED and reserved while
-- exactly one separately admitted child owns the canonical provider cleanup.
CREATE TABLE IF NOT EXISTS public.capacity_failed_unwitnessed_expansion_cleanups (
 id uuid PRIMARY KEY,
 grant_id uuid NOT NULL UNIQUE REFERENCES public.capacity_mutation_grants(id),
 child_grant_id uuid NOT NULL UNIQUE,
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 preregistration_id uuid NOT NULL UNIQUE REFERENCES public.capacity_vm_provisioning_preregistrations(id),
 namespace text NOT NULL, environment text NOT NULL, domain text NOT NULL, dimension text NOT NULL,
 policy_id uuid NOT NULL REFERENCES public.manifests(id), policy_checksum text NOT NULL CHECK(policy_checksum ~ '^[0-9a-f]{64}$'),
 slot integer NOT NULL CHECK(slot BETWEEN 2 AND 8),
 admission_sha256 text NOT NULL UNIQUE CHECK(admission_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),
 recorded_at timestamptz NOT NULL,
 UNIQUE(id,child_grant_id), CHECK(grant_id<>child_grant_id),
 CHECK(original_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(admission_sha256=encode(sha256(original_wire),'hex')),
 CHECK(original_record->>'schema' IS NOT DISTINCT FROM 'failed_unwitnessed_expansion_cleanup_v1'),
 CHECK(original_record->>'id' IS NOT DISTINCT FROM id::text),
 CHECK(original_record->>'grant_id' IS NOT DISTINCT FROM grant_id::text),
 CHECK(original_record->>'child_grant_id' IS NOT DISTINCT FROM child_grant_id::text),
 CHECK(original_record->>'job_id' IS NOT DISTINCT FROM job_id::text),
 CHECK(original_record->>'preregistration_id' IS NOT DISTINCT FROM preregistration_id::text),
 CHECK(original_record->>'namespace' IS NOT DISTINCT FROM namespace),
 CHECK(original_record->>'environment' IS NOT DISTINCT FROM environment),
 CHECK(original_record->>'domain' IS NOT DISTINCT FROM domain),
 CHECK(original_record->>'dimension' IS NOT DISTINCT FROM dimension),
 CHECK(original_record->>'policy_id' IS NOT DISTINCT FROM policy_id::text),
 CHECK(original_record->>'policy_checksum' IS NOT DISTINCT FROM policy_checksum),
 CHECK((original_record->>'slot')::integer IS NOT DISTINCT FROM slot),
 CHECK((original_record->>'recorded_at')::timestamptz IS NOT DISTINCT FROM recorded_at)
);
CREATE TABLE IF NOT EXISTS public.capacity_failed_unwitnessed_expansion_cleanup_events (
 cleanup_id uuid NOT NULL REFERENCES public.capacity_failed_unwitnessed_expansion_cleanups(id),
 sequence bigint NOT NULL CHECK(sequence>=1),
 stage text NOT NULL CHECK(stage IN('requested','claimed','inventory_prepared','inventory_returned','inventory_qualified','issued','possible_send','pending_absence','absence_prepared','absence_returned','absence_complete','terminal')),
 run_id uuid REFERENCES public.workflow_runs(id), child_grant_id uuid NOT NULL,
 event_sha256 text NOT NULL CHECK(event_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),
 recorded_at timestamptz NOT NULL,
 PRIMARY KEY(cleanup_id,sequence),
 FOREIGN KEY(cleanup_id,child_grant_id) REFERENCES public.capacity_failed_unwitnessed_expansion_cleanups(id,child_grant_id),
 CHECK(original_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(event_sha256=encode(sha256(original_wire),'hex')),
 CHECK(original_record->>'schema' IS NOT DISTINCT FROM 'failed_unwitnessed_expansion_cleanup_v1'),
 CHECK(original_record->>'cleanup_id' IS NOT DISTINCT FROM cleanup_id::text),
 CHECK((original_record->>'sequence')::bigint IS NOT DISTINCT FROM sequence),
 CHECK(original_record->>'stage' IS NOT DISTINCT FROM stage),
 CHECK(original_record->>'run_id' IS NOT DISTINCT FROM run_id::text),
 CHECK(original_record->>'child_grant_id' IS NOT DISTINCT FROM child_grant_id::text),
 CHECK((original_record->>'recorded_at')::timestamptz IS NOT DISTINCT FROM recorded_at)
);
ALTER TABLE public.capacity_mutation_grants ADD COLUMN IF NOT EXISTS failed_unwitnessed_expansion_cleanup_id uuid;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT failed_unwitnessed_expansion_exact_child_fk
 FOREIGN KEY(failed_unwitnessed_expansion_cleanup_id,id) REFERENCES public.capacity_failed_unwitnessed_expansion_cleanups(id,child_grant_id);
ALTER TABLE public.capacity_mutation_grants DROP CONSTRAINT capacity_mutation_grants_state_check;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_mutation_grants_state_check
 CHECK(state IN('issued','redeemed','settled','confirmed','rejected','expired','compensating','compensated','cleanup_closed'));
-- Only the FK-joined child is exempt. The SETTLED parent continues to occupy
-- the ordinary unique slot and all ordinary pending-authority counts.
DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled') AND original_disposition_id IS NULL
 AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL
 AND enrolled_failed_disposition_id IS NULL AND failed_unwitnessed_expansion_cleanup_id IS NULL;

-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent_row public.capacity_mutation_grants; pre_row public.capacity_vm_provisioning_preregistrations;
 job_row public.capacity_dispatch_jobs; intent_wire jsonb; policy_row public.manifests;
 run_row public.workflow_runs; sdk jsonb; original_doc jsonb; survivor_count integer;
BEGIN
 SELECT * INTO STRICT parent_row FROM public.capacity_mutation_grants WHERE id=NEW.grant_id FOR SHARE;
 SELECT * INTO STRICT pre_row FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id FOR SHARE;
 SELECT * INTO STRICT job_row FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR SHARE;
 SELECT * INTO STRICT run_row FROM public.workflow_runs WHERE id=job_row.run_id FOR SHARE;
 SELECT * INTO STRICT policy_row FROM public.manifests WHERE id=NEW.policy_id FOR SHARE;
 SELECT ci.intent INTO STRICT intent_wire FROM public.capacity_intents ci WHERE ci.namespace=NEW.namespace AND ci.environment=NEW.environment AND ci.domain=NEW.domain AND ci.dimension=NEW.dimension FOR SHARE;
 sdk:=parent_row.grant_record#>'{settlement,original_provider_create_return}'; original_doc:=NEW.original_record;
 IF parent_row.state IS DISTINCT FROM 'settled' OR parent_row.slot<>NEW.slot
 OR parent_row.namespace<>NEW.namespace OR parent_row.environment<>NEW.environment OR parent_row.domain<>NEW.domain OR parent_row.dimension<>NEW.dimension
 OR num_nonnulls(parent_row.original_disposition_id,parent_row.failed_original_disposition_id,parent_row.native_denied_disposition_id,parent_row.enrolled_failed_disposition_id,parent_row.failed_unwitnessed_expansion_cleanup_id)<>0
 OR COALESCE(parent_row.grant_record#>>'{grant,compensation_of}','')<>''
 OR parent_row.grant_record#>>'{settlement,outcome}' IS DISTINCT FROM 'accepted'
 OR parent_row.grant_record#>>'{settlement,transport_completed}' IS DISTINCT FROM 'true'
 OR sdk->>'schema' IS DISTINCT FROM 'aws_original_run_instances_return_v1'
 OR sdk->>'response_status' IS DISTINCT FROM '200'
 OR sdk->>'provider' IS DISTINCT FROM 'aws'
 OR sdk->>'adapter_source_commit' IS DISTINCT FROM 'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
 OR sdk->>'grant_id' IS DISTINCT FROM NEW.grant_id::text
 OR sdk->>'attempt_id' IS DISTINCT FROM parent_row.grant_record->>'attempt_id'
 OR sdk->>'request_sha256' IS DISTINCT FROM parent_row.grant_record#>>'{grant,request_sha256}'
 OR sdk->>'resource_id' IS DISTINCT FROM original_doc->>'resource_id'
 OR sdk->>'resource_created_at' IS DISTINCT FROM original_doc->>'resource_created_at'
 OR original_doc->>'original_grant_sha256' IS DISTINCT FROM encode(sha256(convert_to(parent_row.grant_record::text,'UTF8')),'hex')
 OR original_doc->>'original_SDK_return_sha256' IS DISTINCT FROM encode(sha256(convert_to(sdk::text,'UTF8')),'hex')
 OR original_doc->>'original_preregistration_sha256' IS DISTINCT FROM encode(sha256(pre_row.original_wire),'hex')
 OR original_doc->>'original_dispatch_sha256' IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(job_row)::text,'UTF8')),'hex')
 OR original_doc->>'original_run_sha256' IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(run_row)::text,'UTF8')),'hex')
 OR original_doc->>'original_intent_sha256' IS DISTINCT FROM encode(sha256(convert_to(intent_wire::text,'UTF8')),'hex')
 OR pre_row.create_grant_id<>NEW.grant_id OR pre_row.original_deadline>=clock_timestamp()
 OR policy_row.kind<>'capacity_policy' OR NOT policy_row.active OR policy_row.checksum<>NEW.policy_checksum
 OR policy_row.namespace IS DISTINCT FROM NEW.namespace
 OR NOT EXISTS(SELECT 1 FROM public.manifests latest WHERE latest.id=NEW.policy_id AND latest.checksum=NEW.policy_checksum AND latest.active AND latest.id=(SELECT id FROM public.manifests WHERE kind='capacity_policy' AND namespace=policy_row.namespace AND name=policy_row.name ORDER BY version DESC,id DESC LIMIT 1))
 OR original_doc->>'original_auxiliary_inventory_complete' IS DISTINCT FROM COALESCE(parent_row.grant_record#>>'{settlement,auxiliary_inventory_complete}','false')
 OR encode(sha256(decode(original_doc->>'original_intent_wire','base64')),'hex') IS DISTINCT FROM original_doc->>'original_intent_sha256'
 OR convert_from(decode(original_doc->>'original_intent_wire','base64'),'UTF8')::jsonb IS DISTINCT FROM intent_wire
 OR original_doc->>'survivor_roster_sha256' IS DISTINCT FROM encode(sha256(decode(original_doc->>'survivor_roster_wire','base64')),'hex')
 OR convert_from(decode(original_doc->>'survivor_roster_wire','base64'),'UTF8')::jsonb IS DISTINCT FROM (SELECT COALESCE(jsonb_agg(s.slot_record ORDER BY s.slot),'[]'::jsonb) FROM public.capacity_resource_slots s WHERE s.namespace=NEW.namespace AND s.environment=NEW.environment AND s.domain=NEW.domain AND s.dimension=NEW.dimension AND s.resource_id<>'')
 OR intent_wire ? 'failed_unwitnessed_expansion_cleanup_id'
 OR intent_wire->>'recovery_only' IS DISTINCT FROM 'false'
 OR COALESCE(intent_wire->>'floor_degraded','false')<>'false'
 OR intent_wire ?| ARRAY['retirement_forward','failed_serving_disposal','failed_installed_disposal','installed_guest_reconcile']
 OR (policy_row.spec->>'floor')::integer IS DISTINCT FROM 1
 OR intent_wire->>'policy_id' IS DISTINCT FROM NEW.policy_id::text OR intent_wire->>'policy_checksum' IS DISTINCT FROM NEW.policy_checksum
 OR intent_wire->>'phase' IS DISTINCT FROM 'preparing'
 OR (intent_wire->>'generation')::bigint IS DISTINCT FROM (original_doc->>'original_generation')::bigint
 OR (intent_wire->>'fencing_token')::bigint IS DISTINCT FROM (original_doc->>'original_fencing_token')::bigint
 OR (intent_wire->>'lease_expires_at')::timestamptz>=clock_timestamp()
 OR (intent_wire#>>'{baseline_snapshot,units}')::integer IS DISTINCT FROM NEW.slot-1
 OR (intent_wire#>>'{assessment,snapshot,units}')::integer IS DISTINCT FROM NEW.slot-1
 OR job_row.state IS DISTINCT FROM 'returned' OR job_row.return_status IS DISTINCT FROM 'failed'
 OR job_row.finalization_ack_at IS NULL OR job_row.finalization_ack_at<job_row.returned_at
 OR run_row.status IS DISTINCT FROM 'failed' OR run_row.finished_at IS DISTINCT FROM job_row.returned_at
 OR original_doc->>'run_id' IS DISTINCT FROM job_row.run_id::text
 OR job_row.realm<>NEW.namespace OR job_row.environment<>NEW.environment OR job_row.domain<>NEW.domain OR job_row.dimension<>NEW.dimension
 OR job_row.lease_expires_at>=clock_timestamp() OR pre_row.created_at NOT BETWEEN job_row.started_at AND job_row.returned_at
 OR job_row.envelope::jsonb#>>'{policy,id}' IS DISTINCT FROM NEW.policy_id::text
 OR job_row.envelope::jsonb#>>'{policy,checksum}' IS DISTINCT FROM NEW.policy_checksum
 OR job_row.envelope::jsonb#>>'{workflow,id}' IS DISTINCT FROM original_doc->>'workflow_id'
 OR job_row.envelope::jsonb#>>'{workflow,checksum}' IS DISTINCT FROM original_doc->>'workflow_checksum'
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=NEW.namespace AND j.environment=NEW.environment AND j.domain=NEW.domain AND j.dimension=NEW.dimension AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL))
 OR EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.workflow_namespace=(SELECT namespace FROM public.manifests WHERE id=(original_doc->>'workflow_id')::uuid) AND w.workflow_name=(SELECT name FROM public.manifests WHERE id=(original_doc->>'workflow_id')::uuid) AND(COALESCE(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(run_row.result->'steps') step WHERE step->>'status'='failed' AND step#>>'{metadata,original_guest_refusal_predicate}'='original-guest-step-25')
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=pre_row.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=pre_row.id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=pre_row.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=pre_row.id)
 OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=NEW.grant_id)
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=NEW.grant_id::text)
 THEN RAISE EXCEPTION 'failed unwitnessed expansion admission refused'; END IF;
 SELECT count(*) INTO survivor_count FROM public.capacity_resource_slots s WHERE s.namespace=NEW.namespace AND s.environment=NEW.environment AND s.domain=NEW.domain AND s.dimension=NEW.dimension AND s.resource_id<>'';
 IF survivor_count<>NEW.slot-1 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots s WHERE s.namespace=NEW.namespace AND s.environment=NEW.environment AND s.domain=NEW.domain AND s.dimension=NEW.dimension AND s.resource_id<>'' AND(s.slot<1 OR s.slot>=NEW.slot OR s.resource_id=original_doc->>'resource_id'))
 THEN RAISE EXCEPTION 'failed expansion survivor roster refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- Closed read proof for the separately qualified read-only observer. This is
-- not CREATE inventory knowledge; it authenticates the new normal DESTROY's
-- exact accepted settlement and every one of its sealed paid auxiliaries.
-- +goose StatementBegin
CREATE FUNCTION public.failed_expansion_absence_read_valid(r jsonb,a jsonb) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE c jsonb:=r->'read'; receipt jsonb:=r->'receipt'; o jsonb:=r->'observation'; h jsonb; aux jsonb; n integer; child public.capacity_mutation_grants; settlement jsonb; sdk jsonb; expected_receipt jsonb;
BEGIN
 h:=convert_from(decode(r->>'original_observer_return','base64'),'UTF8')::jsonb;
 SELECT * INTO STRICT child FROM public.capacity_mutation_grants WHERE id=(a->>'child_grant_id')::uuid;
 settlement:=child.grant_record->'settlement';sdk:=settlement->'original_provider_destroy_return';
 expected_receipt:=jsonb_strip_nulls(jsonb_build_object('grant',child.grant_record->'grant','attempt_id',child.grant_record->'attempt_id','outcome',settlement->'outcome','transport_completed',settlement->'transport_completed','resource_id',settlement->'resource_id','resource_created_at',settlement->'resource_created_at','action_id',settlement->'action_id','next_action_ids',CASE WHEN jsonb_array_length(settlement->'next_action_ids')>0 THEN settlement->'next_action_ids' END,'auxiliary_resources',settlement->'auxiliary_resources','auxiliary_inventory_complete',settlement->'auxiliary_inventory_complete'));
 IF (child.state IS DISTINCT FROM 'settled' OR child.failed_unwitnessed_expansion_cleanup_id::text IS DISTINCT FROM a->>'id'
 OR receipt IS DISTINCT FROM expected_receipt
 OR sdk->>'schema' IS DISTINCT FROM 'aws_original_terminate_instances_return_v1' OR sdk->>'provider' IS DISTINCT FROM 'aws'
 OR sdk->>'adapter_source_commit' IS DISTINCT FROM 'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
 OR sdk->>'response_status' IS DISTINCT FROM '200' OR sdk->>'grant_id' IS DISTINCT FROM a->>'child_grant_id'
 OR sdk->>'attempt_id' IS DISTINCT FROM child.grant_record->>'attempt_id' OR sdk->>'request_sha256' IS DISTINCT FROM child.grant_record#>>'{grant,request_sha256}'
 OR sdk->>'resource_id' IS DISTINCT FROM a->>'resource_id' OR sdk->>'resource_created_at' IS DISTINCT FROM a->>'resource_created_at'
 OR sdk->>'action_id' IS DISTINCT FROM settlement->>'action_id' OR sdk->>'response_body_sha256' !~ '^[0-9a-f]{64}$'
 OR (sdk->>'response_bytes')::bigint NOT BETWEEN 2 AND 2097152 OR (sdk->>'returned_at')::timestamptz<(sdk->>'called_at')::timestamptz
 OR (sdk->>'returned_at')::timestamptz>=(sdk->>'context_deadline')::timestamptz) IS NOT FALSE THEN RETURN false; END IF;

 IF (r->>'schema' IS DISTINCT FROM 'failed_unwitnessed_expansion_native_return_v1'
 OR r->>'status' IS DISTINCT FROM 'observed' OR r->>'call_failed' IS DISTINCT FROM 'false' OR r->>'original_context_failed' IS DISTINCT FROM 'false'
 OR c->>'schema' IS DISTINCT FROM 'failed_unwitnessed_expansion_native_read_v1' OR c->>'kind' IS DISTINCT FROM 'absence'
 OR c->>'cleanup_id' IS DISTINCT FROM a->>'id' OR c->>'child_grant_id' IS DISTINCT FROM a->>'child_grant_id'
 OR (c->>'original_deadline_core')::timestamptz<=(c->>'issued_at_core')::timestamptz
 OR (c->>'original_deadline_core')::timestamptz>(c->>'issued_at_core')::timestamptz+interval '5 seconds'
 OR (r->>'started_at_core')::timestamptz<(c->>'issued_at_core')::timestamptz
 OR (r->>'returned_at_core')::timestamptz<(r->>'started_at_core')::timestamptz
 OR (r->>'returned_at_core')::timestamptz>=(c->>'original_deadline_core')::timestamptz
 OR convert_from(decode(r->>'read_wire','base64'),'UTF8')::jsonb IS DISTINCT FROM c
 OR convert_from(decode(r->>'receipt_wire','base64'),'UTF8')::jsonb IS DISTINCT FROM receipt
 OR jsonb_typeof(h) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(h))<>7
 OR h->>'schema' IS DISTINCT FROM 'original_settled_retirement_absence_read_return_v1'
 OR h->>'observer_source_commit' IS DISTINCT FROM 'd8cbbf48873d24439216f98c30afe2669a525b54'
 OR r->>'observer_source_commit' IS DISTINCT FROM h->>'observer_source_commit'
 OR h->>'original_adapter_source_commit' IS DISTINCT FROM 'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
 OR h->>'read_id' IS DISTINCT FROM c->>'read_id'
 OR h->>'read_sha256' IS DISTINCT FROM encode(sha256(decode(r->>'read_wire','base64')),'hex')
 OR h->>'original_receipt_sha256' IS DISTINCT FROM encode(sha256(decode(r->>'receipt_wire','base64')),'hex')
 OR h->'observation' IS DISTINCT FROM o
 OR receipt#>>'{grant,grant_id}' IS DISTINCT FROM a->>'child_grant_id'
 OR receipt#>>'{grant,state}' IS DISTINCT FROM 'settled' OR COALESCE(receipt#>>'{grant,compensation_of}','')<>''
 OR receipt->>'outcome' IS DISTINCT FROM 'accepted' OR receipt->>'transport_completed' IS DISTINCT FROM 'true'
 OR receipt->>'resource_id' IS DISTINCT FROM a->>'resource_id' OR receipt->>'resource_created_at' IS DISTINCT FROM a->>'resource_created_at'
 OR receipt->>'auxiliary_inventory_complete' IS DISTINCT FROM 'true' OR jsonb_array_length(receipt->'auxiliary_resources') IS DISTINCT FROM 2
 OR o->>'destroy_grant_id' IS DISTINCT FROM a->>'child_grant_id' OR o->>'destroy_grant_state' IS DISTINCT FROM 'settled'
 OR o->>'id' IS DISTINCT FROM a->>'resource_id' OR o->>'created_at' IS DISTINCT FROM a->>'resource_created_at'
 OR o->>'original_outcome' IS DISTINCT FROM 'accepted' OR o->>'original_transport_completed' IS DISTINCT FROM 'true'
 OR o->>'auxiliary_inventory_complete' IS DISTINCT FROM 'true' OR jsonb_array_length(o->'auxiliary_resources') IS DISTINCT FROM 2
 OR o#>>'{aws_retirement_lifecycle,schema}' IS DISTINCT FROM 'aws_original_terminate_and_native_absence_v1'
 OR o#>>'{aws_retirement_lifecycle,request_id}' IS DISTINCT FROM receipt->>'action_id'
) IS NOT FALSE THEN RETURN false; END IF;
 FOR n IN 0..1 LOOP
 aux:=receipt->'auxiliary_resources'->n;
 IF aux->>'kind' NOT IN('aws_ebs_volume','aws_network_interface') OR aux->>'requires_absence' IS DISTINCT FROM 'true'
 OR aux->>'id' IS NULL OR o#>>ARRAY['auxiliary_resources',n::text,'kind'] IS DISTINCT FROM aux->>'kind'
 OR o#>>ARRAY['auxiliary_resources',n::text,'id'] IS DISTINCT FROM aux->>'id'
 THEN RETURN false; END IF;
 END LOOP;
 IF receipt#>>'{auxiliary_resources,0,kind}'=receipt#>>'{auxiliary_resources,1,kind}' THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN others THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a public.capacity_failed_unwitnessed_expansion_cleanups; previous public.capacity_failed_unwitnessed_expansion_cleanup_events;
 claim public.capacity_failed_unwitnessed_expansion_cleanup_events; intent_doc jsonb; doc jsonb:=NEW.original_record; r jsonb:=NEW.original_record->'evidence';
 child public.capacity_mutation_grants; prepared public.capacity_failed_unwitnessed_expansion_cleanup_events; count_rows bigint; actual_now timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO STRICT a FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE id=NEW.cleanup_id FOR UPDATE;
 SELECT count(*) INTO count_rows FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id;
 IF NEW.sequence<>count_rows+1 OR NEW.recorded_at>actual_now+interval '1 second'
 OR EXISTS(SELECT 1 FROM jsonb_object_keys(doc) k WHERE k<>ALL(ARRAY['schema','cleanup_id','sequence','stage','run_id','generation','fencing_token','lease_owner','executor_id','lease_expires_at','child_grant_id','evidence','recorded_at']))
 THEN RAISE EXCEPTION 'failed expansion event sequence or closed fields refused'; END IF;
 SELECT * INTO previous FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id ORDER BY sequence DESC LIMIT 1;
 IF previous.stage='terminal' THEN RAISE EXCEPTION 'failed expansion terminal is closed'; END IF;
 SELECT ci.intent INTO STRICT intent_doc FROM public.capacity_intents ci WHERE ci.namespace=a.namespace AND ci.environment=a.environment AND ci.domain=a.domain AND ci.dimension=a.dimension FOR UPDATE;
 IF NEW.stage='requested' THEN
  IF NEW.sequence<>1 OR NEW.run_id IS NOT NULL OR intent_doc ? 'failed_unwitnessed_expansion_cleanup_id'
  OR encode(sha256(convert_to(intent_doc::text,'UTF8')),'hex') IS DISTINCT FROM a.original_record->>'original_intent_sha256'
  THEN RAISE EXCEPTION 'failed expansion requested original refused'; END IF;
  RETURN NEW;
 END IF;
 IF intent_doc->>'failed_unwitnessed_expansion_cleanup_id' IS DISTINCT FROM a.id::text
 OR intent_doc#>>'{decision,reason}' IS DISTINCT FROM 'failed_unwitnessed_expansion_cleanup'
 THEN RAISE EXCEPTION 'failed expansion typed current frame required'; END IF;
 IF NEW.stage='claimed' THEN
  IF (intent_doc->>'lease_expires_at')::timestamptz>=actual_now OR NEW.run_id IS NULL
  OR (doc->>'generation')::bigint IS DISTINCT FROM (intent_doc->>'generation')::bigint
  OR (doc->>'fencing_token')::bigint IS DISTINCT FROM (intent_doc->>'fencing_token')::bigint+1
  OR (doc->>'lease_expires_at')::timestamptz<=actual_now
  OR NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
   WHERE j.run_id=NEW.run_id AND j.state='started' AND j.returned_at IS NULL AND j.finalization_ack_at IS NULL
   AND w.status='running' AND w.finished_at IS NULL AND j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension
   AND j.envelope::jsonb#>>'{workflow,id}'=a.original_record->>'workflow_id' AND j.envelope::jsonb#>>'{workflow,checksum}'=a.original_record->>'workflow_checksum'
   AND j.envelope::jsonb#>>'{policy,id}'=a.policy_id::text AND j.envelope::jsonb#>>'{policy,checksum}'=a.policy_checksum)
  OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension AND j.run_id IS DISTINCT FROM NEW.run_id AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL))
  THEN RAISE EXCEPTION 'failed expansion genuine new claim refused'; END IF;
  IF previous.stage<>'requested' AND(previous.stage NOT IN('pending_absence','absence_complete') OR public.failed_expansion_absence_read_valid(previous.original_record->'evidence',a.original_record) IS NOT TRUE
   OR NOT EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events c JOIN public.capacity_dispatch_jobs j ON j.run_id=c.run_id JOIN public.workflow_runs w ON w.id=j.run_id
    WHERE c.cleanup_id=a.id AND c.stage='claimed' AND c.sequence=(SELECT max(sequence) FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed') AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at))
  THEN RAISE EXCEPTION 'failed expansion read continuation lacks closed old owner'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT claim FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
 IF NEW.run_id IS DISTINCT FROM claim.run_id OR doc->>'generation' IS DISTINCT FROM claim.original_record->>'generation'
 OR doc->>'fencing_token' IS DISTINCT FROM claim.original_record->>'fencing_token' OR doc->>'lease_owner' IS DISTINCT FROM claim.original_record->>'lease_owner'
 OR doc->>'executor_id' IS DISTINCT FROM claim.original_record->>'executor_id' OR doc->>'lease_expires_at' IS DISTINCT FROM claim.original_record->>'lease_expires_at'
 THEN RAISE EXCEPTION 'failed expansion event owner mismatch'; END IF;
 IF NEW.stage IN('inventory_returned','absence_returned') THEN
  SELECT * INTO STRICT prepared FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage=split_part(NEW.stage,'_',1)||'_prepared' AND original_record#>>'{evidence,read_id}'=r#>>'{read,read_id}';
  IF prepared.original_record->'evidence' IS DISTINCT FROM r->'read'
  OR EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events old WHERE old.cleanup_id=a.id AND old.stage=NEW.stage AND old.original_record#>>'{evidence,read,read_id}'=r#>>'{read,read_id}')
  THEN RAISE EXCEPTION 'failed expansion actual read return mismatch'; END IF;
  RETURN NEW; -- Failed/late raw custody is retained, never authority.
 END IF;
 IF (claim.original_record->>'lease_expires_at')::timestamptz<=actual_now
 OR (intent_doc->>'fencing_token')::bigint IS DISTINCT FROM (doc->>'fencing_token')::bigint
 THEN RAISE EXCEPTION 'failed expansion stale owner'; END IF;
 IF NEW.stage IN('issued','possible_send','terminal') THEN
  -- Same actual enrolled survivors, same new owner, fresh physical read and
  -- accepted source canary publish/read. No old target/witness is synthesized.
  IF (SELECT count(*) FROM public.capacity_resource_slots slotrow WHERE slotrow.namespace=a.namespace AND slotrow.environment=a.environment AND slotrow.domain=a.domain AND slotrow.dimension=a.dimension AND slotrow.resource_id<>'')<>(a.original_record->>'survivor_count')::integer
  OR EXISTS(SELECT 1 FROM public.capacity_resource_slots slotrow WHERE slotrow.namespace=a.namespace AND slotrow.environment=a.environment AND slotrow.domain=a.domain AND slotrow.dimension=a.dimension AND slotrow.resource_id<>'' AND(
    slotrow.slot<1 OR slotrow.slot>=a.slot OR ((slotrow.slot_record->>'observed_at')::timestamptz BETWEEN actual_now-make_interval(secs=>(SELECT (spec->>'max_evidence_age_seconds')::integer FROM public.manifests WHERE id=a.policy_id)) AND actual_now+interval '5 seconds') IS NOT TRUE
    OR NOT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments enrollment
      JOIN public.capacity_guest_notify_canary_challenges rc ON rc.preregistration_id=enrollment.preregistration_id AND rc.phase='read'
      JOIN public.capacity_guest_notify_canary_returns rr ON rr.challenge_id=rc.id AND rr.outcome='accepted'
      JOIN public.capacity_guest_notify_canary_challenges pc ON pc.id=rc.record_challenge_id AND pc.phase='publish'
      JOIN public.capacity_guest_notify_canary_returns pr ON pr.challenge_id=pc.id AND pr.outcome='accepted'
      WHERE enrollment.enrollment_record#>>'{statement,tuple,resource_id}'=slotrow.resource_id
      AND enrollment.enrollment_record#>>'{statement,tuple,resource_created_at}'=slotrow.slot_record->>'resource_created_at'
      AND rc.policy_id=a.policy_id AND rc.workflow_id=(a.original_record->>'workflow_id')::uuid
      AND rc.generation=(claim.original_record->>'generation')::bigint AND rc.fence=(claim.original_record->>'fencing_token')::bigint
      AND rc.lease_owner=claim.original_record->>'lease_owner' AND rc.executor_id=claim.original_record->>'executor_id'
      AND pc.policy_id=rc.policy_id AND pc.generation=rc.generation AND pc.fence=rc.fence AND pc.lease_owner=rc.lease_owner AND pc.executor_id=rc.executor_id
      AND rc.original_record->>'usage_class'=CASE WHEN NEW.stage='terminal' THEN 'after_retirement_floor' ELSE 'before_retirement_floor' END
      AND pc.original_record->>'usage_class'=rc.original_record->>'usage_class'
      AND rc.recorded_at>CASE WHEN NEW.stage='terminal' THEN (SELECT max(recorded_at) FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='absence_complete' AND sequence>claim.sequence) ELSE claim.recorded_at END
      AND pc.recorded_at>claim.recorded_at AND rr.recorded_at>=rc.recorded_at AND pr.recorded_at>=pc.recorded_at
      AND rr.recorded_at BETWEEN actual_now-make_interval(secs=>(SELECT (spec->>'max_evidence_age_seconds')::integer FROM public.manifests WHERE id=a.policy_id)) AND actual_now)))
  THEN RAISE EXCEPTION 'failed expansion fresh real survivor floor refused'; END IF;
 END IF;
 IF NEW.stage IN('inventory_prepared','absence_prepared') THEN
  IF r->>'kind' IS DISTINCT FROM split_part(NEW.stage,'_',1) OR r->>'cleanup_id' IS DISTINCT FROM a.id::text OR r->>'child_grant_id' IS DISTINCT FROM a.child_grant_id::text
  OR (r->>'claim_sequence')::bigint IS DISTINCT FROM claim.sequence
  OR (r->>'original_deadline_core')::timestamptz<=(r->>'issued_at_core')::timestamptz OR (r->>'original_deadline_core')::timestamptz>(r->>'issued_at_core')::timestamptz+interval '5 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events p WHERE p.cleanup_id=a.id AND p.stage=NEW.stage AND NOT EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events q WHERE q.cleanup_id=a.id AND q.stage=split_part(NEW.stage,'_',1)||'_returned' AND q.original_record#>>'{evidence,read,read_id}'=p.original_record#>>'{evidence,read_id}'))
  THEN RAISE EXCEPTION 'failed expansion read preparation refused'; END IF;
  IF NEW.stage='inventory_prepared' AND EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id) THEN RAISE EXCEPTION 'failed expansion inventory cannot rearm child'; END IF;
  IF NEW.stage='absence_prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id=a.child_grant_id AND g.state='settled' AND g.grant_record#>>'{settlement,outcome}'='accepted' AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true') THEN RAISE EXCEPTION 'failed expansion sealed destroy required'; END IF;
 ELSIF NEW.stage IN('inventory_qualified','pending_absence','absence_complete') THEN
  IF previous.stage<>CASE WHEN NEW.stage='inventory_qualified' THEN 'inventory_returned' ELSE 'absence_returned' END
  OR (previous.original_record->'evidence')-ARRAY['pending','complete'] IS DISTINCT FROM r-ARRAY['pending','complete']
  OR r->>'call_failed' IS DISTINCT FROM 'false' OR r->>'original_context_failed' IS DISTINCT FROM 'false'
  OR (r->>'returned_at_core')::timestamptz>=(r#>>'{read,original_deadline_core}')::timestamptz
  THEN RAISE EXCEPTION 'failed expansion qualified return lacks complete original'; END IF;
  IF NEW.stage='inventory_qualified' THEN
   IF r->>'status' IS DISTINCT FROM 'dry_run' OR r#>>'{plan,server,id}' IS DISTINCT FROM a.original_record->>'resource_id'
   OR r#>>'{plan,server,created_at}' IS DISTINCT FROM a.original_record->>'resource_created_at'
   OR r#>>'{plan,server,physical_spec_verified}' IS DISTINCT FROM 'true' OR r#>>'{plan,server,auxiliary_inventory_complete}' IS DISTINCT FROM 'true'
   THEN RAISE EXCEPTION 'failed expansion owned attached inventory required'; END IF;
  ELSE
   IF public.failed_expansion_absence_read_valid(r,a.original_record) IS NOT TRUE THEN RAISE EXCEPTION 'failed expansion observer wrapper refused'; END IF;
   IF NEW.stage='absence_complete' AND(r->>'complete' IS DISTINCT FROM 'true' OR r->>'pending' IS DISTINCT FROM 'false' OR r#>>'{observation,server_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,billable_resources_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'true' OR jsonb_array_length(r#>'{observation,hold_reasons}') IS DISTINCT FROM 0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(r#>'{observation,auxiliary_resources}') aux WHERE aux->>'absent' IS DISTINCT FROM 'true')) THEN RAISE EXCEPTION 'failed expansion complete paid absence required'; END IF;
   IF NEW.stage='pending_absence' AND(r->>'pending' IS DISTINCT FROM 'true' OR r->>'complete' IS DISTINCT FROM 'false' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'false' OR jsonb_array_length(r#>'{observation,hold_reasons}') NOT BETWEEN 1 AND 3) THEN RAISE EXCEPTION 'failed expansion exact pending required'; END IF;
  END IF;
 ELSIF NEW.stage='issued' THEN
  IF EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage IN('issued','possible_send'))
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id AND failed_unwitnessed_expansion_cleanup_id=a.id AND state='issued')
  THEN RAISE EXCEPTION 'failed expansion child issue is once'; END IF;
 ELSIF NEW.stage='possible_send' THEN
  IF previous.stage<>'issued' OR EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='possible_send')
  THEN RAISE EXCEPTION 'failed expansion possible send is once'; END IF;
 ELSIF NEW.stage='terminal' THEN
  IF NOT EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='absence_complete' AND e.sequence>claim.sequence AND public.failed_expansion_absence_read_valid(e.original_record->'evidence',a.original_record))
  OR r->>'original_guest_success' IS DISTINCT FROM 'false' OR r->>'clean_cycle_credit' IS DISTINCT FROM 'false' OR r->>'serving_or_business_or_savings_authority' IS DISTINCT FROM 'false'
  THEN RAISE EXCEPTION 'failed expansion terminal requires its real fresh paid absence'; END IF;
 ELSE RAISE EXCEPTION 'failed expansion event stage refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_grant() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a public.capacity_failed_unwitnessed_expansion_cleanups; c public.capacity_failed_unwitnessed_expansion_cleanup_events; g jsonb; terminal boolean;
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.failed_unwitnessed_expansion_cleanup_id IS NOT NULL OR EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE grant_id=OLD.id) THEN RAISE EXCEPTION 'failed expansion parent/child cannot be deleted'; END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO a FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE grant_id=NEW.id OR child_grant_id=NEW.id FOR SHARE;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanups admitted
    WHERE admitted.namespace=NEW.namespace AND admitted.environment=NEW.environment AND admitted.domain=NEW.domain AND admitted.dimension=NEW.dimension
    AND NOT EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events e WHERE e.cleanup_id=admitted.id AND e.stage='terminal'))
    AND(TG_OP='INSERT' OR NEW.state IS DISTINCT FROM OLD.state OR NEW.grant_record IS DISTINCT FROM OLD.grant_record)
  THEN RAISE EXCEPTION 'failed expansion active frame excludes other grants'; END IF;
  IF NEW.failed_unwitnessed_expansion_cleanup_id IS NOT NULL OR NEW.state='cleanup_closed' OR NEW.grant_record ? 'failed_unwitnessed_expansion_cleanup_id' THEN RAISE EXCEPTION 'unbound failed expansion grant refused'; END IF;
  RETURN NEW;
 END IF;
 terminal:=EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='terminal');
 IF NEW.id=a.grant_id THEN
  IF TG_OP='INSERT' THEN RAISE EXCEPTION 'failed expansion parent already exists'; END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  IF OLD.state<>'settled' OR NEW.state<>'cleanup_closed' OR NOT terminal
  OR NEW.grant_record- 'grant' IS DISTINCT FROM OLD.grant_record- 'grant'
  OR (NEW.grant_record->'grant')-'state' IS DISTINCT FROM (OLD.grant_record->'grant')-'state'
  OR NEW.grant_record#>>'{grant,state}' IS DISTINCT FROM 'cleanup_closed'
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id AND state='confirmed')
  OR (to_jsonb(NEW)-ARRAY['state','grant_record','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','grant_record','updated_at'])
  THEN RAISE EXCEPTION 'failed expansion parent original is frozen until exact closure'; END IF;
  RETURN NEW;
 END IF;
 g:=NEW.grant_record;
 IF NEW.failed_unwitnessed_expansion_cleanup_id IS DISTINCT FROM a.id OR g->>'failed_unwitnessed_expansion_cleanup_id' IS DISTINCT FROM a.id::text
 OR NEW.namespace<>a.namespace OR NEW.environment<>a.environment OR NEW.domain<>a.domain OR NEW.dimension<>a.dimension OR NEW.slot<>a.slot
 OR g->'binding' IS DISTINCT FROM(SELECT grant_record->'binding' FROM public.capacity_mutation_grants WHERE id=a.grant_id)
 OR NEW.integration_instance_id::text IS DISTINCT FROM g#>>'{grant,integration_instance_id}'
 OR NEW.scope_checksum IS DISTINCT FROM g#>>'{grant,scope_checksum}' OR NEW.profile_name IS DISTINCT FROM g#>>'{grant,profile_name}'
 OR g#>>'{grant,binding_name}' IS DISTINCT FROM a.original_record->>'binding_name'
 OR g#>>'{grant,integration_instance_id}' IS DISTINCT FROM g#>>'{binding,integration_instance_id}'
 OR g#>>'{grant,scope_checksum}' IS DISTINCT FROM g#>>'{binding,scope_checksum}' OR g#>>'{grant,profile_name}' IS DISTINCT FROM g#>>'{binding,profile_name}'

 OR g#>>'{grant,capability}' IS DISTINCT FROM g#>>'{binding,destroy_capability}' OR COALESCE(g#>>'{grant,compensation_of}','')<>''
 OR g#>>'{grant,expected_resource_id}' IS DISTINCT FROM a.original_record->>'resource_id' OR g#>>'{grant,expected_resource_created_at}' IS DISTINCT FROM a.original_record->>'resource_created_at'
 OR g->>'policy_id' IS DISTINCT FROM a.policy_id::text OR g->>'policy_checksum' IS DISTINCT FROM a.policy_checksum
 THEN RAISE EXCEPTION 'failed expansion exact normal destroy child required'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT c FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
  IF NEW.state<>'issued' OR terminal OR g->>'generation' IS DISTINCT FROM c.original_record->>'generation' OR g->>'fencing_token' IS DISTINCT FROM c.original_record->>'fencing_token'
  OR g->>'lease_owner' IS DISTINCT FROM c.original_record->>'lease_owner' OR g->>'executor_id' IS DISTINCT FROM c.original_record->>'executor_id'
  OR (c.original_record->>'lease_expires_at')::timestamptz<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='inventory_qualified' AND e.sequence>c.sequence)
  THEN RAISE EXCEPTION 'failed expansion child lacks private fresh inventory owner'; END IF;
 ELSE
  IF OLD.failed_unwitnessed_expansion_cleanup_id IS DISTINCT FROM NEW.failed_unwitnessed_expansion_cleanup_id
  OR (OLD.grant_record->'grant')-'state' IS DISTINCT FROM (g->'grant')-'state'
  OR (OLD.grant_record-ARRAY['grant','attempt_id','settlement_token_sha256','settlement','proof']) IS DISTINCT FROM(g-ARRAY['grant','attempt_id','settlement_token_sha256','settlement','proof'])
  OR OLD.grant_record->'settlement' IS NOT NULL AND OLD.grant_record->'settlement' IS DISTINCT FROM g->'settlement'
  THEN RAISE EXCEPTION 'failed expansion child identity or settlement immutable'; END IF;
  IF OLD.state<>NEW.state AND NOT(OLD.state='issued' AND NEW.state='redeemed' AND EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='possible_send')
   OR OLD.state='redeemed' AND NEW.state IN('settled','rejected') OR OLD.state='settled' AND NEW.state='confirmed' AND terminal)
  THEN RAISE EXCEPTION 'failed expansion child transition refused'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_intent() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a public.capacity_failed_unwitnessed_expansion_cleanups; c public.capacity_failed_unwitnessed_expansion_cleanup_events; oid text:=OLD.intent->>'failed_unwitnessed_expansion_cleanup_id'; nid text:=NEW.intent->>'failed_unwitnessed_expansion_cleanup_id'; before_doc jsonb; after_doc jsonb;
BEGIN
 IF oid IS NULL AND nid IS NULL THEN RETURN NEW; END IF;
 IF NEW.intent IS NOT DISTINCT FROM OLD.intent THEN RETURN NEW; END IF;
 IF oid IS NULL THEN
  SELECT * INTO STRICT a FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE id=nid::uuid FOR SHARE;
  IF encode(sha256(convert_to(OLD.intent::text,'UTF8')),'hex') IS DISTINCT FROM a.original_record->>'original_intent_sha256'
  OR NEW.intent#>>'{decision,reason}' IS DISTINCT FROM 'failed_unwitnessed_expansion_cleanup'
  OR NEW.intent-ARRAY['failed_unwitnessed_expansion_cleanup_id','decision','updated_at'] IS DISTINCT FROM OLD.intent-ARRAY['decision','updated_at']
  OR (NEW.intent->'decision')-'reason' IS DISTINCT FROM (OLD.intent->'decision')-'reason'
  OR NOT EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='requested')
  THEN RAISE EXCEPTION 'failed expansion requested frame mismatch'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT a FROM public.capacity_failed_unwitnessed_expansion_cleanups WHERE id=oid::uuid FOR SHARE;
 SELECT * INTO STRICT c FROM public.capacity_failed_unwitnessed_expansion_cleanup_events WHERE cleanup_id=a.id ORDER BY sequence DESC LIMIT 1;
 IF nid IS NULL THEN
  IF c.stage<>'terminal' OR OLD.intent->>'phase'<>'hold' OR NEW.intent->>'policy_id'=OLD.intent->>'policy_id'
  THEN RAISE EXCEPTION 'failed expansion original policy remains latched'; END IF;
  RETURN NEW;
 END IF;
 IF nid<>oid THEN RAISE EXCEPTION 'failed expansion intent cannot change admission'; END IF;
 IF c.stage='claimed' THEN
  IF NEW.intent-ARRAY['fencing_token','lease_owner','lease_executor_id','lease_expires_at','updated_at'] IS DISTINCT FROM OLD.intent-ARRAY['fencing_token','lease_owner','lease_executor_id','lease_expires_at','updated_at']
  OR NEW.intent->>'fencing_token' IS DISTINCT FROM c.original_record->>'fencing_token' OR NEW.intent->>'lease_owner' IS DISTINCT FROM c.original_record->>'lease_owner'
  OR NEW.intent->>'lease_executor_id' IS DISTINCT FROM c.original_record->>'executor_id' OR NEW.intent->>'lease_expires_at' IS DISTINCT FROM c.original_record->>'lease_expires_at'
  THEN RAISE EXCEPTION 'failed expansion claim cannot rewrite generation or failed decision'; END IF;
 ELSIF c.stage='terminal' THEN
  IF NEW.intent->>'phase' IS DISTINCT FROM 'hold' OR NEW.intent ?| ARRAY['lease_owner','lease_executor_id','lease_expires_at']
  OR NEW.intent#>>'{decision,units}' IS DISTINCT FROM a.original_record->>'survivor_count'
  OR NEW.intent#>>'{decision,action}' IS DISTINCT FROM 'hold' OR NEW.intent#>>'{decision,reason}' IS DISTINCT FROM 'failed_expansion_cleaned_original_failure_preserved'
  OR NEW.intent#>>'{decision,execution_permitted}' IS DISTINCT FROM 'false'
  OR NEW.intent-ARRAY['phase','lease_owner','lease_executor_id','lease_expires_at','decision','updated_at'] IS DISTINCT FROM OLD.intent-ARRAY['phase','lease_owner','lease_executor_id','lease_expires_at','decision','updated_at']
  OR (NEW.intent->'decision')-ARRAY['action','reason','units','execution_permitted'] IS DISTINCT FROM (OLD.intent->'decision')-ARRAY['action','reason','units','execution_permitted']
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.grant_id AND state='cleanup_closed')
  THEN RAISE EXCEPTION 'failed expansion truthful terminal frame refused'; END IF;
 ELSE RAISE EXCEPTION 'failed expansion generic intent write refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_unwitnessed_expansion_cleanup_event_guard BEFORE INSERT ON public.capacity_failed_unwitnessed_expansion_cleanup_events FOR EACH ROW EXECUTE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_event();
CREATE TRIGGER failed_unwitnessed_expansion_cleanup_grant_guard BEFORE INSERT OR UPDATE OR DELETE ON public.capacity_mutation_grants FOR EACH ROW EXECUTE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_grant();
CREATE TRIGGER failed_unwitnessed_expansion_cleanup_intent_guard BEFORE UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_intent();

-- +goose StatementBegin
CREATE FUNCTION public.immutable_failed_unwitnessed_expansion_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'failed unwitnessed expansion original is immutable'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_unwitnessed_expansion_cleanup_admission BEFORE INSERT ON public.capacity_failed_unwitnessed_expansion_cleanups FOR EACH ROW EXECUTE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup();
CREATE TRIGGER failed_unwitnessed_expansion_cleanup_immutable BEFORE UPDATE OR DELETE ON public.capacity_failed_unwitnessed_expansion_cleanups FOR EACH ROW EXECUTE FUNCTION public.immutable_failed_unwitnessed_expansion_cleanup();
CREATE TRIGGER failed_unwitnessed_expansion_cleanup_event_immutable BEFORE UPDATE OR DELETE ON public.capacity_failed_unwitnessed_expansion_cleanup_events FOR EACH ROW EXECUTE FUNCTION public.immutable_failed_unwitnessed_expansion_cleanup();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM public.capacity_failed_unwitnessed_expansion_cleanups)
 THEN RAISE EXCEPTION 'cannot remove admitted failed expansion cleanup history'; END IF; END; $$;
-- +goose StatementEnd
DROP TRIGGER failed_unwitnessed_expansion_cleanup_admission ON public.capacity_failed_unwitnessed_expansion_cleanups;
DROP TRIGGER failed_unwitnessed_expansion_cleanup_immutable ON public.capacity_failed_unwitnessed_expansion_cleanups;
DROP TRIGGER failed_unwitnessed_expansion_cleanup_event_immutable ON public.capacity_failed_unwitnessed_expansion_cleanup_events;
DROP TRIGGER failed_unwitnessed_expansion_cleanup_event_guard ON public.capacity_failed_unwitnessed_expansion_cleanup_events;
DROP TRIGGER failed_unwitnessed_expansion_cleanup_grant_guard ON public.capacity_mutation_grants;
DROP TRIGGER failed_unwitnessed_expansion_cleanup_intent_guard ON public.capacity_intents;
DROP FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_event();
DROP FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_grant();
DROP FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_intent();
DROP FUNCTION public.failed_expansion_absence_read_valid(jsonb,jsonb);
DROP FUNCTION public.guard_failed_unwitnessed_expansion_cleanup();
DROP FUNCTION public.immutable_failed_unwitnessed_expansion_cleanup();
DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled') AND original_disposition_id IS NULL
 AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL
 AND enrolled_failed_disposition_id IS NULL;
ALTER TABLE public.capacity_mutation_grants DROP CONSTRAINT capacity_mutation_grants_state_check;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_mutation_grants_state_check CHECK(state IN('issued','redeemed','settled','confirmed','rejected','expired','compensating','compensated'));
ALTER TABLE public.capacity_mutation_grants DROP CONSTRAINT failed_unwitnessed_expansion_exact_child_fk;
ALTER TABLE public.capacity_mutation_grants DROP COLUMN failed_unwitnessed_expansion_cleanup_id;
DROP TABLE public.capacity_failed_unwitnessed_expansion_cleanup_events;
DROP TABLE public.capacity_failed_unwitnessed_expansion_cleanups;
