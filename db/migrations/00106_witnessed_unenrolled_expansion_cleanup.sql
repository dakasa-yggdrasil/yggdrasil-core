-- +goose Up
-- Distinct witnessed, unenrolled HZN cleanup. Installing Source grants no
-- replay, Guest enrollment, ACK, fencing, health or cycle credit.

CREATE TABLE IF NOT EXISTS public.capacity_witnessed_unenrolled_expansion_cleanups (
 id uuid PRIMARY KEY,
 grant_id uuid NOT NULL UNIQUE REFERENCES public.capacity_mutation_grants(id),
 child_grant_id uuid NOT NULL UNIQUE,
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 preregistration_id uuid NOT NULL UNIQUE REFERENCES public.capacity_vm_provisioning_preregistrations(id),
 namespace text NOT NULL, environment text NOT NULL, domain text NOT NULL, dimension text NOT NULL,
 policy_id uuid NOT NULL REFERENCES public.manifests(id), policy_checksum text NOT NULL CHECK(policy_checksum ~ '^[0-9a-f]{64}$'),
 slot integer NOT NULL CHECK(slot=2),
 admission_sha256 text NOT NULL UNIQUE CHECK(admission_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),
 recorded_at timestamptz NOT NULL,
 UNIQUE(id,child_grant_id), CHECK(grant_id<>child_grant_id),
 CHECK(original_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(admission_sha256=encode(sha256(original_wire),'hex')),
 CHECK(original_record->>'schema' IS NOT DISTINCT FROM 'witnessed_unenrolled_expansion_cleanup_v1'),
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
CREATE TABLE IF NOT EXISTS public.capacity_witnessed_unenrolled_expansion_cleanup_events (
 cleanup_id uuid NOT NULL REFERENCES public.capacity_witnessed_unenrolled_expansion_cleanups(id),
 sequence bigint NOT NULL CHECK(sequence>=1),
 stage text NOT NULL CHECK(stage IN('requested','claimed','inventory_prepared','inventory_returned','inventory_qualified','issued','possible_send','pending_absence','absence_prepared','absence_returned','absence_complete','terminal')),
 run_id uuid REFERENCES public.workflow_runs(id), child_grant_id uuid NOT NULL,
 event_sha256 text NOT NULL CHECK(event_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),
 recorded_at timestamptz NOT NULL,
 PRIMARY KEY(cleanup_id,sequence),
 FOREIGN KEY(cleanup_id,child_grant_id) REFERENCES public.capacity_witnessed_unenrolled_expansion_cleanups(id,child_grant_id),
 CHECK(original_record=convert_from(original_wire,'UTF8')::jsonb),
 CHECK(event_sha256=encode(sha256(original_wire),'hex')),
 CHECK(original_record->>'schema' IS NOT DISTINCT FROM 'witnessed_unenrolled_expansion_cleanup_v1'),
 CHECK(original_record->>'cleanup_id' IS NOT DISTINCT FROM cleanup_id::text),
 CHECK((original_record->>'sequence')::bigint IS NOT DISTINCT FROM sequence),
 CHECK(original_record->>'stage' IS NOT DISTINCT FROM stage),
 CHECK(original_record->>'run_id' IS NOT DISTINCT FROM run_id::text),
 CHECK(original_record->>'child_grant_id' IS NOT DISTINCT FROM child_grant_id::text),
 CHECK((original_record->>'recorded_at')::timestamptz IS NOT DISTINCT FROM recorded_at)
);
CREATE TABLE IF NOT EXISTS public.capacity_witnessed_unenrolled_expansion_dispatch_ownership (
 cleanup_id uuid PRIMARY KEY REFERENCES public.capacity_witnessed_unenrolled_expansion_cleanups(id),
 revision bigint NOT NULL CHECK(revision>=0),
 job_id uuid UNIQUE REFERENCES public.capacity_dispatch_jobs(id) DEFERRABLE INITIALLY DEFERRED,
 updated_at timestamptz NOT NULL,
 CHECK((revision=0 AND job_id IS NULL) OR(revision>0 AND job_id IS NOT NULL))
);

-- +goose StatementBegin
CREATE FUNCTION public.witnessed_expansion_dispatch_marker_present106(envelope_text text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE doc jsonb;
BEGIN
 doc:=envelope_text::jsonb;
 RETURN COALESCE(jsonb_typeof(doc)='object' AND doc ? 'witnessed_unenrolled_expansion_cleanup_id',false);
EXCEPTION WHEN others THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- Preserve the complete legacy active-state predicate, including UNKNOWN.
-- A malformed/null/empty selector is still in the marked class, whose BEFORE
-- guard must reject it before either physical uniqueness exemption is used.
DROP INDEX public.capacity_dispatch_active_scope_idx;
CREATE UNIQUE INDEX capacity_dispatch_active_scope_idx
 ON public.capacity_dispatch_jobs(realm,environment,domain,dimension)
 WHERE (state IN('queued','started','unknown') OR(state='returned' AND finalization_ack_at IS NULL))
 AND NOT public.witnessed_expansion_dispatch_marker_present106(envelope);
CREATE UNIQUE INDEX capacity_witnessed_expansion_active_scope106_idx
 ON public.capacity_dispatch_jobs(realm,environment,domain,dimension)
 WHERE (state IN('queued','started','unknown') OR(state='returned' AND finalization_ack_at IS NULL))
 AND public.witnessed_expansion_dispatch_marker_present106(envelope);

ALTER TABLE public.capacity_mutation_grants DROP CONSTRAINT capacity_mutation_grants_state_check;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_mutation_grants_state_check
 CHECK(state IN('issued','redeemed','settled','confirmed','rejected','expired','compensating','compensated','cleanup_closed','witnessed_unenrolled_cleanup_closed'));
-- Only a BEFORE-trigger-authenticated exact child can carry this JSON marker.
-- The original SETTLED CREATE continues to reserve the ordinary physical slot.
DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled') AND original_disposition_id IS NULL
 AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL
 AND enrolled_failed_disposition_id IS NULL AND failed_unwitnessed_expansion_cleanup_id IS NULL
 AND NOT(grant_record ? 'witnessed_unenrolled_expansion_cleanup_id');

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE parent_row public.capacity_mutation_grants; pre_row public.capacity_vm_provisioning_preregistrations;
 job_row public.capacity_dispatch_jobs; intent_wire jsonb; policy_row public.manifests;
 run_row public.workflow_runs; witness public.capacity_guest_original_create_witnesses; sdk jsonb; original_doc jsonb; survivor_count integer;
BEGIN
 original_doc:=NEW.original_record;
 IF jsonb_typeof(original_doc) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(original_doc))<>44
 OR NOT(original_doc ?& ARRAY['schema','id','grant_id','child_grant_id','job_id','run_id','preregistration_id','issuer','namespace','environment','domain','dimension','policy_id','policy_checksum','workflow_id','workflow_checksum','binding_name','profile_name','slot','resource_id','resource_created_at','original_grant_sha256','original_SDK_return_sha256','original_preregistration_sha256','original_dispatch_sha256','original_run_sha256','original_intent_sha256','original_intent_wire','original_generation','original_fencing_token','original_deadline','original_lease_expires_at','original_auxiliary_inventory_complete','survivor_roster_wire','survivor_roster_sha256','survivor_count','original_create_witness_sha256','original_create_witness_wire','original_grant_wire','original_SDK_return_wire','original_preregistration_wire','original_dispatch_wire','original_run_wire','recorded_at']) OR EXISTS(SELECT 1 FROM jsonb_each(original_doc) e WHERE e.value='null'::jsonb)
 OR EXISTS(SELECT 1 FROM jsonb_each(original_doc) e WHERE e.key<>ALL(ARRAY['slot','original_generation','original_fencing_token','survivor_count','original_auxiliary_inventory_complete']) AND jsonb_typeof(e.value)<>'string')
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['slot','original_generation','original_fencing_token','survivor_count']) k WHERE original_doc->>k !~ '^(0|[1-9][0-9]*)$')
 OR jsonb_typeof(original_doc->'original_auxiliary_inventory_complete') IS DISTINCT FROM 'boolean'
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion closed admission required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension])::text,0));
 SELECT * INTO STRICT parent_row FROM public.capacity_mutation_grants WHERE id=NEW.grant_id FOR SHARE;
 SELECT * INTO STRICT pre_row FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id FOR SHARE;
 SELECT * INTO STRICT job_row FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR SHARE;
 SELECT * INTO STRICT run_row FROM public.workflow_runs WHERE id=job_row.run_id FOR SHARE;
 SELECT * INTO STRICT policy_row FROM public.manifests WHERE id=NEW.policy_id FOR SHARE;
 SELECT ci.intent INTO STRICT intent_wire FROM public.capacity_intents ci WHERE ci.namespace=NEW.namespace AND ci.environment=NEW.environment AND ci.domain=NEW.domain AND ci.dimension=NEW.dimension FOR SHARE;
 SELECT * INTO STRICT witness FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=pre_row.id FOR SHARE;
 sdk:=parent_row.grant_record#>'{settlement,original_provider_create_return}'; original_doc:=NEW.original_record;
 IF (parent_row.state IS DISTINCT FROM 'settled' OR parent_row.slot<>NEW.slot
 OR parent_row.namespace<>NEW.namespace OR parent_row.environment<>NEW.environment OR parent_row.domain<>NEW.domain OR parent_row.dimension<>NEW.dimension
 OR num_nonnulls(parent_row.original_disposition_id,parent_row.failed_original_disposition_id,parent_row.native_denied_disposition_id,parent_row.enrolled_failed_disposition_id,parent_row.failed_unwitnessed_expansion_cleanup_id)<>0
 OR COALESCE(parent_row.grant_record#>>'{grant,compensation_of}','')<>''
 OR parent_row.grant_record#>>'{settlement,outcome}' IS DISTINCT FROM 'accepted'
 OR parent_row.grant_record#>>'{settlement,transport_completed}' IS DISTINCT FROM 'true'
 OR sdk->>'schema' IS DISTINCT FROM 'hetzner_original_create_return_v1'
 OR sdk->>'response_status' IS DISTINCT FROM '201'
 OR sdk->>'provider' IS DISTINCT FROM 'hetzner'
 OR sdk->>'adapter_source_commit' IS DISTINCT FROM '6026f78572a0ebfbf1b50984c2d47ff28bdc714d'
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
 OR intent_wire ? 'witnessed_unenrolled_expansion_cleanup_id'
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
 OR job_row.state IS DISTINCT FROM 'unknown' OR job_row.return_status IS DISTINCT FROM 'failed'
 OR job_row.finalization_ack_at IS NOT NULL OR job_row.returned_at IS NULL OR job_row.started_at IS NULL
 OR run_row.status IS DISTINCT FROM 'failed' OR run_row.finished_at IS DISTINCT FROM job_row.returned_at
 OR original_doc->>'run_id' IS DISTINCT FROM job_row.run_id::text
 OR job_row.realm<>NEW.namespace OR job_row.environment<>NEW.environment OR job_row.domain<>NEW.domain OR job_row.dimension<>NEW.dimension
 OR job_row.lease_expires_at>=clock_timestamp() OR pre_row.created_at NOT BETWEEN job_row.started_at AND job_row.returned_at
 OR job_row.envelope::jsonb#>>'{policy,id}' IS DISTINCT FROM NEW.policy_id::text
 OR job_row.envelope::jsonb#>>'{policy,checksum}' IS DISTINCT FROM NEW.policy_checksum
 OR job_row.envelope::jsonb#>>'{workflow,id}' IS DISTINCT FROM original_doc->>'workflow_id'
 OR job_row.envelope::jsonb#>>'{workflow,checksum}' IS DISTINCT FROM original_doc->>'workflow_checksum'
 OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=NEW.namespace AND j.environment=NEW.environment AND j.domain=NEW.domain AND j.dimension=NEW.dimension AND j.id<>NEW.job_id AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL))
 OR EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.workflow_namespace=(SELECT namespace FROM public.manifests WHERE id=(original_doc->>'workflow_id')::uuid) AND w.workflow_name=(SELECT name FROM public.manifests WHERE id=(original_doc->>'workflow_id')::uuid) AND w.id<>job_row.run_id AND(COALESCE(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(run_row.result->'steps') step WHERE step->>'status'='failed' AND step#>>'{metadata,original_guest_refusal_predicate}'='original-guest-step-29')
 OR EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=pre_row.id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=pre_row.id)
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=pre_row.id)
 OR EXISTS(SELECT 1 FROM public.capacity_factory_original_grant_bindings WHERE grant_id=NEW.grant_id)
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE grant_record#>>'{grant,compensation_of}'=NEW.grant_id::text)

 OR parent_row.grant_record ? 'witnessed_unenrolled_expansion_cleanup_id'
 OR parent_row.grant_record#>>'{grant,state}' IS DISTINCT FROM 'settled'
 OR parent_row.grant_record#>>'{grant,capability}' IS DISTINCT FROM 'ensure_server'
 OR parent_row.grant_record#>>'{binding,ensure_capability}' IS DISTINCT FROM 'ensure_server'
 OR parent_row.grant_record#>>'{binding,destroy_capability}' IS DISTINCT FROM 'destroy_server'
 OR parent_row.grant_record#>>'{binding,original_provider_source_commit}' IS DISTINCT FROM sdk->>'adapter_source_commit'
 OR parent_row.grant_record->>'policy_id' IS DISTINCT FROM NEW.policy_id::text
 OR parent_row.grant_record->>'policy_checksum' IS DISTINCT FROM NEW.policy_checksum
 OR parent_row.integration_instance_id::text IS DISTINCT FROM parent_row.grant_record#>>'{binding,integration_instance_id}'
 OR parent_row.scope_checksum IS DISTINCT FROM parent_row.grant_record#>>'{binding,scope_checksum}'
 OR parent_row.profile_name IS DISTINCT FROM parent_row.grant_record#>>'{binding,profile_name}'
 OR parent_row.profile_name IS DISTINCT FROM 'notify-hetzner-elastic'
 OR original_doc->>'profile_name' IS DISTINCT FROM parent_row.profile_name
 OR original_doc->>'binding_name' IS DISTINCT FROM parent_row.grant_record#>>'{binding,name}'
 OR (original_doc->>'survivor_count')::integer IS DISTINCT FROM NEW.slot-1
 OR (original_doc->>'original_generation')::bigint NOT BETWEEN 1 AND 9007199254740991
 OR (original_doc->>'original_fencing_token')::bigint NOT BETWEEN 1 AND 9007199254740990
 OR NEW.dimension IS DISTINCT FROM 'original_notify_hetzner_vm_members'
 OR sdk->>'action_id' IS DISTINCT FROM parent_row.grant_record#>>'{settlement,action_id}'
 OR sdk->'next_action_ids' IS DISTINCT FROM COALESCE(parent_row.grant_record#>'{settlement,next_action_ids}','[]'::jsonb)
 OR sdk->>'response_body_sha256' !~ '^[0-9a-f]{64}$' OR (sdk->>'response_bytes')::bigint NOT BETWEEN 2 AND 2097152
 OR (sdk->>'called_at')::timestamptz<pre_row.created_at
 OR (sdk->>'returned_at')::timestamptz<(sdk->>'called_at')::timestamptz
 OR (sdk->>'returned_at')::timestamptz>=(sdk->>'context_deadline')::timestamptz
 OR (sdk->>'context_deadline')::timestamptz>(parent_row.grant_record#>>'{grant,expires_at}')::timestamptz
 OR (sdk->>'returned_at')::timestamptz>(parent_row.grant_record#>>'{settlement,observed_at}')::timestamptz
 OR parent_row.grant_record#>>'{settlement,auxiliary_inventory_complete}' IS DISTINCT FROM 'true'
 OR jsonb_array_length(parent_row.grant_record#>'{settlement,auxiliary_resources}') NOT BETWEEN 1 AND 16
 OR NEW.recorded_at<job_row.returned_at OR NEW.recorded_at>clock_timestamp()+interval '1 second'
 OR job_row.protocol IS DISTINCT FROM 'capacity_dispatch_prestart_v1' OR job_row.lease_owner IS NULL OR job_row.fencing_token<1
 OR run_row.started_at IS DISTINCT FROM job_row.started_at
 OR run_row.workflow_id IS NOT NULL AND run_row.workflow_id::text IS DISTINCT FROM original_doc->>'workflow_id'
 OR run_row.result->>'status' IS DISTINCT FROM 'failed'
 OR run_row.result#>>'{workflow,id}' IS DISTINCT FROM original_doc->>'workflow_id'
 OR run_row.result#>>'{workflow,namespace}' IS DISTINCT FROM job_row.envelope::jsonb#>>'{workflow,namespace}'
 OR run_row.result#>>'{workflow,name}' IS DISTINCT FROM job_row.envelope::jsonb#>>'{workflow,name}'
 OR run_row.result#>>'{workflow,version}' IS DISTINCT FROM job_row.envelope::jsonb#>>'{workflow,version}'
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(run_row.result->'steps') s WHERE s->>'id'=pre_row.preregistration_record->>'original_workflow_step_id'
  AND s->>'status'='failed' AND s#>>'{metadata,original_guest_refusal_predicate}'='original-guest-step-29')
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(run_row.result->'steps') s WHERE s->>'id'='plan-original-guest' AND s->>'status'='succeeded'
  AND s#>>'{metadata,generation}'=original_doc->>'original_generation' AND s#>>'{metadata,fencing_token}'=original_doc->>'original_fencing_token'
  AND s#>>'{metadata,lease_owner}'=intent_wire->>'lease_owner')
 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots s WHERE s.integration_instance_id=parent_row.integration_instance_id AND s.resource_id=original_doc->>'resource_id')
 OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups a WHERE (a.namespace,a.environment,a.domain,a.dimension)=(NEW.namespace,NEW.environment,NEW.domain,NEW.dimension)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='terminal'))
 OR EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id<>parent_row.id
  AND (g.integration_instance_id,g.scope_checksum,g.profile_name)=(parent_row.integration_instance_id,parent_row.scope_checksum,parent_row.profile_name)
  AND g.state IN('issued','redeemed','settled','compensating') AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL
  AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND g.failed_unwitnessed_expansion_cleanup_id IS NULL)
 OR witness.original_record IS DISTINCT FROM convert_from(witness.original_wire,'UTF8')::jsonb
 OR witness.witness_sha256 IS DISTINCT FROM encode(sha256(witness.original_wire),'hex')
 OR witness.original_record->>'schema' IS DISTINCT FROM 'original_guest_create_witness_v1'
 OR witness.original_record->>'preregistration_id' IS DISTINCT FROM pre_row.id::text
 OR witness.original_record->>'original_create_grant_id' IS DISTINCT FROM parent_row.id::text
 OR witness.original_record->>'original_create_attempt_id' IS DISTINCT FROM parent_row.grant_record->>'attempt_id'
 OR witness.original_record->>'original_create_request_sha256' IS DISTINCT FROM sdk->>'request_sha256'
 OR witness.original_record->>'original_deadline' IS DISTINCT FROM pre_row.preregistration_record->>'original_deadline'
 OR witness.original_record#>>'{tuple,provider}' IS DISTINCT FROM 'hetzner'
 OR witness.original_record#>>'{tuple,resource_id}' IS DISTINCT FROM sdk->>'resource_id'
 OR witness.original_record#>>'{tuple,resource_created_at}' IS DISTINCT FROM sdk->>'resource_created_at'
 OR witness.original_record#>>'{tuple,integration_instance_id}' IS DISTINCT FROM parent_row.integration_instance_id::text
 OR witness.original_record#>>'{tuple,scope_checksum}' IS DISTINCT FROM parent_row.scope_checksum
 OR witness.original_record#>>'{tuple,instance_checksum}' IS DISTINCT FROM parent_row.grant_record#>>'{binding,integration_checksum}'
 OR witness.original_record#>>'{tuple,integration_type_id}' IS DISTINCT FROM parent_row.grant_record#>>'{binding,integration_type_id}'
 OR witness.original_record#>>'{tuple,type_checksum}' IS DISTINCT FROM parent_row.grant_record#>>'{binding,integration_type_checksum}'
 OR witness.original_record#>>'{tuple,profile}' IS DISTINCT FROM parent_row.profile_name
 OR witness.original_record#>>'{tuple,slot}' IS DISTINCT FROM NEW.slot::text
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(parent_row.grant_record#>'{binding,slots}') approved WHERE approved->>'slot'=NEW.slot::text
  AND approved#>>'{desired_spec,profile_checksum}'=witness.original_record#>>'{tuple,profile_checksum}')
 OR (witness.original_record->>'original_create_returned_at')::timestamptz IS DISTINCT FROM (sdk->>'returned_at')::timestamptz
 OR (witness.original_record->>'observed_at')::timestamptz<(sdk->>'returned_at')::timestamptz
 OR (witness.original_record->>'observed_at')::timestamptz>=pre_row.original_deadline
 OR witness.recorded_at>job_row.returned_at
 OR witness.original_record#>>'{provider_native_identity,schema}' IS DISTINCT FROM 'guest_provider_native_identity_v1'
 OR witness.original_record#>>'{provider_native_identity,provider}' IS DISTINCT FROM 'hetzner'
 OR witness.original_record#>>'{provider_native_identity,resource_id}' IS DISTINCT FROM sdk->>'resource_id'
 OR witness.original_record#>>'{provider_native_identity,resource_created_at}' IS DISTINCT FROM sdk->>'resource_created_at'
 OR witness.original_record#>>'{provider_native_identity,adapter_source_commit}' IS DISTINCT FROM sdk->>'adapter_source_commit'
 OR witness.original_record#>>'{provider_native_identity,resource_id}' !~ '^[1-9][0-9]*$'
 OR witness.original_record#>>'{provider_native_identity,type_id}' !~ '^[1-9][0-9]*$'
 OR witness.original_record#>>'{provider_native_identity,image_id}' !~ '^[1-9][0-9]*$'
 OR witness.original_record#>>'{provider_native_identity,account_id}' IS DISTINCT FROM ''
 OR witness.original_record#>>'{provider_native_identity,zone}' IS DISTINCT FROM ''
 OR witness.original_record#>>'{provider_native_identity,region}' !~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$'
 OR witness.original_record#>>'{provider_native_identity,location}' !~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$'
 OR witness.original_record#>>'{provider_native_identity,hostname}' !~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$'
 OR (witness.original_record#>>'{provider_native_identity,observed_at}')::timestamptz>(witness.original_record->>'observed_at')::timestamptz
 OR (witness.original_record#>>'{provider_native_identity,observed_at}')::timestamptz<(witness.original_record->>'observed_at')::timestamptz-interval '30 seconds'
 OR intent_wire ? 'failed_unwitnessed_expansion_cleanup_id'
 OR (original_doc->>'original_deadline')::timestamptz IS DISTINCT FROM pre_row.original_deadline
 OR (original_doc->>'original_lease_expires_at')::timestamptz IS DISTINCT FROM (intent_wire->>'lease_expires_at')::timestamptz
 OR pre_row.preregistration_record IS DISTINCT FROM convert_from(pre_row.original_wire,'UTF8')::jsonb
 OR pre_row.preregistration_record->>'preregistration_id' IS DISTINCT FROM pre_row.id::text
 OR pre_row.preregistration_record->>'original_create_grant_id' IS DISTINCT FROM parent_row.id::text
 OR pre_row.preregistration_record->>'original_create_request_sha256' IS DISTINCT FROM sdk->>'request_sha256'
 OR pre_row.preregistration_record->>'policy_id' IS DISTINCT FROM NEW.policy_id::text
 OR pre_row.preregistration_record->>'policy_checksum' IS DISTINCT FROM NEW.policy_checksum
 OR pre_row.preregistration_record->>'workflow_id' IS DISTINCT FROM original_doc->>'workflow_id'
 OR pre_row.preregistration_record->>'workflow_checksum' IS DISTINCT FROM original_doc->>'workflow_checksum'
 OR pre_row.preregistration_record->>'generation' IS DISTINCT FROM original_doc->>'original_generation'
 OR pre_row.preregistration_record->>'fence' IS DISTINCT FROM original_doc->>'original_fencing_token'
 OR pre_row.preregistration_record->>'lease_owner' IS DISTINCT FROM parent_row.grant_record->>'lease_owner'
 OR pre_row.preregistration_record->>'executor_id' IS DISTINCT FROM parent_row.grant_record->>'executor_id'
 OR witness.original_record->>'binding_name' IS DISTINCT FROM pre_row.preregistration_record->>'binding_name'
 OR convert_from(pre_row.binding_wire,'UTF8')::jsonb->>'mutation_binding_name' IS DISTINCT FROM original_doc->>'binding_name'
 OR policy_row.spec#>>'{guest_retirement_binding,mutation_binding_name}' IS DISTINCT FROM original_doc->>'binding_name'
 OR (SELECT count(*) FROM jsonb_array_elements(convert_from(pre_row.binding_wire,'UTF8')::jsonb->'members') member
  WHERE member->>'slot'=NEW.slot::text AND member->>'name'=pre_row.preregistration_record->>'binding_name') IS DISTINCT FROM 1::bigint
 OR (SELECT count(*) FROM jsonb_array_elements(policy_row.spec#>'{guest_retirement_binding,members}') member
  WHERE member->>'slot'=NEW.slot::text AND member->>'name'=pre_row.preregistration_record->>'binding_name') IS DISTINCT FROM 1::bigint
 OR witness.original_record->>'preregistration_nonce_sha256' IS DISTINCT FROM pre_row.nonce_sha256
 OR witness.original_record->>'profile_manifest_sha256' IS DISTINCT FROM pre_row.profile_manifest_sha256
 OR witness.original_record->>'core_source_commit' IS DISTINCT FROM pre_row.preregistration_record->>'core_source_commit'
 OR original_doc->>'original_create_witness_sha256' IS DISTINCT FROM witness.witness_sha256
 OR decode(original_doc->>'original_create_witness_wire','base64') IS DISTINCT FROM witness.original_wire
 OR decode(original_doc->>'original_grant_wire','base64') IS DISTINCT FROM convert_to(parent_row.grant_record::text,'UTF8')
 OR decode(original_doc->>'original_SDK_return_wire','base64') IS DISTINCT FROM convert_to(sdk::text,'UTF8')
 OR decode(original_doc->>'original_preregistration_wire','base64') IS DISTINCT FROM pre_row.original_wire
 OR decode(original_doc->>'original_dispatch_wire','base64') IS DISTINCT FROM convert_to(to_jsonb(job_row)::text,'UTF8')
 OR decode(original_doc->>'original_run_wire','base64') IS DISTINCT FROM convert_to(to_jsonb(run_row)::text,'UTF8')
) IS NOT FALSE THEN RAISE EXCEPTION 'witnessed unenrolled expansion admission refused'; END IF;
 SELECT count(*) INTO survivor_count FROM public.capacity_resource_slots s WHERE s.namespace=NEW.namespace AND s.environment=NEW.environment AND s.domain=NEW.domain AND s.dimension=NEW.dimension AND s.resource_id<>'';
 IF survivor_count<>NEW.slot-1 OR EXISTS(SELECT 1 FROM public.capacity_resource_slots s WHERE s.namespace=NEW.namespace AND s.environment=NEW.environment AND s.domain=NEW.domain AND s.dimension=NEW.dimension AND s.resource_id<>'' AND(s.slot<1 OR s.slot>=NEW.slot OR s.resource_id=original_doc->>'resource_id' OR s.slot_record->>'binding_name' IS DISTINCT FROM original_doc->>'binding_name' OR s.slot_record->>'profile_name' IS DISTINCT FROM original_doc->>'profile_name' OR s.slot_record->>'resource_id' IS DISTINCT FROM s.resource_id OR s.slot_record->>'tombstone' IS DISTINCT FROM 'false'))
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion survivor roster refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.witnessed_unenrolled_expansion_parent_valid106(cleanup uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups; p public.capacity_mutation_grants;
 j public.capacity_dispatch_jobs; w public.workflow_runs; pr public.capacity_vm_provisioning_preregistrations;
 witness public.capacity_guest_original_create_witnesses; g jsonb; jd jsonb; doc jsonb;
BEGIN
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=cleanup;
 SELECT * INTO STRICT p FROM public.capacity_mutation_grants WHERE id=a.grant_id;
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=a.job_id;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=j.run_id;
 SELECT * INTO STRICT pr FROM public.capacity_vm_provisioning_preregistrations WHERE id=a.preregistration_id;
 SELECT * INTO STRICT witness FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=a.preregistration_id;
 doc:=a.original_record; g:=p.grant_record; jd:=to_jsonb(j);
 IF p.state='witnessed_unenrolled_cleanup_closed' THEN
  IF NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='terminal') THEN RETURN false; END IF;
  g:=jsonb_set(g,'{grant,state}','"settled"'::jsonb);
 ELSIF p.state<>'settled' THEN RETURN false; END IF;
 IF j.state='witnessed_unenrolled_expansion_disposed' THEN
  IF NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='terminal') THEN RETURN false; END IF;
  jd:=jd||jsonb_build_object('state','unknown','updated_at',convert_from(decode(doc->>'original_dispatch_wire','base64'),'UTF8')::jsonb->'updated_at');
 ELSIF j.state<>'unknown' THEN RETURN false; END IF;
 RETURN (a.admission_sha256=encode(sha256(a.original_wire),'hex') AND doc=convert_from(a.original_wire,'UTF8')::jsonb
  AND convert_to(g::text,'UTF8')=decode(doc->>'original_grant_wire','base64') AND encode(sha256(convert_to(g::text,'UTF8')),'hex')=doc->>'original_grant_sha256'
  AND convert_to((g#>'{settlement,original_provider_create_return}')::text,'UTF8')=decode(doc->>'original_SDK_return_wire','base64')
  AND encode(sha256(decode(doc->>'original_SDK_return_wire','base64')),'hex')=doc->>'original_SDK_return_sha256'
  AND convert_to(jd::text,'UTF8')=decode(doc->>'original_dispatch_wire','base64') AND encode(sha256(convert_to(jd::text,'UTF8')),'hex')=doc->>'original_dispatch_sha256'
  AND convert_to(to_jsonb(w)::text,'UTF8')=decode(doc->>'original_run_wire','base64') AND encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')=doc->>'original_run_sha256'
  AND pr.create_grant_id=a.grant_id AND pr.original_wire=decode(doc->>'original_preregistration_wire','base64')
  AND encode(sha256(pr.original_wire),'hex')=doc->>'original_preregistration_sha256'
  AND witness.original_wire=decode(doc->>'original_create_witness_wire','base64') AND witness.witness_sha256=doc->>'original_create_witness_sha256'
  AND witness.witness_sha256=encode(sha256(witness.original_wire),'hex') AND witness.original_record=convert_from(witness.original_wire,'UTF8')::jsonb
  AND j.run_id::text=doc->>'run_id' AND j.finalization_ack_at IS NULL AND j.return_status='failed' AND w.status='failed' AND w.finished_at=j.returned_at
  AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments WHERE preregistration_id=a.preregistration_id)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_original_installations WHERE preregistration_id=a.preregistration_id)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents WHERE preregistration_id=a.preregistration_id)) IS TRUE;
EXCEPTION WHEN others THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.witnessed_expansion_absence_read_valid106(r jsonb,a jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SET timezone='UTC' AS $$
DECLARE c jsonb:=r->'read'; receipt jsonb:=r->'receipt'; o jsonb:=r->'observation'; child public.capacity_mutation_grants;
 settlement jsonb; expected jsonb; aux jsonb; act jsonb; n integer; all_absent boolean; all_actions boolean; holds jsonb:=o->'hold_reasons';
BEGIN
 SELECT * INTO STRICT child FROM public.capacity_mutation_grants WHERE id=(a->>'child_grant_id')::uuid;
 settlement:=child.grant_record->'settlement';
 expected:=jsonb_strip_nulls(jsonb_build_object('grant',jsonb_set(child.grant_record->'grant','{state}','"settled"'::jsonb),'attempt_id',child.grant_record->'attempt_id','outcome',settlement->'outcome','transport_completed',settlement->'transport_completed','resource_id',settlement->'resource_id','resource_created_at',settlement->'resource_created_at','action_id',settlement->'action_id','next_action_ids',CASE WHEN jsonb_array_length(settlement->'next_action_ids')>0 THEN settlement->'next_action_ids' END,'auxiliary_resources',settlement->'auxiliary_resources','auxiliary_inventory_complete',settlement->'auxiliary_inventory_complete'));
 IF (child.state IN('settled','confirmed') AND child.grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a->>'id'
  AND r->>'schema'='witnessed_unenrolled_expansion_native_return_v1' AND r->>'status'='observed'
  AND r->'call_failed'='false'::jsonb AND r->'original_context_failed'='false'::jsonb
  AND c->>'schema'='witnessed_unenrolled_expansion_native_read_v1' AND c->>'kind'='absence'
  AND c->>'cleanup_id'=a->>'id' AND c->>'child_grant_id'=a->>'child_grant_id'
  AND c->>'admission_sha256'=(SELECT admission_sha256 FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=(a->>'id')::uuid)
  AND (c->>'original_deadline_core')::timestamptz>(c->>'issued_at_core')::timestamptz
  AND (c->>'original_deadline_core')::timestamptz<=(c->>'issued_at_core')::timestamptz+interval '5 seconds'
  AND (r->>'started_at_core')::timestamptz>=(c->>'issued_at_core')::timestamptz
  AND (r->>'returned_at_core')::timestamptz>=(r->>'started_at_core')::timestamptz
  AND (r->>'returned_at_core')::timestamptz<(c->>'original_deadline_core')::timestamptz
  AND convert_from(decode(r->>'read_wire','base64'),'UTF8')::jsonb=c
  AND receipt=expected AND convert_from(decode(r->>'receipt_wire','base64'),'UTF8')::jsonb=receipt
  AND receipt#>>'{grant,grant_id}'=a->>'child_grant_id' AND receipt#>>'{grant,state}'='settled'
  AND COALESCE(receipt#>>'{grant,compensation_of}','')='' AND receipt->>'outcome'='accepted' AND receipt->'transport_completed'='true'::jsonb
  AND receipt->>'resource_id'=a->>'resource_id' AND receipt->>'resource_created_at'=a->>'resource_created_at'
  AND receipt->'auxiliary_inventory_complete'='true'::jsonb AND jsonb_array_length(receipt->'auxiliary_resources') BETWEEN 1 AND 2
  AND receipt->'auxiliary_resources'=(convert_from(decode(a->>'original_grant_wire','base64'),'UTF8')::jsonb#>'{settlement,auxiliary_resources}')
  AND o->>'destroy_grant_id'=a->>'child_grant_id' AND o->>'destroy_grant_state'='settled' AND COALESCE(o->>'compensation_of','')=''
  AND o->>'id'=a->>'resource_id' AND o->>'created_at'=a->>'resource_created_at'
  AND o->>'original_outcome'='accepted' AND o->'original_transport_completed'='true'::jsonb
  AND o->'server_absence_complete'='true'::jsonb AND o->'auxiliary_inventory_complete'='true'::jsonb
  AND NOT(settlement ? 'original_provider_create_return') AND NOT(settlement ? 'original_provider_destroy_return')
  AND NOT(o ? 'aws_retirement_lifecycle') AND COALESCE(o->>'writer_quiescence_evidence','false')='false'
  AND COALESCE(o->>'provider_fencing_evidence','false')='false' AND COALESCE(o->>'invoice_reconciled','false')='false'
  AND o#>>'{delete_action,id}'=receipt->>'action_id' AND o#>>'{delete_action,known}'='true' AND o#>>'{delete_action,observed}'='true'
  AND o#>>'{delete_action,command}'='delete_server' AND o#>>'{delete_action,status}' IN('running','success') AND COALESCE(o#>>'{delete_action,error_code}','')=''
  AND jsonb_typeof(holds)='array' AND jsonb_array_length(holds)<=3
  AND (SELECT count(*) FROM jsonb_array_elements_text(holds))=(SELECT count(DISTINCT h) FROM jsonb_array_elements_text(holds) h)
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(holds) h WHERE h NOT IN('native_server_present','original_delete_actions_not_successful','native_billable_resources_present'))
  AND jsonb_array_length(o->'auxiliary_resources')=jsonb_array_length(receipt->'auxiliary_resources')
  AND jsonb_array_length(o->'next_actions')=jsonb_array_length(COALESCE(receipt->'next_action_ids','[]'::jsonb))) IS NOT TRUE THEN RETURN false; END IF;
 all_absent:=(o->>'server_absent')::boolean; all_actions:=o#>>'{delete_action,status}'='success';
 IF (CASE WHEN all_absent THEN COALESCE(o->>'server_status','')='' ELSE length(o->>'server_status')>0 END) IS NOT TRUE THEN RETURN false; END IF;
 FOR n IN 0..jsonb_array_length(receipt->'auxiliary_resources')-1 LOOP
  aux:=receipt->'auxiliary_resources'->n;
  IF (aux->>'kind'='primary_ip' AND aux->>'id' ~ '^[1-9][0-9]{0,18}$' AND (aux->>'id')::numeric<=9223372036854775807 AND aux->'requires_absence'='true'::jsonb
   AND o->'auxiliary_resources'->n->'kind'=aux->'kind' AND o->'auxiliary_resources'->n->'id'=aux->'id'
   AND jsonb_typeof(o->'auxiliary_resources'->n->'absent')='boolean') IS NOT TRUE THEN RETURN false; END IF;
  all_absent:=all_absent AND (o->'auxiliary_resources'->n->>'absent')::boolean;
 END LOOP;
 IF (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(receipt->'auxiliary_resources') x)<>jsonb_array_length(receipt->'auxiliary_resources') THEN RETURN false; END IF;
 IF jsonb_array_length(o->'next_actions')>0 THEN
  FOR n IN 0..jsonb_array_length(o->'next_actions')-1 LOOP
   act:=o->'next_actions'->n;
   IF (act->'id'=receipt->'next_action_ids'->n AND act->>'resource_id'=receipt->>'resource_id' AND COALESCE(act->>'error_code','')='' AND act->>'status' IN('running','success')) IS NOT TRUE THEN RETURN false; END IF;
   all_actions:=all_actions AND act->>'status'='success';
  END LOOP;
 END IF;
 RETURN ((holds ? 'native_server_present')<>(o->>'server_absent')::boolean
  AND (holds ? 'original_delete_actions_not_successful')<>all_actions AND (holds ? 'native_billable_resources_present')<>all_absent
  AND (o->>'billable_resources_absent')::boolean=all_absent
  AND (o->>'retirement_complete')::boolean=(all_absent AND all_actions)
  AND (r->>'complete')::boolean=(all_absent AND all_actions) AND (r->>'pending')::boolean<>((r->>'complete')::boolean)) IS TRUE;
EXCEPTION WHEN others THEN RETURN false;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_event() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups; previous public.capacity_witnessed_unenrolled_expansion_cleanup_events;
 claim public.capacity_witnessed_unenrolled_expansion_cleanup_events; intent_doc jsonb; doc jsonb:=NEW.original_record; r jsonb:=NEW.original_record->'evidence';
 child public.capacity_mutation_grants; prepared public.capacity_witnessed_unenrolled_expansion_cleanup_events; qualified_return public.capacity_witnessed_unenrolled_expansion_cleanup_events; read_doc jsonb; count_rows bigint; actual_now timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=NEW.cleanup_id FOR UPDATE;
 IF public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed expansion parent original changed'; END IF;
 SELECT count(*) INTO count_rows FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id;
 IF NEW.sequence<>count_rows+1 OR NEW.recorded_at>actual_now+interval '1 second'
 OR EXISTS(SELECT 1 FROM jsonb_object_keys(doc) k WHERE k<>ALL(ARRAY['schema','cleanup_id','sequence','stage','run_id','generation','fencing_token','lease_owner','executor_id','lease_expires_at','child_grant_id','evidence','recorded_at']))
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion event sequence or closed fields refused'; END IF;
 SELECT * INTO previous FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id ORDER BY sequence DESC LIMIT 1;
 IF previous.recorded_at>NEW.recorded_at THEN RAISE EXCEPTION 'witnessed expansion event time order refused'; END IF;
 IF previous.stage='terminal' THEN RAISE EXCEPTION 'witnessed unenrolled expansion terminal is closed'; END IF;
 SELECT ci.intent INTO STRICT intent_doc FROM public.capacity_intents ci WHERE ci.namespace=a.namespace AND ci.environment=a.environment AND ci.domain=a.domain AND ci.dimension=a.dimension FOR UPDATE;
 IF NEW.stage='requested' THEN
  IF NEW.sequence<>1 OR NEW.run_id IS NOT NULL OR intent_doc ? 'witnessed_unenrolled_expansion_cleanup_id'
  OR encode(sha256(convert_to(intent_doc::text,'UTF8')),'hex') IS DISTINCT FROM a.original_record->>'original_intent_sha256'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion requested original refused'; END IF;
  RETURN NEW;
 END IF;
 IF intent_doc->>'witnessed_unenrolled_expansion_cleanup_id' IS DISTINCT FROM a.id::text
 OR intent_doc#>>'{decision,reason}' IS DISTINCT FROM 'witnessed_unenrolled_expansion_cleanup'
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion typed current frame required'; END IF;
 IF NEW.stage='claimed' THEN
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token']) k WHERE jsonb_typeof(doc->k) IS DISTINCT FROM 'number' OR doc->>k !~ '^[1-9][0-9]*$')
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['run_id','lease_owner','executor_id']) k WHERE jsonb_typeof(doc->k) IS DISTINCT FROM 'string' OR COALESCE(doc->>k,'') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR doc->>k='00000000-0000-0000-0000-000000000000')
  OR jsonb_typeof(doc->'lease_expires_at') IS DISTINCT FROM 'string'
  THEN RAISE EXCEPTION 'witnessed expansion closed claim ownership required'; END IF;
  IF (intent_doc->>'lease_expires_at')::timestamptz>=actual_now OR NEW.run_id IS NULL
  OR (doc->>'generation')::bigint IS DISTINCT FROM (intent_doc->>'generation')::bigint
  OR (doc->>'fencing_token')::bigint IS DISTINCT FROM (intent_doc->>'fencing_token')::bigint+1
  OR (doc->>'lease_expires_at')::timestamptz<=actual_now
  OR NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
   WHERE j.run_id=NEW.run_id AND j.state='started' AND j.returned_at IS NULL AND j.finalization_ack_at IS NULL
   AND w.status='running' AND w.finished_at IS NULL AND j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension
   AND j.envelope::jsonb#>>'{workflow,id}'=a.original_record->>'workflow_id' AND j.envelope::jsonb#>>'{workflow,checksum}'=a.original_record->>'workflow_checksum'
   AND j.envelope::jsonb#>>'{policy,id}'=a.policy_id::text AND j.envelope::jsonb#>>'{policy,checksum}'=a.policy_checksum)
  OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension AND j.run_id IS DISTINCT FROM NEW.run_id AND j.id<>a.job_id AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion genuine new claim refused'; END IF;
  -- Failed raw custody remains a failure. A contiguous authenticated read
  -- from this same old owner anchors only a NEW read after real ACK/expiry.
  IF previous.stage='absence_returned' THEN
   SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
   SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-1;
   SELECT * INTO STRICT qualified_return FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-2;
   r:=previous.original_record->'evidence';read_doc:=r->'read';
   IF (prepared.stage='absence_prepared' AND qualified_return.stage IN('pending_absence','absence_complete') AND qualified_return.sequence>claim.sequence
    AND qualified_return.run_id=claim.run_id AND prepared.run_id=claim.run_id AND previous.run_id=claim.run_id
    AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token','lease_owner','executor_id','lease_expires_at']) key WHERE qualified_return.original_record->key IS DISTINCT FROM claim.original_record->key OR prepared.original_record->key IS DISTINCT FROM claim.original_record->key OR previous.original_record->key IS DISTINCT FROM claim.original_record->key)
    AND qualified_return.recorded_at>=claim.recorded_at AND prepared.recorded_at>=qualified_return.recorded_at AND previous.recorded_at>=prepared.recorded_at AND previous.recorded_at<=actual_now
    AND public.witnessed_expansion_absence_read_valid106(qualified_return.original_record->'evidence',a.original_record)
    AND (qualified_return.original_record#>>'{evidence,read,claim_sequence}')::bigint=claim.sequence
    AND ((qualified_return.stage='pending_absence' AND qualified_return.original_record#>>'{evidence,pending}'='true' AND qualified_return.original_record#>>'{evidence,complete}'='false') OR (qualified_return.stage='absence_complete' AND qualified_return.original_record#>>'{evidence,pending}'='false' AND qualified_return.original_record#>>'{evidence,complete}'='true'))
    AND jsonb_typeof(r)='object' AND (SELECT count(*) FROM jsonb_object_keys(r))=12
    AND r-ARRAY['schema','read','read_wire','receipt','receipt_wire','status','started_at_core','returned_at_core','call_failed','original_context_failed','pending','complete']='{}'::jsonb
    AND r->>'schema'='witnessed_unenrolled_expansion_native_return_v1' AND r->>'status'=''
    AND r->>'call_failed'='true' AND r->>'original_context_failed'='true' AND r->>'pending'='false' AND r->>'complete'='false'
    AND jsonb_typeof(r->'call_failed')='boolean' AND jsonb_typeof(r->'original_context_failed')='boolean' AND jsonb_typeof(r->'pending')='boolean' AND jsonb_typeof(r->'complete')='boolean'
    AND jsonb_typeof(read_doc)='object' AND (SELECT count(*) FROM jsonb_object_keys(read_doc))=9
    AND read_doc-ARRAY['schema','read_id','cleanup_id','kind','claim_sequence','admission_sha256','child_grant_id','issued_at_core','original_deadline_core']='{}'::jsonb
    AND read_doc=prepared.original_record->'evidence' AND convert_from(decode(r->>'read_wire','base64'),'UTF8')::jsonb=read_doc
    AND read_doc->>'schema'='witnessed_unenrolled_expansion_native_read_v1' AND read_doc->>'kind'='absence'
    AND read_doc->>'read_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND read_doc->>'read_id'<>'00000000-0000-0000-0000-000000000000'
    AND read_doc->>'read_id'<>qualified_return.original_record#>>'{evidence,read,read_id}'
    AND read_doc->>'cleanup_id'=a.id::text AND read_doc->>'child_grant_id'=a.child_grant_id::text
    AND read_doc->>'admission_sha256'=a.admission_sha256 AND (read_doc->>'claim_sequence')::bigint=claim.sequence
    AND r->'receipt'=qualified_return.original_record#>'{evidence,receipt}'
    AND convert_from(decode(r->>'receipt_wire','base64'),'UTF8')::jsonb=r->'receipt'
    AND (read_doc->>'original_deadline_core')::timestamptz>(read_doc->>'issued_at_core')::timestamptz
    AND (read_doc->>'original_deadline_core')::timestamptz<=(read_doc->>'issued_at_core')::timestamptz+interval '5 seconds'
    AND (read_doc->>'original_deadline_core')::timestamptz<=(claim.original_record->>'lease_expires_at')::timestamptz
    AND (r->>'started_at_core')::timestamptz>=(read_doc->>'issued_at_core')::timestamptz
    AND (r->>'started_at_core')::timestamptz<(read_doc->>'original_deadline_core')::timestamptz
    AND (r->>'returned_at_core')::timestamptz>=(read_doc->>'original_deadline_core')::timestamptz
    AND (r->>'returned_at_core')::timestamptz<=previous.recorded_at
    AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=claim.run_id AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at AND j.returned_at>=previous.recorded_at)) IS NOT TRUE
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion deadline read continuation refused'; END IF;
   previous:=qualified_return;
  END IF;
  IF previous.stage<>'requested' AND(previous.stage NOT IN('pending_absence','absence_complete') OR public.witnessed_expansion_absence_read_valid106(previous.original_record->'evidence',a.original_record) IS NOT TRUE
   OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events c JOIN public.capacity_dispatch_jobs j ON j.run_id=c.run_id JOIN public.workflow_runs w ON w.id=j.run_id
    WHERE c.cleanup_id=a.id AND c.stage='claimed' AND c.sequence=(SELECT max(sequence) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed') AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion read continuation lacks closed old owner'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
 IF NEW.run_id IS DISTINCT FROM claim.run_id OR doc->>'generation' IS DISTINCT FROM claim.original_record->>'generation'
 OR doc->>'fencing_token' IS DISTINCT FROM claim.original_record->>'fencing_token' OR doc->>'lease_owner' IS DISTINCT FROM claim.original_record->>'lease_owner'
 OR doc->>'executor_id' IS DISTINCT FROM claim.original_record->>'executor_id' OR doc->>'lease_expires_at' IS DISTINCT FROM claim.original_record->>'lease_expires_at'
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion event owner mismatch'; END IF;
 IF NEW.stage IN('inventory_returned','absence_returned') THEN
  SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage=split_part(NEW.stage,'_',1)||'_prepared' AND original_record#>>'{evidence,read_id}'=r#>>'{read,read_id}';
  IF prepared.original_record->'evidence' IS DISTINCT FROM r->'read'
  OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events prior_return WHERE prior_return.cleanup_id=a.id AND prior_return.stage=NEW.stage AND prior_return.original_record#>>'{evidence,read,read_id}'=r#>>'{read,read_id}')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion actual read return mismatch'; END IF;
  RETURN NEW; -- Failed/late raw custody is retained, never authority.
 END IF;
 IF (claim.original_record->>'lease_expires_at')::timestamptz<=actual_now
 OR (intent_doc->>'fencing_token')::bigint IS DISTINCT FROM (doc->>'fencing_token')::bigint
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion stale owner'; END IF;
 IF NEW.stage IN('issued','possible_send','terminal') THEN
  IF (SELECT COALESCE(jsonb_agg(s.slot_record-ARRAY['observed_at','receipt_ref'] ORDER BY s.slot),'[]'::jsonb) FROM public.capacity_resource_slots s WHERE (s.namespace,s.environment,s.domain,s.dimension)=(a.namespace,a.environment,a.domain,a.dimension) AND s.resource_id<>'')
   IS DISTINCT FROM (SELECT jsonb_agg(v-ARRAY['observed_at','receipt_ref'] ORDER BY ord) FROM jsonb_array_elements(convert_from(decode(a.original_record->>'survivor_roster_wire','base64'),'UTF8')::jsonb) WITH ORDINALITY x(v,ord))
  THEN RAISE EXCEPTION 'witnessed expansion original survivor identities changed'; END IF;
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
      AND rc.recorded_at>CASE WHEN NEW.stage='terminal' THEN (SELECT max(recorded_at) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='absence_complete' AND sequence>claim.sequence) ELSE claim.recorded_at END
      AND pc.recorded_at>claim.recorded_at AND rr.recorded_at>=rc.recorded_at AND pr.recorded_at>=pc.recorded_at
      AND rr.recorded_at BETWEEN actual_now-make_interval(secs=>(SELECT (spec->>'max_evidence_age_seconds')::integer FROM public.manifests WHERE id=a.policy_id)) AND actual_now)))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion fresh real survivor floor refused'; END IF;
 END IF;
 IF NEW.stage IN('inventory_prepared','absence_prepared') THEN
  IF jsonb_typeof(r) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(r))<>9
  OR r-ARRAY['schema','read_id','cleanup_id','kind','claim_sequence','admission_sha256','child_grant_id','issued_at_core','original_deadline_core']<>'{}'::jsonb
  OR EXISTS(SELECT 1 FROM jsonb_each(r) v WHERE v.value='null'::jsonb)
  OR jsonb_typeof(r->'claim_sequence') IS DISTINCT FROM 'number' OR r->>'claim_sequence' !~ '^[1-9][0-9]*$'
  OR r->>'schema' IS DISTINCT FROM 'witnessed_unenrolled_expansion_native_read_v1'
  OR COALESCE(r->>'read_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  OR r->>'read_id'='00000000-0000-0000-0000-000000000000'
  OR r->>'admission_sha256' IS DISTINCT FROM a.admission_sha256
  OR (r->>'original_deadline_core')::timestamptz>(claim.original_record->>'lease_expires_at')::timestamptz
  OR r->>'kind' IS DISTINCT FROM split_part(NEW.stage,'_',1) OR r->>'cleanup_id' IS DISTINCT FROM a.id::text OR r->>'child_grant_id' IS DISTINCT FROM a.child_grant_id::text
  OR (r->>'claim_sequence')::bigint IS DISTINCT FROM claim.sequence
  OR (r->>'original_deadline_core')::timestamptz<=(r->>'issued_at_core')::timestamptz OR (r->>'original_deadline_core')::timestamptz>(r->>'issued_at_core')::timestamptz+interval '5 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events p WHERE p.cleanup_id=a.id AND p.stage=NEW.stage AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events q WHERE q.cleanup_id=a.id AND q.stage=split_part(NEW.stage,'_',1)||'_returned' AND q.original_record#>>'{evidence,read,read_id}'=p.original_record#>>'{evidence,read_id}'))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion read preparation refused'; END IF;
  IF NEW.stage='inventory_prepared' AND EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id) THEN RAISE EXCEPTION 'witnessed unenrolled expansion inventory cannot rearm child'; END IF;
  IF NEW.stage='absence_prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id=a.child_grant_id AND g.state='settled' AND g.grant_record#>>'{settlement,outcome}'='accepted' AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true') THEN RAISE EXCEPTION 'witnessed unenrolled expansion sealed destroy required'; END IF;
 ELSIF NEW.stage IN('inventory_qualified','pending_absence','absence_complete') THEN
  IF previous.stage<>(CASE WHEN NEW.stage='inventory_qualified' THEN 'inventory_returned' ELSE 'absence_returned' END)
  OR (previous.original_record->'evidence')-ARRAY['pending','complete'] IS DISTINCT FROM r-ARRAY['pending','complete']
  OR r->>'call_failed' IS DISTINCT FROM 'false' OR r->>'original_context_failed' IS DISTINCT FROM 'false'
  OR (r->>'returned_at_core')::timestamptz>=(r#>>'{read,original_deadline_core}')::timestamptz
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion qualified return lacks complete original'; END IF;
  IF NEW.stage='inventory_qualified' THEN
   IF r->>'status' IS DISTINCT FROM 'dry_run' OR r#>>'{plan,server,id}' IS DISTINCT FROM a.original_record->>'resource_id'
   OR r#>>'{plan,server,created_at}' IS DISTINCT FROM a.original_record->>'resource_created_at'
   OR r#>>'{plan,server,physical_spec_verified}' IS DISTINCT FROM 'true' OR r#>>'{plan,server,auxiliary_inventory_complete}' IS DISTINCT FROM 'true'
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion owned attached inventory required'; END IF;
  ELSE
   IF public.witnessed_expansion_absence_read_valid106(r,a.original_record) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed unenrolled expansion observer wrapper refused'; END IF;
   IF NEW.stage='absence_complete' AND(r->>'complete' IS DISTINCT FROM 'true' OR r->>'pending' IS DISTINCT FROM 'false' OR r#>>'{observation,server_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,billable_resources_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'true' OR jsonb_array_length(r#>'{observation,hold_reasons}') IS DISTINCT FROM 0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(r#>'{observation,auxiliary_resources}') aux WHERE aux->>'absent' IS DISTINCT FROM 'true')) THEN RAISE EXCEPTION 'witnessed unenrolled expansion complete paid absence required'; END IF;
   IF NEW.stage='pending_absence' AND(r->>'pending' IS DISTINCT FROM 'true' OR r->>'complete' IS DISTINCT FROM 'false' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'false' OR jsonb_array_length(r#>'{observation,hold_reasons}') NOT BETWEEN 1 AND 3) THEN RAISE EXCEPTION 'witnessed unenrolled expansion exact pending required'; END IF;
  END IF;
 ELSIF NEW.stage='issued' THEN
  IF previous.stage IS DISTINCT FROM 'inventory_qualified' OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage IN('issued','possible_send'))
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id AND grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text AND state='issued')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion child issue is once'; END IF;
 ELSIF NEW.stage='possible_send' THEN
  IF previous.stage<>'issued' OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='possible_send')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion possible send is once'; END IF;
 ELSIF NEW.stage='terminal' THEN
  IF previous.stage IS DISTINCT FROM 'absence_complete' OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='absence_complete' AND e.sequence>claim.sequence AND public.witnessed_expansion_absence_read_valid106(e.original_record->'evidence',a.original_record))
  OR r->>'original_guest_success' IS DISTINCT FROM 'false' OR r->>'clean_cycle_credit' IS DISTINCT FROM 'false' OR r->>'serving_or_business_or_savings_authority' IS DISTINCT FROM 'false'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion terminal requires its real fresh paid absence'; END IF;
 ELSE RAISE EXCEPTION 'witnessed unenrolled expansion event stage refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_grant() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups; c public.capacity_witnessed_unenrolled_expansion_cleanup_events; g jsonb; terminal boolean;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(CASE WHEN TG_OP='DELETE' THEN ARRAY[OLD.namespace,OLD.environment,OLD.domain,OLD.dimension] ELSE ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension] END)::text,0));
 IF TG_OP='DELETE' THEN
  IF OLD.grant_record ? 'witnessed_unenrolled_expansion_cleanup_id' OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE grant_id=OLD.id) THEN RAISE EXCEPTION 'witnessed unenrolled expansion parent/child cannot be deleted'; END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE grant_id=NEW.id OR child_grant_id=NEW.id FOR SHARE;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups admitted
    WHERE admitted.namespace=NEW.namespace AND admitted.environment=NEW.environment AND admitted.domain=NEW.domain AND admitted.dimension=NEW.dimension
    AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=admitted.id AND e.stage='terminal'))
    AND(TG_OP='INSERT' OR NEW.state IS DISTINCT FROM OLD.state OR NEW.grant_record IS DISTINCT FROM OLD.grant_record)
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion active frame excludes other grants'; END IF;
  IF NEW.grant_record ? 'witnessed_unenrolled_expansion_cleanup_id' OR NEW.state='witnessed_unenrolled_cleanup_closed' THEN RAISE EXCEPTION 'unbound witnessed unenrolled expansion grant refused'; END IF;
  RETURN NEW;
 END IF;
 terminal:=EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='terminal');
 IF NEW.id=a.grant_id THEN
  IF TG_OP='INSERT' THEN RAISE EXCEPTION 'witnessed unenrolled expansion parent already exists'; END IF;
  IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
  IF OLD.state<>'settled' OR NEW.state<>'witnessed_unenrolled_cleanup_closed' OR NOT terminal
  OR NEW.grant_record- 'grant' IS DISTINCT FROM OLD.grant_record- 'grant'
  OR (NEW.grant_record->'grant')-'state' IS DISTINCT FROM (OLD.grant_record->'grant')-'state'
  OR NEW.grant_record#>>'{grant,state}' IS DISTINCT FROM 'witnessed_unenrolled_cleanup_closed'
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id AND state='confirmed')
  OR (to_jsonb(NEW)-ARRAY['state','grant_record','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','grant_record','updated_at'])
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion parent original is frozen until exact closure'; END IF;
  RETURN NEW;
 END IF;
 IF public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed expansion immutable originals required'; END IF;
 g:=NEW.grant_record;
 IF jsonb_typeof(g->'witnessed_unenrolled_expansion_cleanup_id') IS DISTINCT FROM 'string' OR g->>'witnessed_unenrolled_expansion_cleanup_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR g->>'witnessed_unenrolled_expansion_cleanup_id'='00000000-0000-0000-0000-000000000000'
 OR g->>'witnessed_unenrolled_expansion_cleanup_id' IS DISTINCT FROM a.id::text
 OR NEW.namespace<>a.namespace OR NEW.environment<>a.environment OR NEW.domain<>a.domain OR NEW.dimension<>a.dimension OR NEW.slot<>a.slot
 OR g->'binding' IS DISTINCT FROM(SELECT grant_record->'binding' FROM public.capacity_mutation_grants WHERE id=a.grant_id)
 OR NEW.integration_instance_id::text IS DISTINCT FROM g#>>'{grant,integration_instance_id}'
 OR NEW.scope_checksum IS DISTINCT FROM g#>>'{grant,scope_checksum}' OR NEW.profile_name IS DISTINCT FROM g#>>'{grant,profile_name}'
 OR g#>>'{grant,binding_name}' IS DISTINCT FROM a.original_record->>'binding_name'
 OR g#>>'{grant,integration_instance_id}' IS DISTINCT FROM g#>>'{binding,integration_instance_id}'
 OR g#>>'{grant,scope_checksum}' IS DISTINCT FROM g#>>'{binding,scope_checksum}' OR g#>>'{grant,profile_name}' IS DISTINCT FROM g#>>'{binding,profile_name}'

 OR g#>>'{grant,capability}' IS DISTINCT FROM g#>>'{binding,destroy_capability}' OR COALESCE(g#>>'{grant,compensation_of}','')<>''
 OR g#>>'{grant,expected_resource_id}' IS DISTINCT FROM a.original_record->>'resource_id' OR g#>>'{grant,expected_resource_created_at}' IS DISTINCT FROM a.original_record->>'resource_created_at'
 OR g->>'workflow_id' IS DISTINCT FROM a.original_record->>'workflow_id' OR g#>>'{grant,grant_id}' IS DISTINCT FROM NEW.id::text OR g#>>'{grant,state}' IS DISTINCT FROM NEW.state
 OR NEW.generation IS DISTINCT FROM (g->>'generation')::bigint OR NEW.expires_at IS DISTINCT FROM (g#>>'{grant,expires_at}')::timestamptz
 OR g->>'policy_id' IS DISTINCT FROM a.policy_id::text OR g->>'policy_checksum' IS DISTINCT FROM a.policy_checksum
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion exact normal destroy child required'; END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT c FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
  IF NEW.expires_at<=clock_timestamp() OR NEW.expires_at>(c.original_record->>'lease_expires_at')::timestamptz OR NEW.expires_at>(g->>'created_at')::timestamptz+interval '60 seconds' OR NEW.state<>'issued' OR terminal OR g->>'generation' IS DISTINCT FROM c.original_record->>'generation' OR g->>'fencing_token' IS DISTINCT FROM c.original_record->>'fencing_token'
  OR g->>'lease_owner' IS DISTINCT FROM c.original_record->>'lease_owner' OR g->>'executor_id' IS DISTINCT FROM c.original_record->>'executor_id'
  OR (c.original_record->>'lease_expires_at')::timestamptz<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='inventory_qualified' AND e.sequence>c.sequence AND e.sequence=(SELECT max(sequence) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion child lacks private fresh inventory owner'; END IF;
 ELSE
  IF to_jsonb(NEW)-ARRAY['state','grant_record','updated_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','grant_record','updated_at']
  OR OLD.grant_record->'witnessed_unenrolled_expansion_cleanup_id' IS DISTINCT FROM NEW.grant_record->'witnessed_unenrolled_expansion_cleanup_id'
  OR (OLD.grant_record->'grant')-'state' IS DISTINCT FROM (g->'grant')-'state'
  OR (OLD.grant_record-ARRAY['grant','attempt_id','settlement_token_sha256','settlement','proof']) IS DISTINCT FROM(g-ARRAY['grant','attempt_id','settlement_token_sha256','settlement','proof'])
  OR OLD.grant_record->'settlement' IS NOT NULL AND OLD.grant_record->'settlement' IS DISTINCT FROM g->'settlement'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion child identity or settlement immutable'; END IF;
  IF OLD.state<>NEW.state AND NOT(OLD.state='issued' AND NEW.state='redeemed' AND EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='possible_send')
   OR OLD.state='redeemed' AND NEW.state IN('settled','rejected') OR OLD.state='settled' AND NEW.state='confirmed' AND terminal)
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion child transition refused'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_intent() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups; c public.capacity_witnessed_unenrolled_expansion_cleanup_events; oid text:=OLD.intent->>'witnessed_unenrolled_expansion_cleanup_id'; nid text:=NEW.intent->>'witnessed_unenrolled_expansion_cleanup_id'; before_doc jsonb; after_doc jsonb;
BEGIN
 IF oid IS NULL AND nid IS NULL THEN RETURN NEW; END IF;
 IF NEW.intent IS NOT DISTINCT FROM OLD.intent THEN RETURN NEW; END IF;
 IF oid IS NULL THEN
  SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=nid::uuid FOR SHARE;
  IF encode(sha256(convert_to(OLD.intent::text,'UTF8')),'hex') IS DISTINCT FROM a.original_record->>'original_intent_sha256'
  OR NEW.intent#>>'{decision,reason}' IS DISTINCT FROM 'witnessed_unenrolled_expansion_cleanup'
  OR NEW.intent-ARRAY['witnessed_unenrolled_expansion_cleanup_id','decision','updated_at'] IS DISTINCT FROM OLD.intent-ARRAY['decision','updated_at']
  OR (NEW.intent->'decision')-'reason' IS DISTINCT FROM (OLD.intent->'decision')-'reason'
  OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='requested')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion requested frame mismatch'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=oid::uuid FOR SHARE;
 SELECT * INTO STRICT c FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id ORDER BY sequence DESC LIMIT 1;
 IF nid IS NULL THEN
  IF c.stage<>'terminal' OR OLD.intent->>'phase'<>'hold' OR NEW.intent->>'policy_id'=OLD.intent->>'policy_id'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion original policy remains latched'; END IF;
  RETURN NEW;
 END IF;
 IF nid<>oid THEN RAISE EXCEPTION 'witnessed unenrolled expansion intent cannot change admission'; END IF;
 IF c.stage='claimed' THEN
  IF NEW.intent-ARRAY['fencing_token','lease_owner','lease_executor_id','lease_expires_at','updated_at'] IS DISTINCT FROM OLD.intent-ARRAY['fencing_token','lease_owner','lease_executor_id','lease_expires_at','updated_at']
  OR NEW.intent->>'fencing_token' IS DISTINCT FROM c.original_record->>'fencing_token' OR NEW.intent->>'lease_owner' IS DISTINCT FROM c.original_record->>'lease_owner'
  OR NEW.intent->>'lease_executor_id' IS DISTINCT FROM c.original_record->>'executor_id' OR NEW.intent->>'lease_expires_at' IS DISTINCT FROM c.original_record->>'lease_expires_at'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion claim cannot rewrite generation or failed decision'; END IF;
 ELSIF c.stage='terminal' THEN
  IF NEW.intent->>'phase' IS DISTINCT FROM 'hold' OR NEW.intent ?| ARRAY['lease_owner','lease_executor_id','lease_expires_at']
  OR NEW.intent#>>'{decision,units}' IS DISTINCT FROM a.original_record->>'survivor_count'
  OR NEW.intent#>>'{decision,action}' IS DISTINCT FROM 'hold' OR NEW.intent#>>'{decision,reason}' IS DISTINCT FROM 'witnessed_unenrolled_cleaned_original_failure_preserved'
  OR NEW.intent#>>'{decision,execution_permitted}' IS DISTINCT FROM 'false'
  OR NEW.intent-ARRAY['phase','lease_owner','lease_executor_id','lease_expires_at','decision','updated_at'] IS DISTINCT FROM OLD.intent-ARRAY['phase','lease_owner','lease_executor_id','lease_expires_at','decision','updated_at']
  OR (NEW.intent->'decision')-ARRAY['action','reason','units','execution_permitted'] IS DISTINCT FROM (OLD.intent->'decision')-ARRAY['action','reason','units','execution_permitted']
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.grant_id AND state='witnessed_unenrolled_cleanup_closed')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion truthful terminal frame refused'; END IF;
 ELSE RAISE EXCEPTION 'witnessed unenrolled expansion generic intent write refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.immutable_witnessed_unenrolled_expansion_cleanup() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
BEGIN RAISE EXCEPTION 'witnessed unenrolled expansion original is immutable'; END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.witnessed_unenrolled_expansion_terminal_valid106(job uuid) RETURNS boolean
LANGUAGE sql STABLE SET timezone='UTC' AS $$
 SELECT COALESCE(j.state='witnessed_unenrolled_expansion_disposed' AND j.finalization_ack_at IS NULL
  AND public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS TRUE
  AND p.state='witnessed_unenrolled_cleanup_closed' AND c.state='confirmed'
  AND c.grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text
  AND j.updated_at=e.recorded_at
  AND e.original_record#>>'{evidence,original_guest_success}'='false'
  AND e.original_record#>>'{evidence,clean_cycle_credit}'='false'
  AND e.original_record#>>'{evidence,serving_or_business_or_savings_authority}'='false',false)
 FROM public.capacity_witnessed_unenrolled_expansion_cleanups a
 JOIN public.capacity_dispatch_jobs j ON j.id=a.job_id
 JOIN public.capacity_mutation_grants p ON p.id=a.grant_id
 JOIN public.capacity_mutation_grants c ON c.id=a.child_grant_id
 JOIN public.capacity_witnessed_unenrolled_expansion_cleanup_events e ON e.cleanup_id=a.id AND e.stage='terminal'
 WHERE j.id=job
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_expansion_callback106() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE p public.capacity_vm_provisioning_preregistrations; g public.capacity_mutation_grants;
BEGIN
 SELECT * INTO p FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id;
 IF NOT FOUND THEN RETURN NEW; END IF; -- Preserve the original missing-parent FK.
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=p.create_grant_id;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[g.namespace,g.environment,g.domain,g.dimension])::text,0));
 IF EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE preregistration_id=p.id)
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion callback is permanently closed'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_expansion_workflow106() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups a WHERE a.original_record->>'run_id'=OLD.id::text)
 AND (TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD) THEN RAISE EXCEPTION 'witnessed expansion original workflow is immutable'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.require_witnessed_expansion_links106() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups;
BEGIN
 IF TG_TABLE_NAME='capacity_witnessed_unenrolled_expansion_cleanups' THEN a:=NEW;
 ELSE SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=NEW.cleanup_id; END IF;
 IF public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed expansion immutable original links required'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=1 AND stage='requested')
 THEN RAISE EXCEPTION 'witnessed expansion requested event required'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='terminal') THEN
  IF public.witnessed_unenrolled_expansion_terminal_valid106(a.job_id) IS NOT TRUE
  THEN RAISE EXCEPTION 'witnessed expansion complete terminal links required'; END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM public.capacity_intents i WHERE (i.namespace,i.environment,i.domain,i.dimension)=(a.namespace,a.environment,a.domain,a.dimension) AND i.intent->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text)
 THEN RAISE EXCEPTION 'witnessed expansion intent marker required'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_expansion_job_insert106() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE current_intent jsonb; a public.capacity_witnessed_unenrolled_expansion_cleanups;
 owner public.capacity_witnessed_unenrolled_expansion_dispatch_ownership; parent public.capacity_dispatch_jobs;
 doc jsonb; original_doc jsonb; marker text; busy boolean;
BEGIN
 IF TG_OP='INSERT' AND NEW.state='witnessed_unenrolled_expansion_disposed' THEN RAISE EXCEPTION 'witnessed expansion terminal cannot be inserted'; END IF;
 busy:=NEW.state IN('queued','started','unknown') OR(NEW.state='returned' AND NEW.finalization_ack_at IS NULL);
 IF TG_OP='UPDATE' AND NOT busy THEN RETURN NEW; END IF;
 -- A claim/start/wake keeps its immutable identity and active index class.
 -- It already holds this job row; acquiring Scope here would invert Enqueue's
 -- Scope -> job order. Both physical UNIQUE indexes still cover this update.
 IF TG_OP='UPDATE' AND busy
 AND (OLD.state IN('queued','started','unknown') OR(OLD.state='returned' AND OLD.finalization_ack_at IS NULL))
 AND (NEW.id,NEW.run_id,NEW.protocol,NEW.realm,NEW.environment,NEW.domain,NEW.dimension,NEW.source_tick,NEW.envelope,NEW.envelope_sha256,NEW.created_at)
 IS NOT DISTINCT FROM (OLD.id,OLD.run_id,OLD.protocol,OLD.realm,OLD.environment,OLD.domain,OLD.dimension,OLD.source_tick,OLD.envelope,OLD.envelope_sha256,OLD.created_at)
 THEN RETURN NEW; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[NEW.realm,NEW.environment,NEW.domain,NEW.dimension])::text,0));
 -- Always lock the existing intent BEFORE discovery, including legacy jobs.
 -- Its real admission/claim/terminal updates turn an older RR snapshot into
 -- 40001 instead of letting it miss an admission or an active marked child.
 SELECT intent INTO current_intent FROM public.capacity_intents
  WHERE (namespace,environment,domain,dimension)=(NEW.realm,NEW.environment,NEW.domain,NEW.dimension) FOR UPDATE;
 IF NOT public.witnessed_expansion_dispatch_marker_present106(NEW.envelope) THEN
  IF busy AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs other
   WHERE (other.realm,other.environment,other.domain,other.dimension)=(NEW.realm,NEW.environment,NEW.domain,NEW.dimension)
   AND other.id<>NEW.id AND public.witnessed_expansion_dispatch_marker_present106(other.envelope)
   AND(other.state IN('queued','started','unknown') OR(other.state='returned' AND other.finalization_ack_at IS NULL)))
  THEN RAISE unique_violation USING MESSAGE='capacity dispatch active scope is reserved by witnessed cleanup',CONSTRAINT='capacity_dispatch_active_scope_idx'; END IF;
  RETURN NEW;
 END IF;
 doc:=NEW.envelope::jsonb; marker:=doc->>'witnessed_unenrolled_expansion_cleanup_id';
 IF jsonb_typeof(doc->'witnessed_unenrolled_expansion_cleanup_id') IS DISTINCT FROM 'string'
 OR COALESCE(marker,'') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR marker='00000000-0000-0000-0000-000000000000'
 OR (SELECT count(*) FROM json_each(NEW.envelope::json))<>(SELECT count(*) FROM jsonb_each(doc))
 THEN RAISE EXCEPTION 'witnessed expansion dispatch requires canonical typed selector'; END IF;
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=marker::uuid FOR SHARE;
 SELECT * INTO STRICT owner FROM public.capacity_witnessed_unenrolled_expansion_dispatch_ownership WHERE cleanup_id=a.id FOR UPDATE;
 SELECT * INTO STRICT parent FROM public.capacity_dispatch_jobs WHERE id=a.job_id FOR SHARE;
 original_doc:=parent.envelope::jsonb;
 IF (public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS TRUE
  AND (NEW.realm,NEW.environment,NEW.domain,NEW.dimension)=(a.namespace,a.environment,a.domain,a.dimension)
  AND NEW.id<>parent.id AND NEW.run_id<>parent.run_id AND NEW.source_tick<>parent.source_tick
  AND NEW.protocol='capacity_dispatch_prestart_v1' AND doc->>'protocol'=NEW.protocol
  AND doc->>'job_id'=NEW.id::text AND doc->>'run_id'=NEW.run_id::text
  AND doc->>'realm'=NEW.realm AND doc->>'environment'=NEW.environment AND doc->>'domain'=NEW.domain AND doc->>'dimension'=NEW.dimension AND doc->>'source_tick'=NEW.source_tick
  AND NEW.envelope_sha256=encode(sha256(convert_to(NEW.envelope,'UTF8')),'hex')
  AND doc->'policy'=original_doc->'policy' AND doc->'workflow'=original_doc->'workflow' AND doc->'rbac'=original_doc->'rbac'
  AND doc->'authorization_policy' IS NOT DISTINCT FROM original_doc->'authorization_policy'
  AND doc->'machine_principal_id'=original_doc->'machine_principal_id' AND doc->'principal_sha256'=original_doc->'principal_sha256' AND doc->'binding_sha256'=original_doc->'binding_sha256'
  AND doc->'inputs_sha256'=original_doc->'inputs_sha256' AND doc->'inputs'=original_doc->'inputs'
  AND doc#>>'{metadata,triggered_by}'='workflow_scheduler' AND original_doc#>>'{metadata,triggered_by}'='workflow_scheduler'
  AND doc#>>'{metadata,capacity_dispatch_job_id}'=NEW.id::text AND original_doc#>>'{metadata,capacity_dispatch_job_id}'=parent.id::text
  AND (doc->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id']=(original_doc->'metadata')-ARRAY['scheduled_for','capacity_dispatch_job_id']) IS NOT TRUE
 THEN RAISE EXCEPTION 'witnessed expansion dispatch selector/pins/original refused'; END IF;
 IF TG_OP='INSERT' THEN
  IF (NEW.state='queued' AND NEW.started_at IS NULL AND NEW.returned_at IS NULL AND NEW.finalization_ack_at IS NULL
   AND parent.state='unknown' AND parent.finalization_ack_at IS NULL
   AND current_intent->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text
   AND current_intent#>>'{decision,reason}'='witnessed_unenrolled_expansion_cleanup'
   AND current_intent->>'policy_id'=a.policy_id::text AND current_intent->>'policy_checksum'=a.policy_checksum
   AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='terminal')
   AND EXISTS(SELECT 1 FROM public.manifests p WHERE p.id=a.policy_id AND p.active AND p.kind='capacity_policy' AND p.checksum=a.policy_checksum
     AND NOT EXISTS(SELECT 1 FROM public.manifests other WHERE (other.kind,other.namespace,other.name)=(p.kind,p.namespace,p.name) AND(other.version>p.version OR other.active AND other.id<>p.id)))
   AND EXISTS(SELECT 1 FROM public.manifests wf WHERE wf.id=(a.original_record->>'workflow_id')::uuid AND wf.kind='workflow' AND wf.active AND wf.checksum=a.original_record->>'workflow_checksum')) IS NOT TRUE
  THEN RAISE EXCEPTION 'witnessed expansion enqueue requires active exact frame'; END IF;
  -- This real row UPDATE is an ownership CAS: a stale RR reader aborts.
  UPDATE public.capacity_witnessed_unenrolled_expansion_dispatch_ownership
   SET revision=owner.revision+1,job_id=NEW.id,updated_at=clock_timestamp()
   WHERE cleanup_id=a.id AND revision=owner.revision;
  IF NOT FOUND THEN RAISE EXCEPTION 'witnessed expansion dispatch ownership changed'; END IF;
 ELSE
  IF owner.job_id IS DISTINCT FROM NEW.id OR doc->>'witnessed_unenrolled_expansion_cleanup_id' IS DISTINCT FROM OLD.envelope::jsonb->>'witnessed_unenrolled_expansion_cleanup_id'
  THEN RAISE EXCEPTION 'witnessed expansion current dispatch ownership required'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.initialize_witnessed_expansion_dispatch106() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
BEGIN
 INSERT INTO public.capacity_witnessed_unenrolled_expansion_dispatch_ownership(cleanup_id,revision,job_id,updated_at) VALUES(NEW.id,0,NULL,NEW.recorded_at);
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_witnessed_expansion_dispatch_ownership106() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'witnessed expansion dispatch ownership is permanent'; END IF;
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=NEW.cleanup_id;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>0 OR NEW.job_id IS NOT NULL OR NEW.updated_at<>a.recorded_at THEN RAISE EXCEPTION 'witnessed expansion initial ownership refused'; END IF;
 ELSIF NEW.cleanup_id<>OLD.cleanup_id OR NEW.revision<>OLD.revision+1 OR NEW.job_id IS NULL OR NEW.job_id IS NOT DISTINCT FROM OLD.job_id OR NEW.updated_at<OLD.updated_at
 THEN RAISE EXCEPTION 'witnessed expansion ownership CAS refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.require_witnessed_expansion_dispatch_ownership106() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE owner public.capacity_witnessed_unenrolled_expansion_dispatch_ownership; a public.capacity_witnessed_unenrolled_expansion_cleanups; count_rows bigint;
BEGIN
 SELECT * INTO STRICT owner FROM public.capacity_witnessed_unenrolled_expansion_dispatch_ownership WHERE cleanup_id=NEW.cleanup_id;
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=owner.cleanup_id;
 SELECT count(*) INTO count_rows FROM public.capacity_dispatch_jobs WHERE (CASE WHEN public.witnessed_expansion_dispatch_marker_present106(envelope) THEN envelope::jsonb->>'witnessed_unenrolled_expansion_cleanup_id' END)=a.id::text;
 IF owner.revision<>count_rows OR(owner.revision>0 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j
   WHERE j.id=owner.job_id AND (CASE WHEN public.witnessed_expansion_dispatch_marker_present106(j.envelope) THEN j.envelope::jsonb->>'witnessed_unenrolled_expansion_cleanup_id' END)=a.id::text
   AND(j.realm,j.environment,j.domain,j.dimension)=(a.namespace,a.environment,a.domain,a.dimension)))
 THEN RAISE EXCEPTION 'witnessed expansion dispatch ownership must join exact job history'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state='witnessed_unenrolled_expansion_disposed' OR NEW.state='witnessed_unenrolled_expansion_disposed' THEN
        IF OLD.state='witnessed_unenrolled_expansion_disposed' AND NEW IS NOT DISTINCT FROM OLD
        AND public.witnessed_unenrolled_expansion_terminal_valid106(OLD.id) IS TRUE THEN RETURN NEW; END IF;
        IF OLD.state<>'unknown' OR NEW.state<>'witnessed_unenrolled_expansion_disposed'
        OR (to_jsonb(NEW)-ARRAY['state','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','updated_at'])
        OR OLD.finalization_ack_at IS NOT NULL OR NOT EXISTS(
          SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups a
          JOIN public.capacity_witnessed_unenrolled_expansion_cleanup_events e ON e.cleanup_id=a.id AND e.stage='terminal'
          JOIN public.capacity_mutation_grants p ON p.id=a.grant_id AND p.state='witnessed_unenrolled_cleanup_closed'
          JOIN public.capacity_mutation_grants c ON c.id=a.child_grant_id AND c.state='confirmed'
          WHERE a.job_id=OLD.id AND NEW.updated_at=e.recorded_at AND public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS TRUE)
        THEN RAISE EXCEPTION 'witnessed expansion terminal requires exact confirmed cleanup and original UNKNOWN'; END IF;
        RETURN NEW;
    END IF;
    IF EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups a WHERE a.job_id=OLD.id) AND NEW IS DISTINCT FROM OLD
    THEN RAISE EXCEPTION 'witnessed expansion original dispatch is permanently frozen'; END IF;
    IF OLD.state='superseded_http_maintenance_disposed' OR NEW.state='superseded_http_maintenance_disposed' THEN
        RETURN public.check_superseded_http_maintenance_dispatch_transition(OLD,NEW);
    END IF;
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
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (SELECT count(*)=1 FROM public.capacity_dispatch_jobs j WHERE j.run_id=own AND j.state='started' AND j.started_at IS NOT NULL AND j.returned_at IS NULL AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND (j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' OR (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}')=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed') OR (j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL)))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='installed_timeout_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.installed_provision_timeout_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='preaction_plan_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.preaction_failed_plan_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire,d.evidence_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions d
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND public.superseded_http_maintenance_dispatch_terminal_valid(j.id) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups a WHERE a.job_id=j.id AND public.witnessed_unenrolled_expansion_terminal_valid106(j.id) IS TRUE))
 AND NOT EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.id<>own AND (w.workflow_id IN(SELECT id FROM public.manifests WHERE kind='workflow' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(r#>>'{original,Request,intent,tuple,integration_instance_id}',r#>>'{original,Request,intent,tuple,scope_checksum}',r#>>'{original,Request,intent,tuple,profile}') AND g.state IN('issued','redeemed','settled','compensating') AND g.id::text<>r->>'destroy_grant_id')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(r#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
$$;
-- +goose StatementEnd

ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v12_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v12_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v13_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v13_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v13_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed','superseded_http_maintenance_disposed','witnessed_unenrolled_expansion_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v13_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed','superseded_http_maintenance_disposed','witnessed_unenrolled_expansion_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));


CREATE TRIGGER witnessed_expansion_admission106 BEFORE INSERT ON public.capacity_witnessed_unenrolled_expansion_cleanups FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup();
CREATE TRIGGER witnessed_expansion_immutable106 BEFORE UPDATE OR DELETE ON public.capacity_witnessed_unenrolled_expansion_cleanups FOR EACH ROW EXECUTE FUNCTION public.immutable_witnessed_unenrolled_expansion_cleanup();
CREATE TRIGGER witnessed_expansion_events_immutable106 BEFORE UPDATE OR DELETE ON public.capacity_witnessed_unenrolled_expansion_cleanup_events FOR EACH ROW EXECUTE FUNCTION public.immutable_witnessed_unenrolled_expansion_cleanup();
CREATE TRIGGER witnessed_expansion_event106 BEFORE INSERT ON public.capacity_witnessed_unenrolled_expansion_cleanup_events FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_event();
CREATE TRIGGER witnessed_expansion_grant106 BEFORE INSERT OR UPDATE OR DELETE ON public.capacity_mutation_grants FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_grant();
CREATE TRIGGER witnessed_expansion_intent106 BEFORE UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_intent();
CREATE TRIGGER witnessed_expansion_enrollment106 BEFORE INSERT ON public.capacity_vm_original_enrollments FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_expansion_callback106();
CREATE TRIGGER witnessed_expansion_installation106 BEFORE INSERT ON public.capacity_guest_original_installations FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_expansion_callback106();
CREATE TRIGGER witnessed_expansion_workflow106 BEFORE UPDATE OR DELETE ON public.workflow_runs FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_expansion_workflow106();
CREATE CONSTRAINT TRIGGER witnessed_expansion_links106 AFTER INSERT ON public.capacity_witnessed_unenrolled_expansion_cleanups DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_witnessed_expansion_links106();
CREATE CONSTRAINT TRIGGER witnessed_expansion_terminal_links106 AFTER INSERT ON public.capacity_witnessed_unenrolled_expansion_cleanup_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_witnessed_expansion_links106();
CREATE TRIGGER witnessed_expansion_job_insert106 BEFORE INSERT OR UPDATE ON public.capacity_dispatch_jobs FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_expansion_job_insert106();
CREATE TRIGGER witnessed_expansion_dispatch_init106 AFTER INSERT ON public.capacity_witnessed_unenrolled_expansion_cleanups FOR EACH ROW EXECUTE FUNCTION public.initialize_witnessed_expansion_dispatch106();
CREATE TRIGGER witnessed_expansion_dispatch_ownership106 BEFORE INSERT OR UPDATE OR DELETE ON public.capacity_witnessed_unenrolled_expansion_dispatch_ownership FOR EACH ROW EXECUTE FUNCTION public.guard_witnessed_expansion_dispatch_ownership106();
CREATE CONSTRAINT TRIGGER witnessed_expansion_dispatch_links106 AFTER INSERT OR UPDATE ON public.capacity_witnessed_unenrolled_expansion_dispatch_ownership DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_witnessed_expansion_dispatch_ownership106();
-- +goose Down
-- Used originals are permanent, including an admitted but unfinished cleanup.
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanups) THEN RAISE EXCEPTION 'used witnessed unenrolled expansion cleanup is permanent provenance'; END IF; END; $$;
-- +goose StatementEnd
DROP TRIGGER witnessed_expansion_admission106 ON public.capacity_witnessed_unenrolled_expansion_cleanups;
DROP TRIGGER witnessed_expansion_immutable106 ON public.capacity_witnessed_unenrolled_expansion_cleanups;
DROP TRIGGER witnessed_expansion_events_immutable106 ON public.capacity_witnessed_unenrolled_expansion_cleanup_events;
DROP TRIGGER witnessed_expansion_event106 ON public.capacity_witnessed_unenrolled_expansion_cleanup_events;
DROP TRIGGER witnessed_expansion_grant106 ON public.capacity_mutation_grants;
DROP TRIGGER witnessed_expansion_intent106 ON public.capacity_intents;
DROP TRIGGER witnessed_expansion_enrollment106 ON public.capacity_vm_original_enrollments;
DROP TRIGGER witnessed_expansion_installation106 ON public.capacity_guest_original_installations;
DROP TRIGGER witnessed_expansion_workflow106 ON public.workflow_runs;
DROP TRIGGER witnessed_expansion_links106 ON public.capacity_witnessed_unenrolled_expansion_cleanups;
DROP TRIGGER witnessed_expansion_terminal_links106 ON public.capacity_witnessed_unenrolled_expansion_cleanup_events;
DROP TRIGGER witnessed_expansion_job_insert106 ON public.capacity_dispatch_jobs;
DROP TRIGGER witnessed_expansion_dispatch_init106 ON public.capacity_witnessed_unenrolled_expansion_cleanups;
DROP TRIGGER witnessed_expansion_dispatch_ownership106 ON public.capacity_witnessed_unenrolled_expansion_dispatch_ownership;
DROP TRIGGER witnessed_expansion_dispatch_links106 ON public.capacity_witnessed_unenrolled_expansion_dispatch_ownership;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state='superseded_http_maintenance_disposed' OR NEW.state='superseded_http_maintenance_disposed' THEN
        RETURN public.check_superseded_http_maintenance_dispatch_transition(OLD,NEW);
    END IF;
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
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (SELECT count(*)=1 FROM public.capacity_dispatch_jobs j WHERE j.run_id=own AND j.state='started' AND j.started_at IS NOT NULL AND j.returned_at IS NULL AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND (j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' OR (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}')=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed') OR (j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL)))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='installed_timeout_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.installed_provision_timeout_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='preaction_plan_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.preaction_failed_plan_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire,d.evidence_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions d
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND public.superseded_http_maintenance_dispatch_terminal_valid(j.id) IS TRUE))
 AND NOT EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.id<>own AND (w.workflow_id IN(SELECT id FROM public.manifests WHERE kind='workflow' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(r#>>'{original,Request,intent,tuple,integration_instance_id}',r#>>'{original,Request,intent,tuple,scope_checksum}',r#>>'{original,Request,intent,tuple,profile}') AND g.state IN('issued','redeemed','settled','compensating') AND g.id::text<>r->>'destroy_grant_id')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(r#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
$$;
-- +goose StatementEnd
DROP INDEX public.capacity_witnessed_expansion_active_scope106_idx;
DROP INDEX public.capacity_dispatch_active_scope_idx;
CREATE UNIQUE INDEX capacity_dispatch_active_scope_idx ON public.capacity_dispatch_jobs(realm,environment,domain,dimension) WHERE state IN('queued','started','unknown') OR(state='returned' AND finalization_ack_at IS NULL);
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_state_v13_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_lifecycle_v13_check;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v12_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed','superseded_http_maintenance_disposed'));
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v12_check CHECK(
 (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
 OR(state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
 OR(state='unknown' AND started_at IS NOT NULL)
 OR(state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed','http_maintenance_disposed','installed_timeout_disposed','preaction_plan_disposed','superseded_http_maintenance_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
 OR(state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));

DROP INDEX public.capacity_mutation_grants_open_slot_idx;
CREATE UNIQUE INDEX capacity_mutation_grants_open_slot_idx
 ON public.capacity_mutation_grants(integration_instance_id,scope_checksum,profile_name,slot)
 WHERE state IN('issued','redeemed','settled') AND original_disposition_id IS NULL
 AND failed_original_disposition_id IS NULL AND native_denied_disposition_id IS NULL
 AND enrolled_failed_disposition_id IS NULL AND failed_unwitnessed_expansion_cleanup_id IS NULL;

ALTER TABLE public.capacity_mutation_grants DROP CONSTRAINT capacity_mutation_grants_state_check;
ALTER TABLE public.capacity_mutation_grants ADD CONSTRAINT capacity_mutation_grants_state_check CHECK(state IN('issued','redeemed','settled','confirmed','rejected','expired','compensating','compensated','cleanup_closed'));
DROP FUNCTION public.require_witnessed_expansion_dispatch_ownership106();
DROP FUNCTION public.guard_witnessed_expansion_dispatch_ownership106();
DROP FUNCTION public.initialize_witnessed_expansion_dispatch106();
DROP FUNCTION public.guard_witnessed_expansion_job_insert106();
DROP FUNCTION public.require_witnessed_expansion_links106();
DROP FUNCTION public.guard_witnessed_expansion_workflow106();
DROP FUNCTION public.guard_witnessed_expansion_callback106();
DROP FUNCTION public.witnessed_unenrolled_expansion_terminal_valid106(uuid);
DROP FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_event();
DROP FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_grant();
DROP FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_intent();
DROP FUNCTION public.witnessed_expansion_absence_read_valid106(jsonb,jsonb);
DROP FUNCTION public.witnessed_unenrolled_expansion_parent_valid106(uuid);
DROP FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup();
DROP FUNCTION public.immutable_witnessed_unenrolled_expansion_cleanup();
DROP FUNCTION public.witnessed_expansion_dispatch_marker_present106(text);
DROP TABLE public.capacity_witnessed_unenrolled_expansion_dispatch_ownership;
DROP TABLE public.capacity_witnessed_unenrolled_expansion_cleanup_events;
DROP TABLE public.capacity_witnessed_unenrolled_expansion_cleanups;
