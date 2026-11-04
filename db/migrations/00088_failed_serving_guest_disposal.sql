-- +goose Up
-- Distinct history-preserving quarantine. All provider mutations remain
-- operator-owned; these immutable rows authorize only bounded native reads.
CREATE TABLE IF NOT EXISTS public.capacity_guest_failed_serving_disposals (
    row_id uuid PRIMARY KEY,
    admission_id uuid NOT NULL REFERENCES public.capacity_guest_failed_serving_disposals(row_id) DEFERRABLE INITIALLY DEFERRED,
    quiescent_row_id uuid REFERENCES public.capacity_guest_failed_serving_disposals(row_id),
    stage text NOT NULL CHECK (stage IN ('quarantined','quiescent','terminal')),
    namespace text NOT NULL,
    environment text NOT NULL,
    domain text NOT NULL,
    dimension text NOT NULL,
    preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id),
    original_wire bytea NOT NULL,
    original_record jsonb NOT NULL,
    record_sha256 text NOT NULL CHECK (record_sha256 = encode(sha256(original_wire),'hex')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (original_record = convert_from(original_wire,'UTF8')::jsonb),
    CHECK ((original_record->>'id' = admission_id::text) IS TRUE),
    CHECK ((original_record->>'record_id' = row_id::text) IS TRUE),
    CHECK ((original_record->>'stage' = stage) IS TRUE),
    CHECK ((original_record->>'preregistration_id' = preregistration_id::text) IS TRUE),
    CHECK ((stage='quarantined') = (row_id=admission_id)),
    CHECK ((stage='terminal') = (quiescent_row_id IS NOT NULL)),
    CHECK ((original_record->>'namespace'=namespace AND original_record->>'environment'=environment
           AND original_record->>'domain'=domain AND original_record->>'dimension'=dimension) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_failed_serving_unique_terminal
ON public.capacity_guest_failed_serving_disposals(admission_id,stage);
CREATE INDEX IF NOT EXISTS capacity_failed_serving_scope
ON public.capacity_guest_failed_serving_disposals(namespace,environment,domain,dimension,recorded_at,row_id);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_failed_serving_original_identity
ON public.capacity_guest_failed_serving_disposals(preregistration_id) WHERE stage='quarantined';

-- SQL owns structural lineage, same-lock scope/CAS, and immutable byte custody.
-- Native authentication, full provider content and original signed enrollment
-- remain in the source-owned Go collector/validators, not caller booleans here.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_failed_serving_disposal_insert()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a public.capacity_guest_failed_serving_disposals;
        q public.capacity_guest_failed_serving_disposals;
        g public.capacity_mutation_grants;
        current_record jsonb; original_record jsonb; slot_record jsonb;
        r jsonb := NEW.original_record;
BEGIN
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension]) n
           WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'one compact JSON dimension lock encoding required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension])::text,0));
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[r#>>'{candidate,Binding,integration_instance_id}',r#>>'{candidate,Binding,scope_checksum}',r#>>'{candidate,Binding,profile_name}']) n
           WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'one compact JSON native slot lock encoding required'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(format('["capacity-native-slot",%s,%s,%s,1]',
  to_json(r#>>'{candidate,Binding,integration_instance_id}')::text,to_json(r#>>'{candidate,Binding,scope_checksum}')::text,to_json(r#>>'{candidate,Binding,profile_name}')::text),0));
 SELECT intent INTO STRICT current_record FROM public.capacity_intents WHERE namespace=NEW.namespace
  AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension FOR UPDATE;
 IF (r->>'schema'<>'failed_serving_guest_disposal_v1' OR r->>'actual_core_source' !~ '^[0-9a-f]{40}$'
     OR r->>'business_effects_preserved'<>'true' OR r->>'Core_or_Guest_native_write_sent'<>'false'
     OR r->>'Guest_writer_drain_claimed'<>'false' OR r->>'issuer' !~ '^collaborator:[0-9a-f-]{36}$'
     OR (r->>'recorded_at')::timestamptz<>NEW.recorded_at
     OR (r->>'original_read_returned_at')::timestamptz<(r->>'original_read_started_at')::timestamptz
     OR (r->>'original_read_returned_at')::timestamptz>clock_timestamp()+interval '5 seconds') IS NOT FALSE
 THEN RAISE EXCEPTION 'closed source-derived read lineage required'; END IF;
 original_record := convert_from(decode(r->>'original_intent_wire','base64'),'UTF8')::jsonb;
 IF (r->>'original_intent_sha256'<>encode(sha256(decode(r->>'original_intent_wire','base64')),'hex')
     OR original_record->>'phase' NOT IN('promoted','reconciled','reconciled_partial') OR original_record->>'recovery_only'<>'false'
     OR COALESCE(original_record->>'floor_degraded','false')<>'false'
     OR original_record#>>'{decision,units}'<>'1' OR original_record#>>'{assessment,snapshot,units}'<>'1'
     OR current_record->>'policy_id'<>original_record->>'policy_id'
     OR current_record->>'policy_checksum'<>original_record->>'policy_checksum'
     OR current_record->>'generation'<>original_record->>'generation'
     OR (current_record->>'fencing_token')::bigint<>(original_record->>'fencing_token')::bigint+1
     OR current_record#>>'{failed_serving_disposal,id}'<>NEW.admission_id::text
     OR current_record#>>'{failed_serving_disposal,preregistration_id}'<>NEW.preregistration_id::text
     OR current_record#>>'{failed_serving_disposal,original_intent_sha256}'<>r->>'original_intent_sha256'
     OR COALESCE(current_record->>'lease_owner','')<>'' OR COALESCE(current_record->>'lease_executor_id','')<>'' OR current_record ? 'lease_expires_at'
     OR current_record#>>'{decision,execution_permitted}'<>'false') IS NOT FALSE
 THEN RAISE EXCEPTION 'same original stable epoch and frozen quarantine required'; END IF;
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=(r#>>'{candidate,Request,grant_id}')::uuid FOR SHARE;
 IF (g.namespace<>NEW.namespace OR g.environment<>NEW.environment OR g.domain<>NEW.domain OR g.dimension<>NEW.dimension
     OR g.slot<>1 OR g.state<>'confirmed' OR g.grant_record->'binding'<>r#>'{candidate,Binding}'
     OR (r#>>'{candidate,Preregistration,generation}')::bigint<1
     OR (r#>>'{candidate,Preregistration,generation}')::bigint>(original_record->>'generation')::bigint
     OR (r#>>'{candidate,Preregistration,fence}')::bigint<1
     OR (r#>>'{candidate,Preregistration,fence}')::bigint>(original_record->>'fencing_token')::bigint
     OR g.grant_record->>'generation'<>r#>>'{candidate,Preregistration,generation}'
     OR g.grant_record->>'fencing_token'<>r#>>'{candidate,Preregistration,fence}'
     OR g.grant_record->>'policy_id'<>r#>>'{candidate,Preregistration,policy_id}'
     OR g.grant_record->>'policy_checksum'<>r#>>'{candidate,Preregistration,policy_checksum}'
     OR g.expires_at>=clock_timestamp() OR (g.grant_record#>>'{grant,expires_at}')::timestamptz<>g.expires_at
     OR (r#>>'{candidate,Preregistration,original_deadline}')::timestamptz>=clock_timestamp()
     OR (r#>>'{candidate,Preregistration,original_workflow_context_deadline}')::timestamptz>=clock_timestamp()
     OR g.grant_record#>>'{settlement,resource_id}'<>r#>>'{candidate,Request,expected_resource_id}'
     OR g.grant_record#>>'{settlement,resource_created_at}'<>r#>>'{candidate,Request,expected_resource_created_at}'
     OR g.id<>(SELECT create_grant_id FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id)) IS NOT FALSE
 THEN RAISE EXCEPTION 'exact original confirmed create and native scope required'; END IF;
 SELECT s.slot_record INTO STRICT slot_record FROM public.capacity_resource_slots s
  WHERE s.integration_instance_id=g.integration_instance_id AND s.scope_checksum=g.scope_checksum AND s.profile_name=g.profile_name AND s.slot=1 FOR UPDATE;
 IF slot_record->>'failed_serving_disposal_id' IS DISTINCT FROM NEW.admission_id::text
 THEN RAISE EXCEPTION 'same frozen logical native slot required'; END IF;
 IF NEW.stage='quarantined' THEN
  IF (current_record->>'phase'<>'serving_guest_quarantined'
     OR r->>'quarantine_intent_sha256'<>encode(sha256(convert_to(current_record::text,'UTF8')),'hex')
     OR current_record#>>'{failed_serving_disposal,stage}'<>'quarantined'
     OR (r->>'historical_accepted_read_count')::int<1 OR (r->>'historical_promoted_count')::int<1
     OR (r->>'historical_accepted_read_count')::int<>(SELECT count(*) FROM public.capacity_guest_notify_canary_challenges c JOIN public.capacity_guest_notify_canary_returns cr ON cr.challenge_id=c.id WHERE c.preregistration_id=NEW.preregistration_id AND c.phase='read' AND cr.outcome='accepted')
     OR (r->>'historical_promoted_count')::int<>(SELECT count(*) FROM public.capacity_intent_events e WHERE e.namespace=NEW.namespace AND e.environment=NEW.environment AND e.domain=NEW.domain AND e.dimension=NEW.dimension AND e.generation=(r#>>'{candidate,Preregistration,generation}')::bigint AND e.phase='promoted')
     OR NOT EXISTS(SELECT 1 FROM public.capacity_intent_events e WHERE e.namespace=NEW.namespace AND e.environment=NEW.environment AND e.domain=NEW.domain AND e.dimension=NEW.dimension
       AND e.generation=(original_record->>'generation')::bigint AND e.fencing_token=(original_record->>'fencing_token')::bigint AND e.phase=original_record->>'phase'
       AND encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex')=r->>'current_stable_event_sha256')
     OR NOT EXISTS(SELECT 1 FROM public.capacity_intent_events e WHERE e.namespace=NEW.namespace AND e.environment=NEW.environment AND e.domain=NEW.domain AND e.dimension=NEW.dimension
       AND e.generation=(r#>>'{candidate,Preregistration,generation}')::bigint AND e.phase='promoted')
     OR jsonb_array_length(r#>'{inventory,members}')<>1 OR jsonb_array_length(r#>'{inventory,missing_slots}')<>7
     OR EXISTS(SELECT 1 FROM public.capacity_guest_failed_serving_disposals x WHERE x.stage='quarantined'
       AND x.namespace=NEW.namespace AND x.environment=NEW.environment AND x.domain=NEW.domain AND x.dimension=NEW.dimension
       AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_failed_serving_disposals t WHERE t.admission_id=x.admission_id AND t.stage='terminal'))) IS NOT FALSE
  THEN RAISE EXCEPTION 'single active previously serving admission and complete native inventory1 required'; END IF;
 ELSE
  SELECT * INTO STRICT a FROM public.capacity_guest_failed_serving_disposals WHERE row_id=NEW.admission_id AND stage='quarantined' FOR SHARE;
  IF (a.preregistration_id<>NEW.preregistration_id OR a.namespace<>NEW.namespace OR a.environment<>NEW.environment
      OR a.domain<>NEW.domain OR a.dimension<>NEW.dimension
      OR (r-ARRAY['record_id','stage','issuer','actual_core_source','recorded_at','inventory','native_off','absence','native_off_record_id','terminal_intent_sha256','original_read_started_at','original_read_returned_at'])
       <> (a.original_record-ARRAY['record_id','stage','issuer','actual_core_source','recorded_at','inventory','native_off','absence','native_off_record_id','terminal_intent_sha256','original_read_started_at','original_read_returned_at'])) IS NOT FALSE
  THEN RAISE EXCEPTION 'read stage must retain complete original admission'; END IF;
  IF NEW.stage='quiescent' THEN
   IF (current_record->>'phase'<>'serving_guest_quarantined'
      OR a.original_record->>'quarantine_intent_sha256'<>encode(sha256(convert_to(current_record::text,'UTF8')),'hex')
      OR COALESCE(r#>>'{native_off,server,status}','') NOT IN('off','stopped')
      OR r#>>'{native_off,server,id}' IS DISTINCT FROM r#>>'{candidate,Request,expected_resource_id}'
      OR r#>>'{native_off,server,created_at}' IS DISTINCT FROM r#>>'{candidate,Request,expected_resource_created_at}') IS NOT FALSE
   THEN RAISE EXCEPTION 'fresh exact native OFF observation required'; END IF;
  ELSE
   SELECT * INTO STRICT q FROM public.capacity_guest_failed_serving_disposals WHERE row_id=NEW.quiescent_row_id AND admission_id=NEW.admission_id AND stage='quiescent' FOR SHARE;
   IF (r->>'native_off_record_id'<>q.row_id::text OR current_record->>'phase'<>'disposed_failed_serving'
       OR r->>'terminal_intent_sha256'<>encode(sha256(convert_to(current_record::text,'UTF8')),'hex')
       OR current_record#>>'{failed_serving_disposal,stage}'<>'terminal' OR current_record#>>'{assessment,snapshot,units}'<>'0'
       OR current_record#>>'{decision,units}'<>'0' OR slot_record->>'tombstone'<>'true' OR COALESCE(slot_record->>'resource_id','')<>''
       OR jsonb_array_length(r#>'{inventory,members}')<>0 OR jsonb_array_length(r#>'{inventory,missing_slots}')<>8
       OR (SELECT array_agg(DISTINCT n::int ORDER BY n::int) FROM jsonb_array_elements_text(r#>'{inventory,missing_slots}') n)<>ARRAY[1,2,3,4,5,6,7,8]
       OR r#>>'{absence,resource_absence_complete}'<>'true' OR r#>>'{absence,auxiliary_inventory_complete}'<>'true'
       OR r#>>'{absence,resource_id}'<>r#>>'{candidate,Request,expected_resource_id}'
       OR r#>>'{absence,resource_created_at}'<>r#>>'{candidate,Request,expected_resource_created_at}') IS NOT FALSE
   THEN RAISE EXCEPTION 'linked OFF then exact complete absence and real whole-fleet inventory0 required'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS failed_serving_disposal_insert ON public.capacity_guest_failed_serving_disposals;
CREATE TRIGGER failed_serving_disposal_insert BEFORE INSERT ON public.capacity_guest_failed_serving_disposals
FOR EACH ROW EXECUTE FUNCTION public.guard_failed_serving_disposal_insert();

-- Completion must append its terminal in the SAME transaction as the intent.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_failed_serving_intent_link()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r public.capacity_guest_failed_serving_disposals;
BEGIN
 IF NEW.intent->>'phase' IN('serving_guest_quarantined','disposed_failed_serving') THEN
  SELECT * INTO STRICT r FROM public.capacity_guest_failed_serving_disposals
   WHERE admission_id=(NEW.intent#>>'{failed_serving_disposal,id}')::uuid
    AND stage=CASE WHEN NEW.intent->>'phase'='disposed_failed_serving' THEN 'terminal' ELSE 'quarantined' END
    AND namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension
   ORDER BY recorded_at DESC LIMIT 1;
  IF (CASE WHEN NEW.intent->>'phase'='disposed_failed_serving' THEN r.original_record->>'terminal_intent_sha256' ELSE r.original_record->>'quarantine_intent_sha256' END)
     IS DISTINCT FROM encode(sha256(convert_to(NEW.intent::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'current recovery intent must retain the exact committed stage wire'; END IF;
  IF TG_OP='UPDATE' AND OLD.intent->>'phase'='serving_guest_quarantined'
     AND NEW.intent->>'phase'='disposed_failed_serving'
     AND r.original_record->>'quarantine_intent_sha256'<>encode(sha256(convert_to(OLD.intent::text,'UTF8')),'hex')
  THEN RAISE EXCEPTION 'terminal must CAS exact frozen quarantine wire'; END IF;
 ELSIF TG_OP='UPDATE' AND OLD.intent->>'phase'='serving_guest_quarantined' AND NEW.intent IS DISTINCT FROM OLD.intent THEN
  RAISE EXCEPTION 'active serving quarantine cannot be recovered or replaced implicitly';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS failed_serving_intent_link ON public.capacity_intents;
CREATE CONSTRAINT TRIGGER failed_serving_intent_link AFTER INSERT OR UPDATE ON public.capacity_intents
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.guard_failed_serving_intent_link();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_failed_serving_immutable()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'failed serving Guest original records are immutable';
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS capacity_failed_serving_immutable ON public.capacity_guest_failed_serving_disposals;
CREATE TRIGGER capacity_failed_serving_immutable BEFORE UPDATE OR DELETE
ON public.capacity_guest_failed_serving_disposals FOR EACH ROW
EXECUTE FUNCTION public.capacity_failed_serving_immutable();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_guest_failed_serving_disposals)
 THEN RAISE EXCEPTION 'cannot discard failed serving Guest immutable history'; END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS failed_serving_intent_link ON public.capacity_intents;
DROP FUNCTION IF EXISTS public.guard_failed_serving_intent_link();
DROP TABLE IF EXISTS public.capacity_guest_failed_serving_disposals;
DROP FUNCTION IF EXISTS public.capacity_failed_serving_immutable();
DROP FUNCTION IF EXISTS public.guard_failed_serving_disposal_insert();
