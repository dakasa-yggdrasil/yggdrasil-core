-- +goose Up
-- Core-only forward proof. Original Guest V2 records and normal five-row proof
-- are neither updated nor reinterpreted. SQL guards supplement Go crypto/IO.
CREATE TABLE IF NOT EXISTS public.capacity_guest_retirement_forwards (
 id uuid NOT NULL,
 stage text NOT NULL CHECK(stage IN('requested','admitted','off_qualified','terminal')),
 retirement_request_id uuid NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
 preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
 namespace text NOT NULL, environment text NOT NULL, domain text NOT NULL, dimension text NOT NULL,
 integration_instance_id text NOT NULL, scope_checksum text NOT NULL, profile_name text NOT NULL,
 slot integer NOT NULL CHECK(slot BETWEEN 2 AND 8),
 record_sha256 text NOT NULL CHECK(record_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 2 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),
 recorded_at timestamptz NOT NULL,
 PRIMARY KEY(id,stage),
 CHECK((original_record=convert_from(original_wire,'UTF8')::jsonb) IS TRUE),
 CHECK((encode(digest(original_wire,'sha256'),'hex')=record_sha256) IS TRUE),
 CHECK((original_record->>'schema'='original_guest_partial_poweroff_forward_v1') IS TRUE),
 CHECK((original_record->>'id'=id::text AND original_record->>'stage'=stage AND original_record->>'retirement_request_id'=retirement_request_id::text AND original_record->>'preregistration_id'=preregistration_id::text) IS TRUE),
 CHECK((original_record->>'namespace'=namespace AND original_record->>'environment'=environment AND original_record->>'domain'=domain AND original_record->>'dimension'=dimension) IS TRUE),
 CHECK((original_record->>'root_admission_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND ((coalesce(original_record->>'parent_admission_id','')='' AND original_record->>'root_admission_id'=id::text) OR (original_record->>'parent_admission_id' ~ '^[0-9a-f-]{36}$' AND original_record->>'parent_admission_sha256' ~ '^[0-9a-f]{64}$'))) IS TRUE),
 CHECK((original_record->>'mode' IN('live','historical') AND original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$') IS TRUE),
 CHECK((original_record#>>'{original,Request,intent,tuple,integration_instance_id}'=integration_instance_id AND original_record#>>'{original,Request,intent,tuple,scope_checksum}'=scope_checksum AND original_record#>>'{original,Request,intent,tuple,profile}'=profile_name AND (original_record#>>'{original,Request,intent,slot}')::integer=slot) IS TRUE),
 CHECK((encode(digest(decode(original_record->>'original_intent_wire','base64'),'sha256'),'hex')=original_record->>'original_intent_sha256') IS TRUE),
 CHECK(((original_record->>'recorded_at')::timestamptz=recorded_at) IS TRUE)
);
CREATE UNIQUE INDEX IF NOT EXISTS capacity_retirement_forward_one_root ON public.capacity_guest_retirement_forwards(retirement_request_id)
 WHERE coalesce(original_record->>'parent_admission_id','')='' AND (stage='requested' OR stage='admitted' AND original_record->>'mode'='live');
CREATE UNIQUE INDEX IF NOT EXISTS capacity_retirement_forward_one_child ON public.capacity_guest_retirement_forwards((original_record->>'parent_admission_id'))
 WHERE stage='requested' AND coalesce(original_record->>'parent_admission_id','')<>'';
CREATE INDEX IF NOT EXISTS capacity_retirement_forward_native_profile ON public.capacity_guest_retirement_forwards(integration_instance_id,scope_checksum,profile_name,slot);
CREATE TABLE IF NOT EXISTS public.capacity_guest_retirement_forward_reads (
 id uuid NOT NULL,
 admission_id uuid NOT NULL,
 admission_stage text NOT NULL DEFAULT 'admitted' CHECK(admission_stage='admitted'),
 retirement_request_id uuid NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
 kind text NOT NULL CHECK(kind IN('off','absence')),
 stage text NOT NULL CHECK(stage IN('prepared','returned')),
 record_sha256 text NOT NULL CHECK(record_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 2 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object'),
 recorded_at timestamptz NOT NULL,
 PRIMARY KEY(id,stage),
 FOREIGN KEY(admission_id,admission_stage) REFERENCES public.capacity_guest_retirement_forwards(id,stage),
 CHECK((original_record=convert_from(original_wire,'UTF8')::jsonb AND encode(digest(original_wire,'sha256'),'hex')=record_sha256) IS TRUE)
);
CREATE INDEX IF NOT EXISTS capacity_retirement_forward_reads_admission ON public.capacity_guest_retirement_forward_reads(admission_id,kind,recorded_at DESC,id);
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
 ELSIF NEW.stage='admitted' THEN
  IF NEW.original_record->>'mode'='historical' THEN
   SELECT * INTO STRICT parent FROM public.capacity_guest_retirement_forwards WHERE id=NEW.id AND stage='requested';
   IF ((NEW.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id'])=(parent.original_record-ARRAY['stage','recorded_at','fence','lease_owner','executor_id','run_id']) AND current_row#>>'{retirement_forward,id}'=NEW.id::text AND current_row#>>'{retirement_forward,stage}'='requested' AND (NEW.original_record->>'fence')::bigint=(current_row->>'fencing_token')::bigint+1 AND (current_row->>'lease_expires_at')::timestamptz<=clock_timestamp()) IS NOT TRUE THEN RAISE EXCEPTION 'new fenced claim preserves requested originals'; END IF;
  ELSIF (convert_from(decode(NEW.original_record->>'original_intent_wire','base64'),'UTF8')::jsonb=current_row AND (current_row->>'lease_expires_at')::timestamptz>clock_timestamp() AND (current_row->>'fencing_token')::bigint=(NEW.original_record->>'fence')::bigint AND current_row->>'lease_owner'=NEW.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=NEW.original_record->>'executor_id' AND NOT(current_row ? 'retirement_forward')) IS NOT TRUE THEN RAISE EXCEPTION 'same original live lease required'; END IF;
 ELSE
  SELECT * INTO STRICT admitted FROM public.capacity_guest_retirement_forwards WHERE id=NEW.id AND stage='admitted';
  IF (current_row#>>'{retirement_forward,id}'=NEW.id::text AND current_row#>>'{retirement_forward,stage}' IN('admitted','off_qualified') AND current_row->>'generation'=admitted.original_record->>'generation' AND current_row->>'fencing_token'=admitted.original_record->>'fence' AND current_row->>'lease_owner'=admitted.original_record->>'lease_owner' AND current_row->>'lease_executor_id'=admitted.original_record->>'executor_id' AND (current_row->>'lease_expires_at')::timestamptz>clock_timestamp()) IS NOT TRUE THEN RAISE EXCEPTION 'qualification belongs to current live exact claimant'; END IF;
  IF ((NEW.original_record-ARRAY['stage','recorded_at','admission_sha256','native_off_read_id','native_off_sha256','destroy_grant_id','native_absence_sha256','terminal_intent_sha256','terminal_intent_wire'])=(admitted.original_record-ARRAY['stage','recorded_at','admission_sha256','native_off_read_id','native_off_sha256','destroy_grant_id','native_absence_sha256','terminal_intent_sha256','terminal_intent_wire']) AND NEW.original_record->>'admission_sha256'=admitted.record_sha256 AND NEW.original_record->'evidence'=admitted.original_record->'evidence' AND NEW.original_record->>'prefix_sha256'=admitted.original_record->>'prefix_sha256' AND NEW.original_record->'original'=admitted.original_record->'original' AND NEW.original_record->>'original_intent_sha256'=admitted.original_record->>'original_intent_sha256' AND (NEW.original_record->>'fence')::bigint=(admitted.original_record->>'fence')::bigint) IS NOT TRUE THEN RAISE EXCEPTION 'qualified stages preserve exact admitted frame'; END IF;
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
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='retirement_forward_chain' AND tgrelid='public.capacity_guest_retirement_forwards'::regclass) THEN CREATE TRIGGER retirement_forward_chain BEFORE INSERT ON public.capacity_guest_retirement_forwards FOR EACH ROW EXECUTE FUNCTION public.guard_retirement_forward(); END IF; END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_forward_read() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission public.capacity_guest_retirement_forwards; prepared public.capacity_guest_retirement_forward_reads; r jsonb;
BEGIN
 SELECT * INTO STRICT admission FROM public.capacity_guest_retirement_forwards WHERE id=NEW.admission_id AND stage='admitted' FOR SHARE;
 IF (admission.retirement_request_id=NEW.retirement_request_id) IS NOT TRUE THEN RAISE EXCEPTION 'read cannot change original retirement'; END IF;
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
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='retirement_forward_read_chain' AND tgrelid='public.capacity_guest_retirement_forward_reads'::regclass) THEN CREATE TRIGGER retirement_forward_read_chain BEFORE INSERT ON public.capacity_guest_retirement_forward_reads FOR EACH ROW EXECUTE FUNCTION public.guard_retirement_forward_read(); END IF; END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_forward_delete_binding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a public.capacity_guest_retirement_forwards; g public.capacity_mutation_grants;
BEGIN
 IF NEW.original_eligibility_record->>'schema'='original_guest_partial_poweroff_delete_eligibility_v1' THEN
  SELECT * INTO STRICT a FROM public.capacity_guest_retirement_forwards WHERE id=(NEW.original_eligibility_record->>'admission_id')::uuid AND stage='admitted' AND retirement_request_id=NEW.intent_id;
  SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=NEW.destroy_grant_id;
  IF (NEW.original_eligibility_record->>'admission_sha256'=a.record_sha256 AND NEW.eligibility_sha256=encode(digest(NEW.original_wire,'sha256'),'hex') AND NEW.original_eligibility_record=convert_from(NEW.original_wire,'UTF8')::jsonb AND g.integration_instance_id::text=a.integration_instance_id AND g.scope_checksum=a.scope_checksum AND g.profile_name=a.profile_name AND g.slot=a.slot AND g.generation=(a.original_record->>'generation')::bigint AND g.grant_record->>'fencing_token'=a.original_record->>'fence' AND g.grant_record->'grant'->>'expected_resource_id'=a.original_record#>>'{original,Request,intent,tuple,resource_id}' AND g.grant_record->'grant'->>'expected_resource_created_at'=a.original_record#>>'{original,Request,intent,tuple,resource_created_at}'
   AND g.grant_record->>'lease_owner'=a.original_record->>'lease_owner' AND g.grant_record->>'executor_id'=a.original_record->>'executor_id'
   AND EXISTS(SELECT 1 FROM public.capacity_intents c WHERE c.namespace=a.namespace AND c.environment=a.environment AND c.domain=a.domain AND c.dimension=a.dimension AND c.intent#>>'{retirement_forward,id}'=a.id::text AND c.intent#>>'{retirement_forward,stage}'='off_qualified' AND c.intent->>'phase'='drained' AND c.intent->>'fencing_token'=a.original_record->>'fence' AND c.intent->>'lease_owner'=a.original_record->>'lease_owner' AND (c.intent->>'lease_expires_at')::timestamptz>clock_timestamp())
   AND EXISTS(SELECT 1 FROM public.capacity_guest_retirement_forward_reads v WHERE v.id=(NEW.original_eligibility_record->>'native_off_read_id')::uuid AND v.admission_id=a.id AND v.kind='off' AND v.stage='returned' AND v.record_sha256=NEW.original_eligibility_record->>'native_off_sha256' AND v.original_record->>'status'='observed' AND v.original_record->>'call_failed'='false' AND v.original_record->>'original_context_failed'='false' AND v.original_record#>>'{plan,server,status}' IN('off','stopped'))) IS NOT TRUE THEN RAISE EXCEPTION 'narrow forward destroy binding cannot change epoch or tuple'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='retirement_forward_delete_chain' AND tgrelid='public.capacity_vm_retirement_delete_bindings'::regclass) THEN CREATE TRIGGER retirement_forward_delete_chain BEFORE INSERT ON public.capacity_vm_retirement_delete_bindings FOR EACH ROW EXECUTE FUNCTION public.guard_retirement_forward_delete_binding(); END IF; END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='retirement_forward_immutable' AND tgrelid='public.capacity_guest_retirement_forwards'::regclass) THEN CREATE TRIGGER retirement_forward_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_retirement_forwards FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable(); END IF; END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='retirement_forward_read_immutable' AND tgrelid='public.capacity_guest_retirement_forward_reads'::regclass) THEN CREATE TRIGGER retirement_forward_read_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_retirement_forward_reads FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable(); END IF; END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_forward_terminal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE terminal_wire bytea; terminal_intent jsonb; actual jsonb;
BEGIN
 IF NEW.stage='terminal' THEN
  terminal_wire=decode(NEW.original_record->>'terminal_intent_wire','base64');
  terminal_intent=convert_from(terminal_wire,'UTF8')::jsonb;
  SELECT intent INTO STRICT actual FROM public.capacity_intents WHERE namespace=NEW.namespace AND environment=NEW.environment AND domain=NEW.domain AND dimension=NEW.dimension;
  IF (encode(digest(terminal_wire,'sha256'),'hex')=NEW.original_record->>'terminal_intent_sha256' AND terminal_intent=actual AND actual#>>'{retirement_forward,id}'=NEW.id::text AND actual#>>'{retirement_forward,stage}'='terminal' AND actual->>'phase'='promoted' AND actual->>'generation'=NEW.original_record->>'generation' AND actual->>'fencing_token'=NEW.original_record->>'fence') IS NOT TRUE THEN RAISE EXCEPTION 'terminal must link exact committed promoted intent bytes'; END IF;
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='retirement_forward_terminal' AND tgrelid='public.capacity_guest_retirement_forwards'::regclass) THEN CREATE CONSTRAINT TRIGGER retirement_forward_terminal AFTER INSERT ON public.capacity_guest_retirement_forwards DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.guard_retirement_forward_terminal(); END IF; END $$;
-- +goose StatementEnd
-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'permanent partial retirement forward originals cannot be rolled back destructively'; END $$;
