-- +goose Up
-- ADR-0092: quiesce an original_production_v2 failed-installed disposal whose
-- Guest refused the V2 retirement, from a native OFF read only.
--
-- The Guest answered the V2 nonce, journaled only possible_start (no writer
-- quiescence, no poweroff) and then closed the single caller POST with a
-- non-200 status whose body Core did not retain. No existing lane can reach
-- quiescent from that history: the normal V2 proof needs five journal rows and
-- a caller 200, and the 79/80/81 lanes are legacy-only. This lane never claims
-- writer quiescence, never sends a Guest request, a poweroff or a DELETE.
--
-- One immutable admission per disposal (stage admitted), and at most one
-- qualification (stage qualified) bound to one native OFF read of the existing
-- capacity_guest_original_native_poweroff_reads table, whose challenge joins
-- the refused caller return. A quiescent disposal row for a disposal that has
-- an admission here must carry exactly that qualified lineage.
CREATE TABLE public.capacity_guest_v2_refused_nativeoff_quiescences (
 id uuid NOT NULL,
 stage text NOT NULL CHECK(stage IN('admitted','qualified')),
 disposal_id uuid NOT NULL,
 preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
 retirement_request_id uuid NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object' AND original_record=convert_from(original_wire,'UTF8')::jsonb),
 record_sha256 text NOT NULL CHECK(record_sha256=encode(sha256(original_wire),'hex')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(id,stage),UNIQUE(preregistration_id,stage),UNIQUE(disposal_id,stage),UNIQUE(retirement_request_id,stage),
 CHECK((original_record->>'schema'='failed_installed_v2_refused_native_off_quiescence_v1' AND original_record->>'id'=id::text AND original_record->>'stage'=stage AND original_record->>'disposal_id'=disposal_id::text AND original_record->>'preregistration_id'=preregistration_id::text AND original_record->>'retirement_request_id'=retirement_request_id::text) IS TRUE),
 CHECK((length(original_record->>'issuer') BETWEEN 1 AND 256 AND original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$' AND original_record->>'original_claim_sha256' ~ '^[0-9a-f]{64}$' AND jsonb_typeof(original_record->'original_claimed_intent')='object' AND jsonb_typeof(original_record->'evidence')='object' AND jsonb_typeof(original_record->'failed_run')='string' AND jsonb_typeof((original_record->>'failed_run')::jsonb)='object') IS TRUE),
 CHECK(original_record ?& ARRAY['schema','id','stage','disposal_id','preregistration_id','retirement_request_id','issuer','actual_core_source','original_claim_sha256','original_claimed_intent','failed_run','evidence']),
 CHECK((original_record-ARRAY['schema','id','stage','disposal_id','preregistration_id','retirement_request_id','issuer','actual_core_source','original_claim_sha256','original_claimed_intent','failed_run','evidence','admission_sha256','native_read_id','native_off_sha256'])='{}'::jsonb)
);

-- The refused V2 history is append-only and tied to the expired intent, so
-- it is re-derived on every insert. Native reads are checked separately.
-- +goose StatementBegin
CREATE FUNCTION public.assert_v2_refused_nativeoff_evidence(req uuid,pre uuid,disposal uuid,e jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE parent public.capacity_vm_retirement_intents; c public.capacity_guest_original_caller_returns; pr public.capacity_vm_provisioning_preregistrations;
BEGIN
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE id=req AND preregistration_id=pre FOR UPDATE;
 IF (parent.intent_record->>'schema'<>'original_guest_production_retirement_intent_v2' OR parent.original_deadline>clock_timestamp() OR (parent.intent_record->>'original_deadline')::timestamptz>clock_timestamp()) IS NOT FALSE THEN RAISE EXCEPTION 'expired original V2 retirement without renewal required'; END IF;
 IF (SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=pre)<>1 THEN RAISE EXCEPTION 'exactly one retirement intent for the preregistration required'; END IF;
 SELECT * INTO STRICT pr FROM public.capacity_vm_provisioning_preregistrations WHERE id=pre;
 IF ((e ?& ARRAY['order','guest_source','intent_sha256','observation_sha256','caller_sha256','caller_status'] AND e->>'order'='v2_nonce_then_possible_start_then_closed_caller_refusal_v1' AND e->>'guest_source' ~ '^[0-9a-f]{40}$' AND e->>'intent_sha256'=parent.intent_sha256 AND e->>'caller_sha256' ~ '^[0-9a-f]{64}$' AND jsonb_typeof(e->'observation_sha256')='array' AND jsonb_typeof(e->'caller_status')='number') IS NOT TRUE OR
  (e-ARRAY['order','guest_source','intent_sha256','observation_sha256','caller_sha256','caller_status'])<>'{}'::jsonb OR
  pr.binding_wire IS NULL OR convert_from(pr.binding_wire,'UTF8')::jsonb->>'guest_source_commit' IS DISTINCT FROM e->>'guest_source') IS NOT FALSE THEN RAISE EXCEPTION 'closed V2 refusal evidence required'; END IF;
 SELECT * INTO STRICT c FROM public.capacity_guest_original_caller_returns WHERE intent_id=req;
 IF (e->>'caller_sha256'<>c.return_sha256 OR (c.original_record->>'status')::int=200 OR (c.original_record->>'status')::int NOT BETWEEN 400 AND 599 OR (e->>'caller_status')::int<>(c.original_record->>'status')::int OR
  c.original_record->>'body_persisted'<>'false' OR c.original_record->>'preflight_failed'<>'false' OR c.original_record->>'do_failed'<>'false' OR c.original_record->>'read_failed'<>'false' OR c.original_record->>'close_failed'<>'false' OR c.original_record->>'original_context_failed'<>'false' OR
  c.original_record->>'request_id'<>req::text OR c.original_record->>'attempt_id'<>parent.attempt_id::text OR
  (c.original_record->>'driver_returned_at')::timestamptz>=parent.original_deadline) IS NOT FALSE THEN RAISE EXCEPTION 'one closed non-200 caller return without a retained body required'; END IF;
 IF ((SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=req)<>1 OR
  (SELECT count(*) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=req)<>2 OR
  EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_reads WHERE intent_id=req AND phase='before_poweroff') OR
  EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=req)) IS NOT FALSE THEN RAISE EXCEPTION 'exact nonce and possible-start history without poweroff authority or delete required'; END IF;
 IF e->'observation_sha256' IS DISTINCT FROM (SELECT jsonb_agg(return_sha256 ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=req) OR
  EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=req AND
   (sequence NOT BETWEEN 1 AND 2 OR
    (sequence=1 AND (kind<>'production_clock_nonce_v2' OR previous_sha256<>'')) OR
    (sequence=2 AND (kind<>'production_retirement_v2:possible_start' OR original_return_record->>'journal_complete'<>'true' OR
      original_return_record #>>'{record,state}'<>'possible_start' OR original_return_record #>>'{record,writer_quiescence_evidence}'<>'false' OR
      original_return_record #>>'{record,poweroff_command_returned}'<>'false' OR original_return_record #>>'{record,powered_off_observed}'<>'false'))) IS NOT FALSE)
 THEN RAISE EXCEPTION 'exact nonce then unquiesced possible-start journal required'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_presend_retirement_recoveries WHERE disposal_id=disposal) OR
  EXISTS(SELECT 1 FROM public.capacity_guest_prejournal_refusal_recoveries WHERE disposal_id=disposal) OR
  EXISTS(SELECT 1 FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE disposal_id=disposal) THEN RAISE EXCEPTION 'a 79, 80 or 81 recovery owns this disposal'; END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.guard_v2_refused_nativeoff_quiescence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE claim public.capacity_guest_failed_installed_disposals; admitted public.capacity_guest_v2_refused_nativeoff_quiescences;
        parent public.capacity_vm_retirement_intents; current_record jsonb;
        read_return public.capacity_guest_original_native_poweroff_reads; challenge public.capacity_guest_original_native_poweroff_reads;
BEGIN
 SELECT * INTO STRICT claim FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.disposal_id AND stage='claimed' AND preregistration_id=NEW.preregistration_id FOR SHARE;
 -- Same single lock encoding rule as migrations 83 to 85 (Go json.Marshal vs array_to_json).
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[claim.namespace,claim.environment,claim.domain,claim.dimension]) n WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'V2 refused native OFF requires a scope name with one lock encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[claim.namespace,claim.environment,claim.domain,claim.dimension])::text,0));
 SELECT intent INTO STRICT current_record FROM public.capacity_intents WHERE namespace=claim.namespace AND environment=claim.environment AND domain=claim.domain AND dimension=claim.dimension FOR UPDATE;
 PERFORM public.assert_v2_refused_nativeoff_evidence(NEW.retirement_request_id,NEW.preregistration_id,NEW.disposal_id,NEW.original_record->'evidence');
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE id=NEW.retirement_request_id;
 IF (claim.original_record->>'retirement_mode'<>'original_production_v2' OR NEW.original_record->>'original_claim_sha256'<>claim.record_sha256 OR
  claim.original_record->'claimed_intent'<>current_record OR current_record<>NEW.original_record->'original_claimed_intent' OR
  current_record #>>'{failed_installed_disposal,id}'<>NEW.disposal_id::text OR current_record #>>'{failed_installed_disposal,stage}'<>'claimed' OR
  coalesce(current_record #>>'{failed_installed_disposal,retirement_recovery_id}','')<>'' OR coalesce(current_record #>>'{failed_installed_disposal,retirement_refusal_recovery_id}','')<>'') IS NOT FALSE
 THEN RAISE EXCEPTION 'exact original V2 claimed disposal and unchanged current intent required'; END IF;
 IF ((parent.intent_record->>'preregistration_id')<>NEW.preregistration_id::text OR (parent.intent_record->>'generation')::bigint<>(current_record->>'generation')::bigint OR (parent.intent_record->>'fence')::bigint<>(current_record->>'fencing_token')::bigint OR
  parent.intent_record->>'lease_owner'<>current_record->>'lease_owner' OR current_record->>'lease_expires_at' IS NULL OR (current_record->>'lease_expires_at')::timestamptz>clock_timestamp()) IS NOT FALSE
 THEN RAISE EXCEPTION 'same expired original V2 workflow epoch required'; END IF;
 IF NEW.stage='admitted' THEN
  IF (NEW.original_record ?| ARRAY['admission_sha256','native_read_id','native_off_sha256']) IS NOT FALSE THEN RAISE EXCEPTION 'admission grants no native OFF proof'; END IF;
  IF EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=NEW.retirement_request_id) THEN RAISE EXCEPTION 'no earlier native poweroff read may exist at admission'; END IF;
 ELSE
  SELECT * INTO STRICT admitted FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE id=NEW.id AND stage='admitted';
  IF (NOT (NEW.original_record ?& ARRAY['admission_sha256','native_read_id','native_off_sha256']) OR NEW.original_record->>'native_off_sha256' !~ '^[0-9a-f]{64}$' OR NEW.original_record->>'admission_sha256'<>admitted.record_sha256 OR
   (NEW.original_record-ARRAY['stage','admission_sha256','native_read_id','native_off_sha256'])<>(admitted.original_record-'stage')) IS NOT FALSE THEN RAISE EXCEPTION 'qualified must preserve the original admission'; END IF;
  SELECT * INTO STRICT read_return FROM public.capacity_guest_original_native_poweroff_reads WHERE id=(NEW.original_record->>'native_read_id')::uuid AND intent_id=NEW.retirement_request_id;
  SELECT * INTO STRICT challenge FROM public.capacity_guest_original_native_poweroff_reads WHERE id=(read_return.original_record #>>'{challenge,read_id}')::uuid AND intent_id=NEW.retirement_request_id;
  IF (read_return.original_record->>'schema'<>'original_core_guest_native_poweroff_read_return_v2' OR read_return.observation_sha256<>NEW.original_record->>'native_off_sha256' OR
   read_return.observation_sha256<>encode(sha256(read_return.original_wire),'hex') OR read_return.original_record<>convert_from(read_return.original_wire,'UTF8')::jsonb OR
   read_return.original_record->>'status'<>'observed' OR read_return.original_record->>'call_failed'<>'false' OR read_return.original_record->>'original_context_failed'<>'false' OR
   jsonb_typeof(read_return.original_record->'plan') IS DISTINCT FROM 'object' OR coalesce(read_return.original_record #>>'{plan,server,status}','') NOT IN('off','stopped') OR
   read_return.original_record #>>'{challenge,original_caller_sha256}'<>NEW.original_record #>>'{evidence,caller_sha256}' OR
   read_return.original_record #>>'{challenge,intent_id}'<>NEW.retirement_request_id::text OR
   (read_return.original_record->>'original_returned_at_core')::timestamptz>=(read_return.original_record #>>'{challenge,original_deadline_core}')::timestamptz OR
   read_return.recorded_at<clock_timestamp()-interval '60 seconds' OR
   challenge.original_record->>'schema'<>'original_core_guest_native_poweroff_read_challenge_v2' OR challenge.original_wire<>read_return.original_native_join_wire OR
   challenge.recorded_at<admitted.recorded_at OR read_return.recorded_at<challenge.recorded_at OR
   challenge.id<>(SELECT id FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=NEW.retirement_request_id AND original_record->>'schema'='original_core_guest_native_poweroff_read_challenge_v2' ORDER BY recorded_at DESC,id DESC LIMIT 1) OR
   -- The return must also be the newest return of the intent and the only
   -- return of its challenge: the table itself does not make returns unique
   -- per challenge, so an older OFF return can never outrank a later one.
   read_return.id<>(SELECT id FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=NEW.retirement_request_id AND original_record->>'schema'='original_core_guest_native_poweroff_read_return_v2' ORDER BY recorded_at DESC,id DESC LIMIT 1) OR
   (SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=NEW.retirement_request_id AND original_record->>'schema'='original_core_guest_native_poweroff_read_return_v2' AND original_record #>>'{challenge,read_id}'=challenge.id::text)<>1) IS NOT FALSE
  THEN RAISE EXCEPTION 'only the newest complete fresh exact OFF read joined to the refused caller can qualify'; END IF;
  IF EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=NEW.retirement_request_id AND
   (recorded_at<admitted.recorded_at OR coalesce(original_record->>'schema','') NOT IN('original_core_guest_native_poweroff_read_challenge_v2','original_core_guest_native_poweroff_read_return_v2') OR
    coalesce(original_record->>'original_caller_sha256',original_record #>>'{challenge,original_caller_sha256}','')<>NEW.original_record #>>'{evidence,caller_sha256}'))
  THEN RAISE EXCEPTION 'every native read of this intent must belong to this admission'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER v2_refused_nativeoff_quiescence_chain BEFORE INSERT ON public.capacity_guest_v2_refused_nativeoff_quiescences FOR EACH ROW EXECUTE FUNCTION public.guard_v2_refused_nativeoff_quiescence();

-- +goose StatementBegin
CREATE FUNCTION public.guard_v2_refused_nativeoff_disposal_join() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.stage IN('quiescent','terminal') AND EXISTS(SELECT 1 FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=NEW.id AND stage='admitted') THEN
  PERFORM 1 FROM public.capacity_guest_v2_refused_nativeoff_quiescences WHERE disposal_id=NEW.id AND stage='qualified' AND preregistration_id=NEW.preregistration_id AND retirement_request_id::text=NEW.original_record->>'retirement_request_id' AND original_record->>'native_off_sha256'=NEW.original_record->>'native_poweroff_sha256' AND original_record->'original_claimed_intent'=NEW.original_record->'claimed_intent';
  IF (NOT FOUND) IS NOT FALSE THEN RAISE EXCEPTION 'an admitted V2 refused disposal is quiesced only by its own qualified native OFF lineage'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER v2_refused_nativeoff_disposal_join BEFORE INSERT ON public.capacity_guest_failed_installed_disposals FOR EACH ROW EXECUTE FUNCTION public.guard_v2_refused_nativeoff_disposal_join();

-- +goose StatementBegin
CREATE FUNCTION public.guard_v2_refused_nativeoff_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'V2 refused native OFF quiescence originals are immutable'; END $$;
-- +goose StatementEnd
CREATE TRIGGER v2_refused_nativeoff_quiescence_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_v2_refused_nativeoff_quiescences FOR EACH ROW EXECUTE FUNCTION public.guard_v2_refused_nativeoff_immutable();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'append-only86 V2 refused native OFF lineage cannot be rolled back destructively'; END $$;
-- +goose StatementEnd
