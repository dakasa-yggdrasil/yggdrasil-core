-- +goose Up
-- An expired, proven-never-sent retirement may have ONE explicitly admitted
-- successor. Original63/78 rows, signatures, deadlines, jobs and ACKs are never
-- modified. Every possible-send and return keeps its REAL new intent FK.
CREATE TABLE public.capacity_guest_presend_retirement_recoveries (
 id uuid NOT NULL,
 stage text NOT NULL CHECK(stage IN('requested','claimed','issued')),
 disposal_id uuid NOT NULL,
 preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
 parent_intent_id uuid NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object' AND original_record=convert_from(original_wire,'UTF8')::jsonb),
 record_sha256 text NOT NULL CHECK(record_sha256=encode(sha256(original_wire),'hex')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(id,stage), UNIQUE(preregistration_id,stage), UNIQUE(parent_intent_id,stage),
 CHECK((original_record->>'schema'='failed_installed_never_sent_retirement_recovery_v1') IS TRUE),
 CHECK((original_record->>'id'=id::text AND original_record->>'stage'=stage AND original_record->>'disposal_id'=disposal_id::text AND original_record->>'preregistration_id'=preregistration_id::text AND original_record->>'parent_intent_id'=parent_intent_id::text) IS TRUE),
 CHECK((original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$' AND original_record->>'parent_intent_sha256' ~ '^[0-9a-f]{64}$' AND original_record->>'original_claim_sha256' ~ '^[0-9a-f]{64}$') IS TRUE),
 CHECK((length(original_record->>'issuer') BETWEEN 1 AND 256 AND jsonb_typeof(original_record->'failed_run')='string' AND jsonb_typeof((original_record->>'failed_run')::jsonb)='object' AND jsonb_typeof(original_record->'original_claimed_intent')='object') IS TRUE),
 CHECK(original_record ?& ARRAY['schema','id','stage','disposal_id','preregistration_id','parent_intent_id','parent_intent_sha256','original_claim_sha256','issuer','actual_core_source','failed_run','original_claimed_intent']),
 CHECK((original_record-ARRAY['schema','id','stage','disposal_id','preregistration_id','parent_intent_id','parent_intent_sha256','original_claim_sha256','issuer','actual_core_source','failed_run','original_claimed_intent','claimed_intent','admission_sha256','successor_intent'])='{}'::jsonb)
);
-- +goose StatementBegin
CREATE FUNCTION public.guard_presend_retirement_recovery_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission public.capacity_guest_presend_retirement_recoveries;
        claimed public.capacity_guest_failed_installed_disposals;
        parent public.capacity_vm_retirement_intents;
BEGIN
 SELECT * INTO STRICT claimed FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.disposal_id AND stage='claimed' AND preregistration_id=NEW.preregistration_id FOR SHARE;
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE id=NEW.parent_intent_id AND preregistration_id=NEW.preregistration_id FOR UPDATE;
 IF claimed.original_record->>'retirement_mode'<>'legacy_guest548_original_v1' OR claimed.record_sha256<>NEW.original_record->>'original_claim_sha256' OR parent.intent_sha256<>NEW.original_record->>'parent_intent_sha256' OR claimed.original_record->'claimed_intent'<>NEW.original_record->'original_claimed_intent' OR parent.original_deadline>clock_timestamp() THEN RAISE EXCEPTION 'recovery requires exact expired original and immutable original claim'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_attempts WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_returns WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_reads WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=parent.id) THEN RAISE EXCEPTION 'never-sent recovery forbids every old possible-send or result'; END IF;
 IF NEW.stage='requested' THEN
  IF NEW.original_record ?| ARRAY['claimed_intent','admission_sha256','successor_intent'] THEN RAISE EXCEPTION 'recovery admission has no claim or successor'; END IF;
 ELSE
  SELECT * INTO STRICT admission FROM public.capacity_guest_presend_retirement_recoveries WHERE id=NEW.id AND stage='requested';
  IF (NEW.original_record->>'admission_sha256'=admission.record_sha256) IS NOT TRUE OR
     (NEW.original_record-ARRAY['stage','claimed_intent','admission_sha256','successor_intent'])<>(admission.original_record-'stage') OR jsonb_typeof(NEW.original_record->'claimed_intent') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'recovery admission lineage mismatch'; END IF;
  IF (NEW.original_record #>>'{claimed_intent,failed_installed_disposal,retirement_recovery_id}'=NEW.id::text AND NEW.original_record #>>'{claimed_intent,failed_installed_disposal,retirement_recovery_admission_sha256}'=admission.record_sha256 AND (NEW.original_record #>>'{claimed_intent,generation}')::bigint=(NEW.original_record #>>'{original_claimed_intent,generation}')::bigint AND (NEW.original_record #>>'{claimed_intent,fencing_token}')::bigint=(NEW.original_record #>>'{original_claimed_intent,fencing_token}')::bigint+1 AND NEW.original_record #>>'{claimed_intent,lease_owner}'<>NEW.original_record #>>'{original_claimed_intent,lease_owner}' AND NEW.original_record #>>'{claimed_intent,failed_installed_disposal,run_id}'<>NEW.original_record #>>'{original_claimed_intent,failed_installed_disposal,run_id}') IS NOT TRUE THEN RAISE EXCEPTION 'recovery requires distinct new fence run and lease'; END IF;
  IF NEW.stage='claimed' THEN
   IF NEW.original_record ? 'successor_intent' THEN RAISE EXCEPTION 'claim has no successor credit'; END IF;
  ELSE
   PERFORM 1 FROM public.capacity_guest_presend_retirement_recoveries WHERE id=NEW.id AND stage='claimed' AND original_record->'claimed_intent'=NEW.original_record->'claimed_intent';
   IF NOT FOUND OR jsonb_typeof(NEW.original_record->'successor_intent') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'issued successor requires exact recovery claim'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER presend_retirement_recovery_chain BEFORE INSERT ON public.capacity_guest_presend_retirement_recoveries FOR EACH ROW EXECUTE FUNCTION public.guard_presend_retirement_recovery_chain();
-- +goose StatementBegin
CREATE FUNCTION public.guard_presend_retirement_recovery_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'never-sent retirement recovery originals are immutable'; END $$;
-- +goose StatementEnd
CREATE TRIGGER presend_retirement_recovery_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_presend_retirement_recoveries FOR EACH ROW EXECUTE FUNCTION public.guard_presend_retirement_recovery_immutable();
-- Replace unconditional single-intent cardinality with its guarded extension.
-- All original rows and FK targets stay in63; no child record aliases its parent.
ALTER TABLE public.capacity_vm_retirement_intents DROP CONSTRAINT capacity_vm_retirement_intents_preregistration_id_key;
-- +goose StatementBegin
CREATE FUNCTION public.guard_retirement_intent_linear_successor() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent public.capacity_vm_retirement_intents;
        issue public.capacity_guest_presend_retirement_recoveries;
        total integer;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('retirement-prereg:'||NEW.preregistration_id::text,0));
 SELECT count(*) INTO total FROM public.capacity_vm_retirement_intents WHERE preregistration_id=NEW.preregistration_id;
 IF total=0 THEN RETURN NEW; END IF;
 IF total<>1 THEN RAISE EXCEPTION 'only one explicit never-sent successor permitted'; END IF;
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE preregistration_id=NEW.preregistration_id FOR UPDATE;
 SELECT * INTO STRICT issue FROM public.capacity_guest_presend_retirement_recoveries WHERE parent_intent_id=parent.id AND preregistration_id=NEW.preregistration_id AND stage='issued';
 IF parent.original_deadline>clock_timestamp() OR issue.original_record->'successor_intent'<>NEW.intent_record OR issue.original_record #>>'{successor_intent,request_id}'<>NEW.id::text OR NEW.id=parent.id OR NEW.attempt_id=parent.attempt_id OR NEW.nonce_sha256=parent.nonce_sha256 OR NEW.intent_sha256=parent.intent_sha256 OR NEW.original_deadline<=clock_timestamp() OR NEW.original_deadline>NEW.created_at+interval '30 seconds' THEN RAISE EXCEPTION 'successor requires exact distinct bounded new original'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_attempts WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_returns WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_reads WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=parent.id) THEN RAISE EXCEPTION 'any original possible-send or Guest result forbids successor'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER retirement_intent_linear_successor BEFORE INSERT ON public.capacity_vm_retirement_intents FOR EACH ROW EXECUTE FUNCTION public.guard_retirement_intent_linear_successor();
-- Extend only the existing immutable disposal continuation with the explicit79
-- claim. The original claimed78 row remains permanently unchanged.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_failed_installed_disposal_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission public.capacity_guest_failed_installed_disposals;
BEGIN
 IF NEW.stage='requested' THEN
  IF NEW.original_record ?| ARRAY['admission_sha256','claimed_intent','retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer'] THEN RAISE EXCEPTION 'requested disposal has no claim or terminal'; END IF;
 ELSE
  SELECT * INTO STRICT admission FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.id AND stage='requested';
  IF (NEW.original_record->>'admission_sha256'=admission.record_sha256) IS NOT TRUE OR
     (NEW.original_record - ARRAY['stage','admission_sha256','claimed_intent','retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer']) <> (admission.original_record-'stage') OR
     jsonb_typeof(NEW.original_record->'claimed_intent') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'disposal admission lineage mismatch'; END IF;
  IF NEW.stage IN('quiescent','terminal') THEN
   PERFORM 1 FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.id AND stage=CASE WHEN NEW.stage='quiescent' THEN 'claimed' ELSE 'quiescent' END AND original_record->'claimed_intent'=NEW.original_record->'claimed_intent';
   IF NEW.stage='quiescent' AND EXISTS(SELECT 1 FROM public.capacity_guest_presend_retirement_recoveries WHERE disposal_id=NEW.id AND stage='requested') THEN
    PERFORM 1 FROM public.capacity_guest_presend_retirement_recoveries c JOIN public.capacity_guest_presend_retirement_recoveries i ON i.id=c.id AND i.stage='issued'
     WHERE c.disposal_id=NEW.id AND c.stage='claimed' AND c.preregistration_id=NEW.preregistration_id
     AND c.original_record->'claimed_intent'=NEW.original_record->'claimed_intent'
     AND NEW.original_record #>>'{claimed_intent,failed_installed_disposal,retirement_recovery_id}'=c.id::text
     AND i.original_record #>>'{successor_intent,request_id}'=NEW.original_record->>'retirement_request_id';
    IF NOT FOUND THEN RAISE EXCEPTION 'quiescence requires explicit recovery79 claim and genuine successor'; END IF;
   ELSIF NOT FOUND THEN RAISE EXCEPTION 'terminal disposal requires original claim'; END IF;
   IF (NEW.original_record->>'retirement_request_id' ~ '^[0-9a-f-]{36}$' AND NEW.original_record->>'native_poweroff_sha256' ~ '^[0-9a-f]{64}$') IS NOT TRUE THEN RAISE EXCEPTION 'terminal disposal requires original retirement'; END IF;
   IF NEW.stage='terminal' THEN
    PERFORM 1 FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.id AND stage='quiescent' AND original_record->>'retirement_request_id'=NEW.original_record->>'retirement_request_id' AND original_record->>'native_poweroff_sha256'=NEW.original_record->>'native_poweroff_sha256';
    IF NOT FOUND THEN RAISE EXCEPTION 'terminal changed original quiescence'; END IF;
   END IF;
   IF NEW.stage='quiescent' AND NEW.original_record ?| ARRAY['observation_sha256','observation','terminal_issuer'] THEN RAISE EXCEPTION 'quiescence is not absence'; END IF;
   IF NEW.stage='terminal' AND (jsonb_typeof(NEW.original_record->'observation')='object' AND NEW.original_record->>'observation_sha256' ~ '^[0-9a-f]{64}$' AND length(NEW.original_record->>'terminal_issuer') BETWEEN 1 AND 256) IS NOT TRUE THEN RAISE EXCEPTION 'terminal requires actual readonly observation'; END IF;
  ELSIF NEW.original_record ?| ARRAY['retirement_request_id','native_poweroff_sha256','observation_sha256','observation','terminal_issuer'] THEN RAISE EXCEPTION 'claim has no terminal credit';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'immutable admitted recovery79 cannot be rolled back'; END $$;
-- +goose StatementEnd
