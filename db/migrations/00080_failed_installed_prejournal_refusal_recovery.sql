-- +goose Up
-- Exact548 first-live refusal is DISTINCT from never-sent79. Preserve the real
-- POST/409, all old63/64/77/78/79 and every business effect. No caller supplies
-- a no-effect flag, current epoch, Guest observation or native absence.
-- +goose StatementBegin
CREATE FUNCTION public.assert_prejournal_refusal_evidence(parent_id uuid,pre_id uuid,evidence jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE p public.capacity_vm_retirement_intents; c public.capacity_guest_original_caller_returns;
        r public.capacity_guest_original_authority_reads; ch public.capacity_guest_runtime_snapshot_challenges;
        t public.capacity_guest_original_authority_transport_returns;
BEGIN
 SELECT * INTO STRICT p FROM public.capacity_vm_retirement_intents WHERE id=parent_id AND preregistration_id=pre_id FOR UPDATE;
 IF p.original_deadline>clock_timestamp() OR (p.intent_record->>'original_deadline')::timestamptz>clock_timestamp() THEN RAISE EXCEPTION 'refused original must expire without renewing it'; END IF;
 IF (SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=pre_id)<>1 OR
 (SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=parent_id)<>1 OR
 (SELECT count(*) FROM public.capacity_guest_original_caller_returns WHERE intent_id=parent_id)<>1 OR
 (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=parent_id)<>1 OR
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=parent_id)<>1 OR
 (SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns x JOIN public.capacity_guest_original_authority_reads y ON y.id=x.read_id WHERE y.intent_id=parent_id)<>1 THEN RAISE EXCEPTION 'exact first read and sole closed possible-send required'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_runtime_snapshot_returns x JOIN public.capacity_guest_runtime_snapshot_challenges y ON y.id=x.challenge_id WHERE y.intent_id=parent_id) OR
 EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_returns x JOIN public.capacity_guest_original_authority_reads y ON y.id=x.read_id WHERE y.intent_id=parent_id) OR
 EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=parent_id) OR
 EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=parent_id) OR
 EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=parent_id) THEN RAISE EXCEPTION 'authority success or any retirement result forbids prejournal recovery'; END IF;
 SELECT * INTO STRICT c FROM public.capacity_guest_original_caller_returns WHERE intent_id=parent_id;
 SELECT * INTO STRICT r FROM public.capacity_guest_original_authority_reads WHERE intent_id=parent_id AND phase='before_start' AND ordinal=1;
 SELECT * INTO STRICT ch FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=parent_id AND phase='before_start' AND ordinal=1;
 SELECT * INTO STRICT t FROM public.capacity_guest_original_authority_transport_returns WHERE read_id=r.id AND native_stage='snapshot';
 IF (evidence->>'causal_guest_source'='548734eef627404f10b5117e0ec7f27582ae9048' AND evidence->>'source_order'='guest548_first_authority_before_journal_v1' AND
 evidence->>'original_caller_sha256'=c.return_sha256 AND evidence->>'authority_read_id'=r.id::text AND evidence->>'snapshot_challenge_sha256'=ch.challenge_sha256 AND evidence->>'snapshot_transport_sha256'=t.return_sha256 AND evidence->>'authenticated_snapshot_sha256'=encode(sha256(t.original_reply_wire),'hex')) IS NOT TRUE OR
 NOT(evidence ?& ARRAY['causal_guest_source','source_order','original_caller_sha256','authority_read_id','snapshot_challenge_sha256','snapshot_transport_sha256','authenticated_snapshot_sha256']) OR
 evidence-ARRAY['causal_guest_source','source_order','original_caller_sha256','authority_read_id','snapshot_challenge_sha256','snapshot_transport_sha256','authenticated_snapshot_sha256']<>'{}'::jsonb THEN RAISE EXCEPTION 'immutable original evidence identities required'; END IF;
 IF (c.original_record->>'attempt_id'=p.attempt_id::text AND c.original_record->>'request_id'=p.id::text AND (c.original_record->>'status')::int=409 AND c.original_record->'body_persisted'='false'::jsonb AND
 c.original_record->>'response_body_scope'='complete_original_body_read' AND (c.original_record->>'received_body_bytes')::int>0 AND c.original_record->>'response_sha256'=c.original_record->>'retained_prefix_sha256' AND c.original_record->>'received_body_bytes'=c.original_record->>'retained_prefix_bytes' AND
 c.original_record->'preflight_failed'='false'::jsonb AND c.original_record->'do_failed'='false'::jsonb AND c.original_record->'read_failed'='false'::jsonb AND c.original_record->'close_failed'='false'::jsonb AND c.original_record->'original_context_failed'='false'::jsonb AND
 t.original_record->>'native_stage'='snapshot' AND (t.original_record->>'status')::int=200 AND t.original_record->>'response_body_scope'='complete_original_body_read' AND octet_length(t.original_reply_wire)>0 AND
 t.original_record->>'response_sha256'=encode(sha256(t.original_reply_wire),'hex') AND (t.original_record->>'received_body_bytes')::int=octet_length(t.original_reply_wire) AND t.original_record->>'retained_prefix_sha256'=t.original_record->>'response_sha256' AND t.original_record->>'retained_prefix_bytes'=t.original_record->>'received_body_bytes' AND
 t.original_record->'preflight_failed'='false'::jsonb AND t.original_record->'do_failed'='false'::jsonb AND t.original_record->'read_failed'='false'::jsonb AND t.original_record->'close_failed'='false'::jsonb AND t.original_record->'original_context_failed'='false'::jsonb AND
 c.original_record=convert_from(c.original_wire,'UTF8')::jsonb AND t.original_record=convert_from(t.original_wire,'UTF8')::jsonb AND ch.original_record=convert_from(ch.original_wire,'UTF8')::jsonb) IS NOT TRUE THEN RAISE EXCEPTION 'closed409 and authenticated complete200 originals required'; END IF;
END $$;
-- +goose StatementEnd
CREATE TABLE public.capacity_guest_prejournal_refusal_recoveries (
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
 CHECK((original_record->>'schema'='failed_installed_prejournal_refusal_recovery_v1') IS TRUE),
 CHECK((original_record->>'id'=id::text AND original_record->>'stage'=stage AND original_record->>'disposal_id'=disposal_id::text AND original_record->>'preregistration_id'=preregistration_id::text AND original_record->>'parent_intent_id'=parent_intent_id::text) IS TRUE),
 CHECK((original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$' AND original_record->>'parent_intent_sha256' ~ '^[0-9a-f]{64}$' AND original_record->>'original_claim_sha256' ~ '^[0-9a-f]{64}$') IS TRUE),
 CHECK((length(original_record->>'issuer') BETWEEN 1 AND 256 AND jsonb_typeof(original_record->'failed_run')='string' AND jsonb_typeof((original_record->>'failed_run')::jsonb)='object' AND jsonb_typeof(original_record->'original_claimed_intent')='object') IS TRUE),
 CHECK((original_record->'possible_business_effects_preserved'='true'::jsonb AND jsonb_typeof(original_record->'refusal_evidence')='object') IS TRUE),
 CHECK(original_record ?& ARRAY['schema','id','stage','disposal_id','preregistration_id','parent_intent_id','parent_intent_sha256','original_claim_sha256','issuer','actual_core_source','failed_run','original_claimed_intent','refusal_evidence','possible_business_effects_preserved']),
 CHECK((original_record-ARRAY['schema','id','stage','disposal_id','preregistration_id','parent_intent_id','parent_intent_sha256','original_claim_sha256','issuer','actual_core_source','failed_run','original_claimed_intent','claimed_intent','admission_sha256','successor_intent','refusal_evidence','possible_business_effects_preserved'])='{}'::jsonb)
);
-- +goose StatementBegin
CREATE FUNCTION public.guard_prejournal_refusal_recovery_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission public.capacity_guest_prejournal_refusal_recoveries;
        claimed public.capacity_guest_failed_installed_disposals;
        parent public.capacity_vm_retirement_intents;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('retirement-prereg:'||NEW.preregistration_id::text,0));
 SELECT * INTO STRICT claimed FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.disposal_id AND stage='claimed' AND preregistration_id=NEW.preregistration_id FOR SHARE;
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE id=NEW.parent_intent_id AND preregistration_id=NEW.preregistration_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_presend_retirement_recoveries WHERE preregistration_id=NEW.preregistration_id) THEN RAISE EXCEPTION 'never-sent79 and prejournal-refusal80 admissions are exclusive'; END IF;
 IF claimed.original_record->>'retirement_mode'<>'legacy_guest548_original_v1' OR claimed.record_sha256<>NEW.original_record->>'original_claim_sha256' OR parent.intent_sha256<>NEW.original_record->>'parent_intent_sha256' OR claimed.original_record->'claimed_intent'<>NEW.original_record->'original_claimed_intent' OR parent.original_deadline>clock_timestamp() THEN RAISE EXCEPTION 'recovery requires exact expired original and immutable original claim'; END IF;
 PERFORM public.assert_prejournal_refusal_evidence(parent.id,NEW.preregistration_id,NEW.original_record->'refusal_evidence');
 IF NEW.stage='requested' THEN
  IF NEW.original_record ?| ARRAY['claimed_intent','admission_sha256','successor_intent'] THEN RAISE EXCEPTION 'recovery admission has no claim or successor'; END IF;
 ELSE
  SELECT * INTO STRICT admission FROM public.capacity_guest_prejournal_refusal_recoveries WHERE id=NEW.id AND stage='requested';
  IF (NEW.original_record->>'admission_sha256'=admission.record_sha256) IS NOT TRUE OR
     (NEW.original_record-ARRAY['stage','claimed_intent','admission_sha256','successor_intent'])<>(admission.original_record-'stage') OR jsonb_typeof(NEW.original_record->'claimed_intent') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'recovery admission lineage mismatch'; END IF;
  IF (NEW.original_record #>>'{claimed_intent,failed_installed_disposal,retirement_refusal_recovery_id}'=NEW.id::text AND NEW.original_record #>>'{claimed_intent,failed_installed_disposal,retirement_refusal_recovery_admission_sha256}'=admission.record_sha256 AND (NEW.original_record #>>'{claimed_intent,generation}')::bigint=(NEW.original_record #>>'{original_claimed_intent,generation}')::bigint AND (NEW.original_record #>>'{claimed_intent,fencing_token}')::bigint=(NEW.original_record #>>'{original_claimed_intent,fencing_token}')::bigint+1 AND NEW.original_record #>>'{claimed_intent,lease_owner}'<>NEW.original_record #>>'{original_claimed_intent,lease_owner}' AND NEW.original_record #>>'{claimed_intent,failed_installed_disposal,run_id}'<>NEW.original_record #>>'{original_claimed_intent,failed_installed_disposal,run_id}') IS NOT TRUE THEN RAISE EXCEPTION 'recovery requires distinct new fence run and lease'; END IF;
  IF NEW.stage='claimed' THEN
   IF NEW.original_record ? 'successor_intent' THEN RAISE EXCEPTION 'claim has no successor credit'; END IF;
  ELSE
   PERFORM 1 FROM public.capacity_guest_prejournal_refusal_recoveries WHERE id=NEW.id AND stage='claimed' AND original_record->'claimed_intent'=NEW.original_record->'claimed_intent';
   IF NOT FOUND OR jsonb_typeof(NEW.original_record->'successor_intent') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'issued successor requires exact recovery claim'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER prejournal_refusal_recovery_chain BEFORE INSERT ON public.capacity_guest_prejournal_refusal_recoveries FOR EACH ROW EXECUTE FUNCTION public.guard_prejournal_refusal_recovery_chain();
-- +goose StatementBegin
CREATE FUNCTION public.guard_prejournal_refusal_recovery_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'prejournal-refusal80 recovery originals are immutable'; END $$;
-- +goose StatementEnd
CREATE TRIGGER prejournal_refusal_recovery_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_prejournal_refusal_recoveries FOR EACH ROW EXECUTE FUNCTION public.guard_prejournal_refusal_recovery_immutable();
-- +goose StatementBegin
CREATE FUNCTION public.guard_retirement_recovery_kind_exclusive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('retirement-prereg:'||NEW.preregistration_id::text,0));
 IF EXISTS(SELECT 1 FROM public.capacity_guest_prejournal_refusal_recoveries WHERE preregistration_id=NEW.preregistration_id) THEN RAISE EXCEPTION 'one successor overall: never-sent79 cannot follow refusal80'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER a_retirement_recovery_kind_exclusive BEFORE INSERT ON public.capacity_guest_presend_retirement_recoveries FOR EACH ROW EXECUTE FUNCTION public.guard_retirement_recovery_kind_exclusive();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_retirement_intent_linear_successor() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent public.capacity_vm_retirement_intents;
        issue public.capacity_guest_presend_retirement_recoveries;
        refusal public.capacity_guest_prejournal_refusal_recoveries;
        total integer;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('retirement-prereg:'||NEW.preregistration_id::text,0));
 SELECT count(*) INTO total FROM public.capacity_vm_retirement_intents WHERE preregistration_id=NEW.preregistration_id;
 IF total=0 THEN RETURN NEW; END IF;
 IF total<>1 THEN RAISE EXCEPTION 'only one explicit retirement successor overall permitted'; END IF;
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE preregistration_id=NEW.preregistration_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_prejournal_refusal_recoveries WHERE parent_intent_id=parent.id AND stage='requested') THEN
  SELECT * INTO STRICT refusal FROM public.capacity_guest_prejournal_refusal_recoveries WHERE parent_intent_id=parent.id AND preregistration_id=NEW.preregistration_id AND stage='issued';
  PERFORM public.assert_prejournal_refusal_evidence(parent.id,NEW.preregistration_id,refusal.original_record->'refusal_evidence');
  IF refusal.original_record->'successor_intent'<>NEW.intent_record OR refusal.original_record #>>'{successor_intent,request_id}'<>NEW.id::text OR NEW.id=parent.id OR NEW.attempt_id=parent.attempt_id OR NEW.nonce_sha256=parent.nonce_sha256 OR NEW.intent_sha256=parent.intent_sha256 OR NEW.original_deadline<=clock_timestamp() OR NEW.original_deadline>NEW.created_at+interval '30 seconds' THEN RAISE EXCEPTION 'refusal successor requires distinct bounded new original'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT issue FROM public.capacity_guest_presend_retirement_recoveries WHERE parent_intent_id=parent.id AND preregistration_id=NEW.preregistration_id AND stage='issued';
 IF parent.original_deadline>clock_timestamp() OR issue.original_record->'successor_intent'<>NEW.intent_record OR issue.original_record #>>'{successor_intent,request_id}'<>NEW.id::text OR NEW.id=parent.id OR NEW.attempt_id=parent.attempt_id OR NEW.nonce_sha256=parent.nonce_sha256 OR NEW.intent_sha256=parent.intent_sha256 OR NEW.original_deadline<=clock_timestamp() OR NEW.original_deadline>NEW.created_at+interval '30 seconds' THEN RAISE EXCEPTION 'successor requires exact distinct bounded new original'; END IF;
 IF EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_attempts WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_caller_returns WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_reads WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=parent.id) OR EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=parent.id) THEN RAISE EXCEPTION 'any original possible-send or Guest result forbids successor'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
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
   IF NEW.stage='quiescent' AND EXISTS(SELECT 1 FROM public.capacity_guest_prejournal_refusal_recoveries WHERE disposal_id=NEW.id AND stage='requested') THEN
    PERFORM 1 FROM public.capacity_guest_prejournal_refusal_recoveries c JOIN public.capacity_guest_prejournal_refusal_recoveries i ON i.id=c.id AND i.stage='issued'
     WHERE c.disposal_id=NEW.id AND c.stage='claimed' AND c.preregistration_id=NEW.preregistration_id
     AND c.original_record->'claimed_intent'=NEW.original_record->'claimed_intent'
     AND NEW.original_record #>>'{claimed_intent,failed_installed_disposal,retirement_refusal_recovery_id}'=c.id::text
     AND i.original_record #>>'{successor_intent,request_id}'=NEW.original_record->>'retirement_request_id';
    IF NOT FOUND THEN RAISE EXCEPTION 'quiescence requires explicit refusal80 claim and genuine new original'; END IF;
   ELSIF NEW.stage='quiescent' AND EXISTS(SELECT 1 FROM public.capacity_guest_presend_retirement_recoveries WHERE disposal_id=NEW.id AND stage='requested') THEN
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
DO $$ BEGIN RAISE EXCEPTION 'refusal80 evidence and guarded63/78 lineage cannot be downgraded'; END $$;
-- +goose StatementEnd
