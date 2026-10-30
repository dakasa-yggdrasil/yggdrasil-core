-- +goose Up
-- Separate explicit reconciliation after three authenticated548 records and a
-- closed409. Never create another63 request or pretend poweroff-returned4/200.
CREATE TABLE public.capacity_guest_partial_nativeoff_reconciliations (
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
 CHECK((original_record->>'schema'='failed_installed_partial_native_off_reconciliation_v1' AND original_record->>'id'=id::text AND original_record->>'stage'=stage AND original_record->>'disposal_id'=disposal_id::text AND original_record->>'preregistration_id'=preregistration_id::text AND original_record->>'retirement_request_id'=retirement_request_id::text) IS TRUE),
 CHECK((length(original_record->>'issuer') BETWEEN 1 AND 256 AND original_record->>'actual_core_source' ~ '^[0-9a-f]{40}$' AND original_record->>'original_claim_sha256' ~ '^[0-9a-f]{64}$' AND jsonb_typeof(original_record->'original_claimed_intent')='object' AND jsonb_typeof(original_record->'evidence')='object' AND jsonb_typeof(original_record->'failed_run')='string' AND jsonb_typeof((original_record->>'failed_run')::jsonb)='object') IS TRUE),
 CHECK(original_record ?& ARRAY['schema','id','stage','disposal_id','preregistration_id','retirement_request_id','issuer','actual_core_source','original_claim_sha256','original_claimed_intent','failed_run','evidence']),
 CHECK((original_record-ARRAY['schema','id','stage','disposal_id','preregistration_id','retirement_request_id','issuer','actual_core_source','original_claim_sha256','original_claimed_intent','failed_run','evidence','admission_sha256','native_read_id','native_off_sha256'])='{}'::jsonb)
);
CREATE TABLE public.capacity_guest_partial_nativeoff_reads (
 id uuid NOT NULL,
 stage text NOT NULL CHECK(stage IN('started','returned')),
 reconciliation_id uuid NOT NULL,
 ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 3),
 preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
 retirement_request_id uuid NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
 original_wire bytea NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 2097152),
 original_record jsonb NOT NULL CHECK(jsonb_typeof(original_record)='object' AND original_record=convert_from(original_wire,'UTF8')::jsonb),
 record_sha256 text NOT NULL CHECK(record_sha256=encode(sha256(original_wire),'hex')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(id,stage),UNIQUE(reconciliation_id,ordinal,stage),
 CHECK(((stage='started' AND original_record ?& ARRAY['schema','read_id','reconciliation_id','preregistration_id','retirement_request_id','ordinal','admission_sha256','evidence_sha256','issued_at','original_deadline']) OR
        (stage='returned' AND original_record ?& ARRAY['schema','read','status','started_at','returned_at','call_failed','context_failed'])) IS TRUE)
);
-- +goose StatementBegin
CREATE FUNCTION public.assert_partial_nativeoff_evidence(req uuid,pre uuid,e jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE parent public.capacity_vm_retirement_intents; c public.capacity_guest_original_caller_returns;
BEGIN
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE id=req AND preregistration_id=pre FOR UPDATE;
 IF (parent.original_deadline>clock_timestamp() OR (parent.intent_record->>'original_deadline')::timestamptz>clock_timestamp()) IS NOT FALSE THEN RAISE EXCEPTION 'original retirement must expire without renewal'; END IF;
 IF ((e ?& ARRAY['guest_source','source_order','caller_sha256','observation_sha256','authority_sha256','transport_sha256','snapshot_challenge_sha256','snapshot_return_sha256'] AND e->>'caller_sha256' ~ '^[0-9a-f]{64}$' AND e->>'guest_source'='548734eef627404f10b5117e0ec7f27582ae9048' AND e->>'source_order'='guest548_quiescent_then_poweroff_possible_v1') IS NOT TRUE OR
 (e-ARRAY['guest_source','source_order','caller_sha256','observation_sha256','authority_sha256','transport_sha256','snapshot_challenge_sha256','snapshot_return_sha256'])<>'{}'::jsonb) IS NOT FALSE THEN RAISE EXCEPTION 'closed distinct548 partial evidence required'; END IF;
 SELECT * INTO STRICT c FROM public.capacity_guest_original_caller_returns WHERE intent_id=req;
 IF (e->>'caller_sha256'<>c.return_sha256 OR c.original_record->>'status'<>'409' OR c.original_record->>'body_persisted'<>'false' OR
 c.original_record->>'response_body_scope'<>'complete_original_body_read' OR
 c.original_record->>'response_sha256'<>'7ccf3e6b9a90a7fa8fdac77e6ab1d88d74884691ff6f0cf1b2e6595167b6a882' OR
 c.original_record->>'retained_prefix_sha256'<>c.original_record->>'response_sha256' OR
 c.original_record->>'received_body_bytes'<>'199' OR c.original_record->>'retained_prefix_bytes'<>'199' OR
 c.original_record->>'preflight_failed'<>'false' OR c.original_record->>'do_failed'<>'false' OR c.original_record->>'read_failed'<>'false' OR c.original_record->>'close_failed'<>'false' OR c.original_record->>'original_context_failed'<>'false' OR
 (c.original_record->>'driver_returned_at')::timestamptz>=parent.original_deadline) IS NOT FALSE THEN RAISE EXCEPTION 'closed exact original548 refusal required'; END IF;
 IF ((SELECT count(*) FROM public.capacity_guest_original_caller_attempts WHERE intent_id=req)<>1 OR
 (SELECT count(*) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=req)<>3 OR
 (SELECT count(*) FROM public.capacity_guest_original_authority_reads WHERE intent_id=req)<>4 OR
 (SELECT count(*) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=req)<>4 OR
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=req)<>2 OR
 (SELECT count(*) FROM public.capacity_guest_runtime_snapshot_returns v JOIN public.capacity_guest_runtime_snapshot_challenges r ON r.id=v.challenge_id WHERE r.intent_id=req)<>2 OR
 (SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=req)<>5 OR
 EXISTS(SELECT 1 FROM public.capacity_vm_retirement_delete_bindings WHERE intent_id=req) OR
 EXISTS(SELECT 1 FROM public.capacity_guest_original_native_poweroff_reads WHERE intent_id=req)) IS NOT FALSE THEN RAISE EXCEPTION 'exact partial3 history and no existing off/delete proof required'; END IF;
 IF e->'observation_sha256' IS DISTINCT FROM (SELECT jsonb_agg(return_sha256 ORDER BY sequence) FROM public.capacity_vm_retirement_original_returns WHERE intent_id=req) OR
 EXISTS(SELECT 1 FROM public.capacity_vm_retirement_original_returns WHERE intent_id=req AND
  (sequence NOT BETWEEN 1 AND 3 OR kind<>CASE sequence WHEN 1 THEN 'possible_start' WHEN 2 THEN 'quiescent' ELSE 'poweroff_possible_start' END OR original_return_record->>'journal_complete'<>'true' OR original_return_record #>>'{record,powered_off_observed}'<>'false' OR (sequence>1 AND original_return_record #>>'{record,writer_quiescence_evidence}'<>'true')) IS NOT FALSE)
 THEN RAISE EXCEPTION 'exact original signed prefix references required'; END IF;
 IF e->'authority_sha256' IS DISTINCT FROM (SELECT jsonb_agg(v.authority_sha256 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal) FROM public.capacity_guest_original_authority_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=req) OR
 EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_reads r JOIN public.capacity_guest_original_authority_returns v ON v.read_id=r.id WHERE r.intent_id=req AND
  (r.ordinal NOT BETWEEN 1 AND 2 OR v.original_record->>'state'<>'authorized' OR v.recorded_at>=r.original_deadline OR v.recorded_at>(c.original_record->>'do_returned_at')::timestamptz) IS NOT FALSE) OR
 e->'transport_sha256' IS DISTINCT FROM (SELECT jsonb_agg(v.return_sha256 ORDER BY CASE r.phase WHEN 'before_start' THEN 0 ELSE 1 END,r.ordinal,CASE v.native_stage WHEN 'snapshot' THEN 0 ELSE 1 END) FROM public.capacity_guest_original_authority_transport_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=req) OR
 EXISTS(SELECT 1 FROM public.capacity_guest_original_authority_transport_returns v JOIN public.capacity_guest_original_authority_reads r ON r.id=v.read_id WHERE r.intent_id=req AND
  (v.original_reply_wire IS NULL OR v.original_record->>'status'<>'200' OR v.original_record->>'preflight_failed'<>'false' OR v.original_record->>'do_failed'<>'false' OR v.original_record->>'read_failed'<>'false' OR v.original_record->>'close_failed'<>'false' OR v.original_record->>'original_context_failed'<>'false' OR (v.original_record->>'driver_returned_at')::timestamptz>=r.original_deadline) IS NOT FALSE)
 THEN RAISE EXCEPTION 'four authorized closed original reads required'; END IF;
 IF (e->'snapshot_challenge_sha256' IS DISTINCT FROM (SELECT jsonb_agg(challenge_sha256 ORDER BY ordinal) FROM public.capacity_guest_runtime_snapshot_challenges WHERE intent_id=req) OR
 e->'snapshot_return_sha256' IS DISTINCT FROM (SELECT jsonb_agg(v.return_sha256 ORDER BY r.ordinal) FROM public.capacity_guest_runtime_snapshot_returns v JOIN public.capacity_guest_runtime_snapshot_challenges r ON r.id=v.challenge_id WHERE r.intent_id=req)) IS NOT FALSE THEN RAISE EXCEPTION 'exact two authenticated snapshot references required'; END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION public.guard_partial_nativeoff_reconciliation() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE claim public.capacity_guest_failed_installed_disposals; admitted public.capacity_guest_partial_nativeoff_reconciliations;
        read_return public.capacity_guest_partial_nativeoff_reads; current_record jsonb; parent public.capacity_vm_retirement_intents;
BEGIN
 SELECT * INTO STRICT claim FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.disposal_id AND stage='claimed' AND preregistration_id=NEW.preregistration_id FOR SHARE;
 SELECT intent INTO STRICT current_record FROM public.capacity_intents WHERE namespace=claim.namespace AND environment=claim.environment AND domain=claim.domain AND dimension=claim.dimension FOR UPDATE;
 PERFORM public.assert_partial_nativeoff_evidence(NEW.retirement_request_id,NEW.preregistration_id,NEW.original_record->'evidence');
 SELECT * INTO STRICT parent FROM public.capacity_vm_retirement_intents WHERE id=NEW.retirement_request_id FOR UPDATE;
 IF (claim.original_record->>'retirement_mode'<>'legacy_guest548_original_v1' OR NEW.original_record->>'original_claim_sha256'<>claim.record_sha256 OR current_record<>NEW.original_record->'original_claimed_intent' OR current_record #>>'{failed_installed_disposal,id}'<>NEW.disposal_id::text OR current_record #>>'{failed_installed_disposal,stage}'<>'claimed') IS NOT FALSE THEN RAISE EXCEPTION 'exact original claimed disposal and unchanged current required'; END IF;
 IF ((parent.intent_record->>'generation')::bigint<>(current_record->>'generation')::bigint OR (parent.intent_record->>'fence')::bigint<>(current_record->>'fencing_token')::bigint OR parent.intent_record->>'lease_owner'<>current_record->>'lease_owner' OR (current_record->>'lease_expires_at')::timestamptz>clock_timestamp()) IS NOT FALSE THEN RAISE EXCEPTION 'same expired original workflow epoch required'; END IF;
 IF (NOT EXISTS(SELECT 1 FROM public.capacity_guest_presend_retirement_recoveries WHERE disposal_id=NEW.disposal_id AND stage='issued' AND original_record->'claimed_intent'=current_record AND original_record->'successor_intent'=parent.intent_record AND original_record #>>'{successor_intent,request_id}'=NEW.retirement_request_id::text) AND
 NOT EXISTS(SELECT 1 FROM public.capacity_guest_prejournal_refusal_recoveries WHERE disposal_id=NEW.disposal_id AND stage='issued' AND original_record->'claimed_intent'=current_record AND original_record->'successor_intent'=parent.intent_record AND original_record #>>'{successor_intent,request_id}'=NEW.retirement_request_id::text)) IS NOT FALSE THEN RAISE EXCEPTION 'existing explicit79 or80 issued request required without another successor'; END IF;
 IF NEW.stage='admitted' THEN
  IF (NEW.original_record ?| ARRAY['admission_sha256','native_read_id','native_off_sha256']) IS NOT FALSE THEN RAISE EXCEPTION 'admission grants no off proof'; END IF;
 ELSE
  SELECT * INTO STRICT admitted FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE id=NEW.id AND stage='admitted';
  IF (NOT (NEW.original_record ?& ARRAY['admission_sha256','native_read_id','native_off_sha256']) OR NEW.original_record->>'native_off_sha256' !~ '^[0-9a-f]{64}$' OR NEW.original_record->>'admission_sha256'<>admitted.record_sha256 OR (NEW.original_record-ARRAY['stage','admission_sha256','native_read_id','native_off_sha256'])<>(admitted.original_record-'stage')) IS NOT FALSE THEN RAISE EXCEPTION 'qualified81 must preserve original admission'; END IF;
  SELECT * INTO STRICT read_return FROM public.capacity_guest_partial_nativeoff_reads WHERE reconciliation_id=NEW.id AND id=(NEW.original_record->>'native_read_id')::uuid AND stage='returned';
  IF (NEW.original_record->>'native_off_sha256'<>read_return.record_sha256 OR read_return.original_record->>'schema'<>'partial_guest548_native_off_return_v1' OR read_return.original_record->>'status'<>'observed' OR read_return.original_record->>'call_failed'<>'false' OR read_return.original_record->>'context_failed'<>'false' OR read_return.original_record #>>'{read,admission_sha256}'<>admitted.record_sha256 OR (read_return.original_record->>'returned_at')::timestamptz>=(read_return.original_record #>>'{read,original_deadline}')::timestamptz OR clock_timestamp()>=(read_return.original_record #>>'{read,original_deadline}')::timestamptz OR read_return.ordinal<>(SELECT max(ordinal) FROM public.capacity_guest_partial_nativeoff_reads WHERE reconciliation_id=NEW.id AND stage='started') OR jsonb_typeof(read_return.original_record->'plan') IS DISTINCT FROM 'object' OR coalesce(read_return.original_record #>>'{plan,server,status}','') NOT IN('off','stopped')) IS NOT FALSE THEN RAISE EXCEPTION 'only newest complete fresh5 exact OFF GET can qualify'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER partial_nativeoff_reconciliation_chain BEFORE INSERT ON public.capacity_guest_partial_nativeoff_reconciliations FOR EACH ROW EXECUTE FUNCTION public.guard_partial_nativeoff_reconciliation();
-- +goose StatementBegin
CREATE FUNCTION public.guard_partial_nativeoff_read() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admitted public.capacity_guest_partial_nativeoff_reconciliations; prior public.capacity_guest_partial_nativeoff_reads;
        r jsonb; last_ordinal integer;
BEGIN
 SELECT * INTO STRICT admitted FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE id=NEW.reconciliation_id AND stage='admitted' FOR SHARE;
 PERFORM 1 FROM public.capacity_vm_retirement_intents WHERE id=NEW.retirement_request_id FOR UPDATE;
 IF (NEW.preregistration_id<>admitted.preregistration_id OR NEW.retirement_request_id<>admitted.retirement_request_id) IS NOT FALSE THEN RAISE EXCEPTION 'read cannot change scope'; END IF;
 IF NEW.stage='started' THEN
  r=NEW.original_record;
  IF (r->>'schema'<>'partial_guest548_native_off_read_v1' OR (r-ARRAY['schema','read_id','reconciliation_id','preregistration_id','retirement_request_id','ordinal','admission_sha256','evidence_sha256','issued_at','original_deadline'])<>'{}'::jsonb OR r->>'admission_sha256'<>admitted.record_sha256 OR r->>'evidence_sha256' !~ '^[0-9a-f]{64}$' OR r->>'read_id'<>NEW.id::text OR r->>'reconciliation_id'<>NEW.reconciliation_id::text OR r->>'preregistration_id'<>NEW.preregistration_id::text OR r->>'retirement_request_id'<>NEW.retirement_request_id::text OR (r->>'ordinal')::integer<>NEW.ordinal OR (r->>'original_deadline')::timestamptz<=(r->>'issued_at')::timestamptz OR (r->>'original_deadline')::timestamptz>(r->>'issued_at')::timestamptz+interval '5 seconds' OR (r->>'original_deadline')::timestamptz<=clock_timestamp() OR EXISTS(SELECT 1 FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE id=NEW.reconciliation_id AND stage='qualified')) IS NOT FALSE THEN RAISE EXCEPTION 'closed distinct bounded readonly challenge required'; END IF;
  SELECT coalesce(max(ordinal),0) INTO last_ordinal FROM public.capacity_guest_partial_nativeoff_reads WHERE reconciliation_id=NEW.reconciliation_id AND stage='started';
  IF (NEW.ordinal<>last_ordinal+1) IS NOT FALSE THEN RAISE EXCEPTION 'at most three linear readonly attempts'; END IF;
  IF last_ordinal>0 THEN
   SELECT * INTO STRICT prior FROM public.capacity_guest_partial_nativeoff_reads WHERE reconciliation_id=NEW.reconciliation_id AND ordinal=last_ordinal AND stage='started';
   IF ((prior.original_record->>'original_deadline')::timestamptz>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_partial_nativeoff_reads WHERE id=prior.id AND stage='returned')) IS NOT FALSE THEN RAISE EXCEPTION 'previous original read still pending'; END IF;
  END IF;
 ELSE
  SELECT * INTO STRICT prior FROM public.capacity_guest_partial_nativeoff_reads WHERE id=NEW.id AND stage='started';
  r=NEW.original_record;
  IF (r->>'schema'<>'partial_guest548_native_off_return_v1' OR (r-ARRAY['schema','read','status','plan','started_at','returned_at','call_failed','context_failed'])<>'{}'::jsonb OR r->'read'<>prior.original_record OR NEW.reconciliation_id<>prior.reconciliation_id OR NEW.ordinal<>prior.ordinal OR jsonb_typeof(r->'call_failed') IS DISTINCT FROM 'boolean' OR jsonb_typeof(r->'context_failed') IS DISTINCT FROM 'boolean' OR (r->>'started_at')::timestamptz<(r #>>'{read,issued_at}')::timestamptz OR (r->>'returned_at')::timestamptz<(r->>'started_at')::timestamptz) IS NOT FALSE THEN RAISE EXCEPTION 'original read return cannot change challenge or normalize failure'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER partial_nativeoff_read_chain BEFORE INSERT ON public.capacity_guest_partial_nativeoff_reads FOR EACH ROW EXECUTE FUNCTION public.guard_partial_nativeoff_read();
-- +goose StatementBegin
CREATE FUNCTION public.guard_partial_nativeoff_disposal_join() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.stage IN('quiescent','terminal') AND EXISTS(SELECT 1 FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE disposal_id=NEW.id AND stage='admitted') THEN
  PERFORM 1 FROM public.capacity_guest_partial_nativeoff_reconciliations WHERE disposal_id=NEW.id AND stage='qualified' AND preregistration_id=NEW.preregistration_id AND retirement_request_id::text=NEW.original_record->>'retirement_request_id' AND original_record->>'native_off_sha256'=NEW.original_record->>'native_poweroff_sha256' AND original_record->'original_claimed_intent'=NEW.original_record->'claimed_intent';
  IF (NOT FOUND) IS NOT FALSE THEN RAISE EXCEPTION 'new81 cleanup requires explicit qualified81 lineage; never fake4/200'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER partial_nativeoff_disposal_join BEFORE INSERT ON public.capacity_guest_failed_installed_disposals FOR EACH ROW EXECUTE FUNCTION public.guard_partial_nativeoff_disposal_join();
-- +goose StatementBegin
CREATE FUNCTION public.guard_partial_nativeoff_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'partial native OFF originals are immutable'; END $$;
-- +goose StatementEnd
CREATE TRIGGER partial_nativeoff_reconciliation_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_partial_nativeoff_reconciliations FOR EACH ROW EXECUTE FUNCTION public.guard_partial_nativeoff_immutable();
CREATE TRIGGER partial_nativeoff_read_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_partial_nativeoff_reads FOR EACH ROW EXECUTE FUNCTION public.guard_partial_nativeoff_immutable();
-- +goose Down
DO $$ BEGIN RAISE EXCEPTION 'append-only81 reconciliation cannot be rolled back destructively'; END $$;
