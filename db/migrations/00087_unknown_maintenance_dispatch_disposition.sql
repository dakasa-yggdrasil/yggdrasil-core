-- +goose Up
-- ADR-0096: close only an unknown, recorded failed maintenance refresh.
-- All original job return fields and the entire workflow run are retained.
-- No ACK, replay, provider read, native mutation or quiescence is invented.

-- A closed seven-step original result. This is a maintenance hold, never a
-- provision/retire/resume. Missing keys are false, not SQL NULL acceptance.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_result_valid(result jsonb,generation text,fence text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT COALESCE(jsonb_typeof(result)='object' AND result->>'status'='failed'
 AND jsonb_typeof(result->'steps')='array' AND jsonb_array_length(result->'steps')=7
 AND NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(result->'steps') WITH ORDINALITY x(s,n)
  JOIN (VALUES
   (1,'plan-original-guest','capacity.plan_original_guest','succeeded'),
   (2,'provision-original-notify','capacity.provision_original_guest','skipped'),
   (3,'retire-original-guest','capacity.retire_original_guest','skipped'),
   (4,'refresh-original-membership','capacity.complete_original_guest','failed'),
   (5,'complete-original-provision','capacity.complete_original_guest','skipped'),
   (6,'finish-original-retirement','capacity.finish_original_guest_retirement','skipped'),
   (7,'complete-original-retirement','capacity.complete_original_guest','skipped')
  ) e(n,id,op,status) ON e.n=x.n
  WHERE (s->>'id',s->>'kind',s->>'operation',s->>'capability',s->>'status')
    IS DISTINCT FROM (e.id,'yggdrasil',e.op,e.op,e.status)
    OR (e.n NOT IN(1,4) AND COALESCE(s->>'attempts','0')<>'0')
    OR s ? 'integration_instance' OR s ? 'integration_type')
 AND result#>>'{steps,0,attempts}'='1'
 AND result#>>'{steps,0,metadata,mode}'='refresh'
 AND result#>>'{steps,0,metadata,slot}'='0'
 AND result#>>'{steps,0,metadata,reason}'='signal_evidence_unavailable'
 AND result#>>'{steps,0,metadata,generation}'=generation
 AND result#>>'{steps,0,metadata,fencing_token}'=fence
 AND result#>>'{steps,0,metadata,lease_owner}'=''
 AND result#>>'{steps,0,metadata,preregistration_id}'=''
 AND NOT (result#>'{steps,0,metadata}' ? 'request_id')
 AND result#>>'{steps,3,attempts}'='1'
 AND result#>>'{steps,3,error}'='original Guest reconciliation held'
 AND result#>>'{steps,3,metadata,original_guest_reconcile_refusal_stage}'='fresh_original_canary'
 AND result#>>'{steps,3,metadata,original_guest_notify_refusal_stage}' IN('nonce_finalize','reserve_send'),false)
$$;
-- +goose StatementEnd

-- Current stored membership, not a fresh provider observation or readiness.
-- A non-tombstoned slot must join exactly one confirmed, undisposed create,
-- preregistration, original enrollment and original installation. All originals
-- predate this dispatch's conservative window and pin its exact policy/epoch.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_members(job uuid)
RETURNS jsonb LANGUAGE sql STABLE AS $$
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 all_sl AS (SELECT s.* FROM public.capacity_resource_slots s,j WHERE s.namespace=j.realm
  AND s.environment=j.environment AND s.domain=j.domain AND s.dimension=j.dimension
  AND s.resource_id<>'' AND COALESCE(s.slot_record->>'tombstone','false')='false'
 ), sl AS (SELECT * FROM all_sl WHERE NOT(slot_record ? 'authority_kind')),
 joined AS (
 SELECT s.slot,s.resource_id,s.slot_record,s.revision,s.updated_at,p.id AS preregistration_id,
  e.enrollment_sha256,n.confirmation_sha256
 FROM sl s CROSS JOIN j
 JOIN public.capacity_mutation_grants g ON g.namespace=j.realm AND g.environment=j.environment
  AND g.domain=j.domain AND g.dimension=j.dimension AND g.slot=s.slot
  AND g.integration_instance_id=s.integration_instance_id AND g.scope_checksum=s.scope_checksum
  AND g.profile_name=s.profile_name AND g.state='confirmed'
  AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL
  AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL
 JOIN public.capacity_vm_provisioning_preregistrations p ON p.create_grant_id=g.id
  AND p.preregistration_record->>'slot'=s.slot::text
  AND p.preregistration_record->>'policy_id'=j.envelope::jsonb#>>'{policy,id}'
  AND p.preregistration_record->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND p.preregistration_record->>'workflow_id'=j.envelope::jsonb#>>'{workflow,id}'
  AND p.preregistration_record->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'
  AND p.preregistration_record->>'generation'=(SELECT intent->>'generation' FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension)
  AND p.preregistration_record->>'fence'=(SELECT intent->>'fencing_token' FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension)

 JOIN public.capacity_vm_original_enrollments e ON e.preregistration_id=p.id
  AND e.enrollment_record#>>'{statement,tuple,resource_id}'=s.resource_id
  AND e.enrollment_record#>>'{statement,tuple,resource_created_at}'=s.slot_record->>'resource_created_at'
 JOIN public.capacity_guest_original_installations n ON n.preregistration_id=p.id
 WHERE p.created_at<j.started_at-interval '30 seconds' AND e.recorded_at<j.started_at-interval '30 seconds'
  AND n.recorded_at<j.started_at-interval '30 seconds'
  AND NOT EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents ri WHERE ri.preregistration_id=p.id)
 )
SELECT CASE WHEN (SELECT count(*) FROM sl) BETWEEN 1 AND 8
 AND (SELECT count(*) FROM sl)=(SELECT count(*) FROM all_sl)
 AND (SELECT count(*) FROM joined)=(SELECT count(*) FROM sl)
 AND (SELECT count(DISTINCT slot) FROM joined)=(SELECT count(*) FROM sl)
 THEN (SELECT jsonb_agg(jsonb_build_object('slot',slot,'resource_id',resource_id,
  'preregistration_id',preregistration_id,'enrollment_sha256',enrollment_sha256,
  'installation_sha256',confirmation_sha256,
  'slot_sha256',encode(sha256(convert_to(jsonb_build_object('record',slot_record,'revision',revision,'updated_at',updated_at)::text,'UTF8')),'hex'))
  ORDER BY slot) FROM joined)
 ELSE '[]'::jsonb END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan(job uuid)
RETURNS jsonb LANGUAGE sql STABLE AS $$
WITH j AS (SELECT * FROM public.capacity_dispatch_jobs WHERE id=job),
 w AS (SELECT w.* FROM public.workflow_runs w,j WHERE w.id=j.run_id),
 it AS (SELECT i.intent FROM public.capacity_intents i,j WHERE i.namespace=j.realm
  AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension),
 mem AS (SELECT public.unknown_maintenance_dispatch_members(job) AS members),
 candidates AS (
 SELECT c.* FROM public.capacity_guest_notify_canary_challenges c
 JOIN public.capacity_vm_provisioning_preregistrations p ON p.id=c.preregistration_id
 JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id CROSS JOIN j
 WHERE g.namespace=j.realm AND g.environment=j.environment AND g.domain=j.domain AND g.dimension=j.dimension
 AND (c.recorded_at>=j.started_at-interval '30 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces n WHERE n.challenge_id=c.id AND n.recorded_at>=j.started_at-interval '30 seconds')
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=c.id AND (s.recorded_at>=j.started_at-interval '30 seconds' OR s.possible_send_at>=j.started_at-interval '30 seconds'))
  OR EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.started_at-interval '30 seconds'))),
 epoch AS (SELECT COALESCE(
  j.environment='production' AND j.domain='notify' AND j.dimension IN('original_notify_aws_vm_members','original_notify_hetzner_vm_members')
  AND it.intent->>'policy_id'=j.envelope::jsonb#>>'{policy,id}'
  AND it.intent->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND it.intent->>'phase' IN('promoted','reconciled','reconciled_partial')
  AND COALESCE(it.intent->>'lease_owner','')='' AND COALESCE(it.intent->>'lease_executor_id','')=''
  AND COALESCE(jsonb_typeof(it.intent->'lease_expires_at'),'null')='null'
  AND COALESCE(it.intent->>'recovery_only','false')='false' AND COALESCE(it.intent->>'floor_degraded','false')='false'
  AND COALESCE(jsonb_typeof(it.intent->'failed_installed_disposal'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'installed_guest_reconcile'),'null')='null'
  AND COALESCE(jsonb_typeof(it.intent->'original_notify_window'),'null')='null'
  AND it.intent#>>'{decision,action}'='hold' AND COALESCE(it.intent#>>'{decision,execution_permitted}','false')='false'
  AND EXISTS(SELECT 1 FROM public.manifests p WHERE p.id::text=j.envelope::jsonb#>>'{policy,id}' AND p.kind='capacity_policy'
   AND p.active AND p.checksum=j.envelope::jsonb#>>'{policy,checksum}'
   AND p.spec#>>'{guest_notify_reconcile_binding,mode}'='original_guest_notify_reconcile_v1'
   AND p.spec#>>'{environment}'=j.environment AND p.spec#>>'{domain}'=j.domain AND p.spec#>>'{dimension}'=j.dimension)
  AND EXISTS(SELECT 1 FROM public.manifests wf WHERE wf.id::text=j.envelope::jsonb#>>'{workflow,id}' AND wf.kind='workflow'
   AND wf.active AND wf.checksum=j.envelope::jsonb#>>'{workflow,checksum}'),false) AS valid FROM j,w,it)
SELECT jsonb_build_object('schema','unknown_maintenance_dispatch_effect_scan_v1',
 'base',public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at),
 'current_members',(SELECT members FROM mem),
 'current_members_sha256',encode(sha256(convert_to((SELECT members FROM mem)::text,'UTF8')),'hex'),
 'current_member_count',jsonb_array_length((SELECT members FROM mem)),
 'policy_epoch_valid',COALESCE((SELECT valid FROM epoch),false),
 'refresh_only_result',COALESCE((SELECT public.unknown_maintenance_dispatch_result_valid(w.result,it.intent->>'generation',it.intent->>'fencing_token')
  AND w.result#>>'{workflow,id}'=j.envelope::jsonb#>>'{workflow,id}'
  AND w.result#>>'{workflow,kind}'='workflow'
  AND w.result#>>'{workflow,namespace}'=j.envelope::jsonb#>>'{workflow,namespace}'
  AND w.result#>>'{workflow,name}'=j.envelope::jsonb#>>'{workflow,name}'
  AND w.result#>>'{workflow,version}'=j.envelope::jsonb#>>'{workflow,version}' FROM w,it),false),
 'invalid_maintenance_canary_rows',(SELECT count(*) FROM candidates c WHERE NOT COALESCE(
  c.original_record->>'usage_class'='steady_useful_membership'
  AND c.policy_id::text=j.envelope::jsonb#>>'{policy,id}' AND c.workflow_id::text=j.envelope::jsonb#>>'{workflow,id}'
  AND c.generation::text=(SELECT intent->>'generation' FROM it) AND c.fence::text=(SELECT intent->>'fencing_token' FROM it)
  AND c.original_record->>'policy_checksum'=j.envelope::jsonb#>>'{policy,checksum}'
  AND c.original_record->>'workflow_checksum'=j.envelope::jsonb#>>'{workflow,checksum}'
  AND c.original_deadline<=j.lease_expires_at AND c.original_deadline<statement_timestamp()
  AND EXISTS(SELECT 1 FROM jsonb_array_elements((SELECT members FROM mem)) m WHERE m->>'preregistration_id'=c.preregistration_id::text)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_sends s WHERE s.challenge_id=c.id
    AND (s.possible_send_at>=c.original_deadline OR s.original_deadline IS DISTINCT FROM c.original_deadline OR s.recorded_at>=j.lease_expires_at))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_nonces n WHERE n.challenge_id=c.id AND n.recorded_at>=j.lease_expires_at)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_returns r WHERE r.challenge_id=c.id AND r.recorded_at>=j.lease_expires_at),false)))
FROM j
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.unknown_maintenance_dispatch_effect_scan_tolerable(scan jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT COALESCE(jsonb_typeof(scan)='object' AND scan->>'schema'='unknown_maintenance_dispatch_effect_scan_v1'
 AND scan->'policy_epoch_valid'='true'::jsonb AND scan->'refresh_only_result'='true'::jsonb
 AND scan->'invalid_maintenance_canary_rows'='0'::jsonb
 AND jsonb_typeof(scan->'current_members')='array' AND jsonb_array_length(scan->'current_members') BETWEEN 1 AND 8
 AND scan->'current_member_count'=to_jsonb(jsonb_array_length(scan->'current_members'))
 AND scan->>'current_members_sha256'=encode(sha256(convert_to((scan->'current_members')::text,'UTF8')),'hex')
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan->'base') e WHERE e.key IN('canary_challenges_since_start','canary_nonces_since_start','canary_possible_sends_since_start','canary_returns_since_start')
   AND (jsonb_typeof(e.value)<>'number' OR (e.value::text)::numeric<0 OR trunc((e.value::text)::numeric)<>(e.value::text)::numeric))
 AND public.finalization_lost_dispatch_effect_scan_tolerable((scan->'base') || jsonb_build_object(
  'canary_challenges_since_start',0,'canary_nonces_since_start',0,'canary_possible_sends_since_start',0,'canary_returns_since_start',0)),false)
$$;
-- +goose StatementEnd

CREATE TABLE IF NOT EXISTS public.capacity_dispatch_unknown_maintenance_dispositions (
 id uuid PRIMARY KEY,
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
 original_dispatch_sha256 text NOT NULL CHECK(original_dispatch_sha256 ~ '^[a-f0-9]{64}$'),
 original_run_sha256 text NOT NULL CHECK(original_run_sha256 ~ '^[a-f0-9]{64}$'),
 original_returned_at timestamptz NOT NULL,
 current_members_sha256 text NOT NULL CHECK(current_members_sha256 ~ '^[a-f0-9]{64}$'),
 executor_barrier text NOT NULL CHECK(executor_barrier='disposing_core_process_started_after_lease_expiry_v1'),
 disposing_core_process_started_at timestamptz NOT NULL,
 disposing_core_hostname text NOT NULL CHECK(disposing_core_hostname ~ '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'),
 disposing_core_pid integer NOT NULL CHECK(disposing_core_pid>0),
 disposing_core_source_commit text NOT NULL CHECK(disposing_core_source_commit ~ '^([0-9a-f]{40})?$'),
 issuer text NOT NULL CHECK(issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
 reason text NOT NULL CHECK(reason='unknown_failed_maintenance_dispatch_disposed'),
 historical_return text NOT NULL CHECK(historical_return='unknown'),
 recorded_at timestamptz NOT NULL,
 provider_mutation_evidence jsonb NOT NULL CHECK(public.unknown_maintenance_dispatch_effect_scan_tolerable(provider_mutation_evidence)),
 UNIQUE(id,job_id)
);
ALTER TABLE public.capacity_dispatch_jobs ADD COLUMN IF NOT EXISTS unknown_maintenance_disposition_id uuid;
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_dispatch_jobs'::regclass AND conname='capacity_unknown_maintenance_matching_job_fk') THEN
 ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_unknown_maintenance_matching_job_fk
 FOREIGN KEY(unknown_maintenance_disposition_id,id) REFERENCES public.capacity_dispatch_unknown_maintenance_dispositions(id,job_id);
 END IF;
END $idempotent$;
-- +goose StatementEnd
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_state_v7_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT IF EXISTS capacity_dispatch_jobs_lifecycle_v7_check;
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_dispatch_jobs'::regclass AND conname='capacity_dispatch_jobs_state_v8_check') THEN
 ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_state_v8_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed'));
 END IF;
END $idempotent$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_dispatch_jobs'::regclass AND conname='capacity_dispatch_jobs_lifecycle_v8_check') THEN
 ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v8_check CHECK(
  (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
  OR (state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
  OR (state='unknown' AND started_at IS NOT NULL)
  OR (state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed','unknown_maintenance_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
  OR (state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL));
 END IF;
END $idempotent$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.capacity_dispatch_jobs'::regclass AND conname='capacity_dispatch_jobs_unknown_maintenance_check') THEN
 ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_dispatch_jobs_unknown_maintenance_check CHECK(
  (state='unknown_maintenance_disposed' AND unknown_maintenance_disposition_id IS NOT NULL AND finalization_ack_at IS NULL)
  OR (state<>'unknown_maintenance_disposed' AND unknown_maintenance_disposition_id IS NULL));
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- Receipt precedes the one terminal change, under scope/job/run row locks.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_unknown_maintenance_dispatch_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs; scan jsonb;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[j.realm,j.environment,j.domain,j.dimension]) n WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'unknown maintenance disposition requires one scope lock encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[j.realm,j.environment,j.domain,j.dimension])::text,0));
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=j.run_id FOR UPDATE;
 PERFORM id FROM public.manifests WHERE id::text IN(j.envelope::jsonb#>>'{policy,id}',j.envelope::jsonb#>>'{workflow,id}',j.envelope::jsonb#>>'{rbac,id}',j.envelope::jsonb#>>'{authorization_policy,id}') ORDER BY id FOR SHARE;
 PERFORM namespace FROM public.capacity_intents WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension FOR SHARE;
 PERFORM slot FROM public.capacity_resource_slots WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE;
 PERFORM id FROM public.capacity_mutation_grants WHERE namespace=j.realm AND environment=j.environment AND domain=j.domain AND dimension=j.dimension ORDER BY id FOR SHARE;
 IF j.protocol<>'capacity_dispatch_prestart_v1' OR j.state<>'unknown' OR j.started_at IS NULL OR j.returned_at IS NULL
 OR j.return_status IS DISTINCT FROM 'failed' OR j.return_error IS DISTINCT FROM 'capacity dispatch original deadline exceeded'
 OR j.finalization_ack_at IS NOT NULL OR j.finalization_error IS NOT NULL
 OR j.failed_original_disposition_id IS NOT NULL OR j.native_denied_disposition_id IS NOT NULL OR j.enrolled_failed_disposition_id IS NOT NULL
 OR j.abandoned_disposition_id IS NOT NULL OR j.finalization_lost_disposition_id IS NOT NULL OR j.unknown_maintenance_disposition_id IS NOT NULL
 OR j.lease_owner IS NULL OR j.lease_expires_at IS NULL OR j.started_at>=j.returned_at OR j.returned_at>=j.lease_expires_at
 OR j.lease_expires_at>clock_timestamp()-interval '15 minutes'
 OR w.id<>NEW.run_id OR w.status<>'failed' OR w.error IS DISTINCT FROM j.return_error OR w.started_at IS DISTINCT FROM j.started_at
 OR w.finished_at IS DISTINCT FROM j.returned_at OR w.result IS NULL
 OR NEW.original_returned_at IS DISTINCT FROM j.returned_at
 OR NEW.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')
 OR NEW.original_run_sha256<>encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')
 OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 OR NEW.disposing_core_process_started_at<=j.lease_expires_at OR NEW.disposing_core_process_started_at>NEW.recorded_at
 THEN RAISE EXCEPTION 'unknown maintenance disposition requires an exact expired recorded failed refresh and later process'; END IF;
 scan=public.unknown_maintenance_dispatch_effect_scan(j.id);
 IF NEW.provider_mutation_evidence IS DISTINCT FROM scan OR NOT public.unknown_maintenance_dispatch_effect_scan_tolerable(scan)
 OR NEW.current_members_sha256 IS DISTINCT FROM scan->>'current_members_sha256'
 THEN RAISE EXCEPTION 'unknown maintenance disposition requires current exact members and no native mutation effects'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_unknown_maintenance_dispositions'::regclass AND tgname='unknown_maintenance_dispatch_disposition_insert') THEN
 CREATE TRIGGER unknown_maintenance_dispatch_disposition_insert BEFORE INSERT ON public.capacity_dispatch_unknown_maintenance_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.guard_unknown_maintenance_dispatch_disposition_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.immutable_unknown_maintenance_dispatch_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'unknown maintenance dispatch disposition is immutable'; END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_unknown_maintenance_dispositions'::regclass AND tgname='unknown_maintenance_dispatch_disposition_immutable') THEN
 CREATE TRIGGER unknown_maintenance_dispatch_disposition_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_unknown_maintenance_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.immutable_unknown_maintenance_dispatch_disposition();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.check_unknown_maintenance_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE d public.capacity_dispatch_unknown_maintenance_dispositions;
BEGIN
 IF old_row.unknown_maintenance_disposition_id IS NOT NULL OR old_row.state='unknown_maintenance_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'unknown maintenance disposed dispatch is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'unknown' OR new_row.state<>'unknown_maintenance_disposed' OR new_row.unknown_maintenance_disposition_id IS NULL
 OR old_row.returned_at IS NULL OR old_row.finalization_ack_at IS NOT NULL
 OR (to_jsonb(new_row)-ARRAY['state','updated_at','unknown_maintenance_disposition_id'])
 IS DISTINCT FROM (to_jsonb(old_row)-ARRAY['state','updated_at','unknown_maintenance_disposition_id'])
 THEN RAISE EXCEPTION 'unknown maintenance disposition must preserve every original return field'; END IF;
 SELECT * INTO STRICT d FROM public.capacity_dispatch_unknown_maintenance_dispositions WHERE id=new_row.unknown_maintenance_disposition_id AND job_id=old_row.id;
 IF d.run_id<>old_row.run_id OR d.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(old_row)::text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'unknown maintenance disposition requires same transaction original snapshot'; END IF;
 RETURN new_row;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
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
CREATE OR REPLACE FUNCTION public.guard_unknown_maintenance_dispatch_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='unknown_maintenance_disposed' OR NEW.unknown_maintenance_disposition_id IS NOT NULL
 THEN RAISE EXCEPTION 'unknown maintenance disposition requires a retained original job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_jobs'::regclass AND tgname='unknown_maintenance_dispatch_insert') THEN
 CREATE TRIGGER unknown_maintenance_dispatch_insert BEFORE INSERT ON public.capacity_dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION public.guard_unknown_maintenance_dispatch_insert();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- The whole already-finished workflow stays byte-identical, including its
-- result/error/times; administrative disposal cannot pretend to finish it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_unknown_maintenance_dispatch_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_dispatch_unknown_maintenance_dispositions WHERE run_id=OLD.id)
 AND (TG_OP='DELETE' OR NEW IS DISTINCT FROM OLD)
 THEN RAISE EXCEPTION 'unknown maintenance original workflow history is immutable'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.workflow_runs'::regclass AND tgname='unknown_maintenance_dispatch_workflow_immutable') THEN
 CREATE TRIGGER unknown_maintenance_dispatch_workflow_immutable BEFORE UPDATE OR DELETE ON public.workflow_runs
 FOR EACH ROW EXECUTE FUNCTION public.guard_unknown_maintenance_dispatch_workflow();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.require_unknown_maintenance_dispatch_disposition_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=NEW.run_id;
 IF j.unknown_maintenance_disposition_id IS DISTINCT FROM NEW.id OR j.state<>'unknown_maintenance_disposed'
 OR j.returned_at IS DISTINCT FROM NEW.original_returned_at OR j.finalization_ack_at IS NOT NULL
 OR encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')<>NEW.original_run_sha256
 THEN RAISE EXCEPTION 'unknown maintenance disposition requires linked terminal with unchanged original return in same commit'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $idempotent$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_dispatch_unknown_maintenance_dispositions'::regclass AND tgname='unknown_maintenance_dispatch_disposition_complete_links') THEN
 CREATE CONSTRAINT TRIGGER unknown_maintenance_dispatch_disposition_complete_links AFTER INSERT ON public.capacity_dispatch_unknown_maintenance_dispositions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_unknown_maintenance_dispatch_disposition_links();
 END IF;
END $idempotent$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'unknown maintenance dispatch disposition is a retained forward-only boundary'; END; $$;
-- +goose StatementEnd
