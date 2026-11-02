-- +goose Up
-- An administrative terminal for a started capacity dispatch whose original
-- executor is gone and whose actual return was never recorded (ADR-0089).
-- It is NOT a return, an acknowledgment, a replay or proof that no provider
-- effect happened: returned_at, return_status and finalization_ack_at stay
-- NULL forever and the receipt records historical_return='unknown'.

-- One SQL definition of the scope effect scan, used by the repository and by
-- the receipt guard. Every count must be zero for a disposal. The scan reads
-- the enumerated Core ledgers below only (not every Core table: the host
-- factory ledgers belong to other capabilities); it performs no provider read
-- and proves no provider quiescence, which the two fixed false members state
-- explicitly. Many compared columns are application clock values, so the
-- window opens a fixed 30 seconds before the database started_at
-- (clock_skew_margin_seconds) to keep a lagging executor clock from hiding an
-- effect. The job's own original Notify-window marker is counted with no time
-- bound because its writers append no intent event.
-- +goose StatementBegin
CREATE FUNCTION public.abandoned_started_dispatch_effect_scan(scope_realm text,scope_environment text,scope_domain text,scope_dimension text,job uuid,since timestamptz)
RETURNS jsonb LANGUAGE sql STABLE AS $$
WITH win AS (
 SELECT since - interval '30 seconds' AS t
), g AS (
 SELECT id,state,updated_at,grant_record,original_disposition_id,failed_original_disposition_id,native_denied_disposition_id,enrolled_failed_disposition_id
 FROM public.capacity_mutation_grants
 WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension
), p AS (
 SELECT r.id,r.created_at FROM public.capacity_vm_provisioning_preregistrations r JOIN g ON g.id=r.create_grant_id
), c AS (
 SELECT x.id,x.recorded_at FROM public.capacity_guest_notify_canary_challenges x JOIN p ON p.id=x.preregistration_id
), ri AS (
 SELECT i.id,i.created_at FROM public.capacity_vm_retirement_intents i JOIN p ON p.id=i.preregistration_id
), ar AS (
 SELECT a.id,a.possible_read_at FROM public.capacity_guest_original_authority_reads a JOIN ri ON ri.id=a.intent_id
), sc AS (
 SELECT x.id,x.recorded_at FROM public.capacity_guest_runtime_snapshot_challenges x JOIN ri ON ri.id=x.intent_id
), it AS (
 SELECT intent,updated_at FROM public.capacity_intents
 WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension
)
SELECT jsonb_build_object(
 'schema','abandoned_started_dispatch_effect_scan_v2',
 'clock_skew_margin_seconds',30,
 'grants_created_or_updated_since_start',(SELECT count(*) FROM g WHERE g.updated_at>=(SELECT t FROM win)
   OR (jsonb_typeof(g.grant_record->'created_at')='string' AND g.grant_record->>'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'
       AND (g.grant_record->>'created_at')::timestamptz>=(SELECT t FROM win))),
 'open_undisposed_grants',(SELECT count(*) FROM g WHERE g.state IN('issued','redeemed','compensating')
   AND g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL
   AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL),
 'preregistrations_since_start',(SELECT count(*) FROM p WHERE p.created_at>=(SELECT t FROM win)),
 'create_witnesses_since_start',(SELECT count(*) FROM public.capacity_guest_original_create_witnesses w JOIN p ON p.id=w.preregistration_id WHERE w.recorded_at>=(SELECT t FROM win)),
 'enrollments_since_start',(SELECT count(*) FROM public.capacity_vm_original_enrollments e JOIN p ON p.id=e.preregistration_id WHERE e.recorded_at>=(SELECT t FROM win)),
 'installations_since_start',(SELECT count(*) FROM public.capacity_guest_original_installations n JOIN p ON p.id=n.preregistration_id WHERE n.recorded_at>=(SELECT t FROM win)),
 'qualification_probe_challenges_since_start',(SELECT count(*) FROM public.capacity_guest_qualification_probe_challenges x JOIN p ON p.id=x.preregistration_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'qualification_native_source_returns_since_start',(SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns x JOIN p ON p.id=x.preregistration_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'source_recovery_cleanup_challenges_since_start',(SELECT count(*) FROM public.capacity_source_recovery_cleanup_challenges x JOIN p ON p.id=x.preregistration_id WHERE x.prepared_at>=(SELECT t FROM win)),
 'source_recovery_cleanup_effect_permits_since_start',(SELECT count(*) FROM public.capacity_source_recovery_cleanup_effect_permits x JOIN g ON g.id=x.child_grant_id WHERE x.checked_at>=(SELECT t FROM win)),
 'partial_nativeoff_reconciliations_since_start',(SELECT count(*) FROM public.capacity_guest_partial_nativeoff_reconciliations x JOIN p ON p.id=x.preregistration_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'partial_nativeoff_reads_since_start',(SELECT count(*) FROM public.capacity_guest_partial_nativeoff_reads x JOIN p ON p.id=x.preregistration_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'prejournal_refusal_recoveries_since_start',(SELECT count(*) FROM public.capacity_guest_prejournal_refusal_recoveries x JOIN p ON p.id=x.preregistration_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'presend_retirement_recoveries_since_start',(SELECT count(*) FROM public.capacity_guest_presend_retirement_recoveries x JOIN p ON p.id=x.preregistration_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'retirement_intents_since_start',(SELECT count(*) FROM ri WHERE ri.created_at>=(SELECT t FROM win)),
 'retirement_contexts_since_start',(SELECT count(*) FROM public.capacity_guest_original_retirement_contexts x JOIN ri ON ri.id=x.intent_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'retirement_original_returns_since_start',(SELECT count(*) FROM public.capacity_vm_retirement_original_returns x JOIN ri ON ri.id=x.intent_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'retirement_delete_bindings_since_start',(SELECT count(*) FROM public.capacity_vm_retirement_delete_bindings x WHERE (x.intent_id IN(SELECT id FROM ri) OR x.destroy_grant_id IN(SELECT id FROM g)) AND x.recorded_at>=(SELECT t FROM win)),
 'retirement_native_readbacks_since_start',(SELECT count(*) FROM public.capacity_vm_retirement_native_readbacks x JOIN g ON g.id=x.destroy_grant_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'caller_possible_sends_since_start',(SELECT count(*) FROM public.capacity_guest_original_caller_attempts a JOIN ri ON ri.id=a.intent_id WHERE a.possible_send_at>=(SELECT t FROM win)),
 'caller_returns_since_start',(SELECT count(*) FROM public.capacity_guest_original_caller_returns x JOIN ri ON ri.id=x.intent_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'runtime_snapshot_challenges_since_start',(SELECT count(*) FROM sc WHERE sc.recorded_at>=(SELECT t FROM win)),
 'runtime_snapshot_returns_since_start',(SELECT count(*) FROM public.capacity_guest_runtime_snapshot_returns x JOIN sc ON sc.id=x.challenge_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'authority_reads_since_start',(SELECT count(*) FROM ar WHERE ar.possible_read_at>=(SELECT t FROM win)),
 'authority_returns_since_start',(SELECT count(*) FROM public.capacity_guest_original_authority_returns x JOIN ar ON ar.id=x.read_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'authority_transport_returns_since_start',(SELECT count(*) FROM public.capacity_guest_original_authority_transport_returns x JOIN ar ON ar.id=x.read_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'native_poweroff_reads_since_start',(SELECT count(*) FROM public.capacity_guest_original_native_poweroff_reads x JOIN ri ON ri.id=x.intent_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'canary_challenges_since_start',(SELECT count(*) FROM c WHERE c.recorded_at>=(SELECT t FROM win)),
 'canary_nonces_since_start',(SELECT count(*) FROM public.capacity_guest_notify_canary_nonces x JOIN c ON c.id=x.challenge_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'canary_possible_sends_since_start',(SELECT count(*) FROM public.capacity_guest_notify_canary_sends s JOIN c ON c.id=s.challenge_id WHERE s.possible_send_at>=(SELECT t FROM win) OR s.recorded_at>=(SELECT t FROM win)),
 'canary_returns_since_start',(SELECT count(*) FROM public.capacity_guest_notify_canary_returns x JOIN c ON c.id=x.challenge_id WHERE x.recorded_at>=(SELECT t FROM win)),
 'intents_updated_since_start',(SELECT count(*) FROM it WHERE it.updated_at>=(SELECT t FROM win)),
 'notify_window_markers_for_job',(SELECT count(*) FROM it WHERE jsonb_typeof(it.intent->'original_notify_window')='object'
   AND it.intent->'original_notify_window'->>'dispatch_job_id'=job::text),
 'intent_events_since_start',(SELECT count(*) FROM public.capacity_intent_events WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension AND recorded_at>=(SELECT t FROM win)),
 'native_commands_since_start',(SELECT count(*) FROM public.capacity_native_commands WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension AND updated_at>=(SELECT t FROM win)),
 'native_lifetimes_updated_since_start',(SELECT count(*) FROM public.capacity_native_lifetimes WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension AND updated_at>=(SELECT t FROM win)),
 'native_lifetime_archives_since_start',(SELECT count(*) FROM public.capacity_native_lifetime_archive WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension AND archived_at>=(SELECT t FROM win)),
 'native_pod_checkpoints_since_start',(SELECT count(*) FROM public.capacity_native_pod_checkpoints WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension AND updated_at>=(SELECT t FROM win)),
 'executor_activity_updated_since_start',(SELECT count(*) FROM public.capacity_executor_activity WHERE scope_key=array_to_json(ARRAY[scope_realm,scope_environment,scope_domain,scope_dimension])::text AND updated_at>=(SELECT t FROM win)),
 'resource_slots_updated_since_start',(SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=scope_realm AND environment=scope_environment AND domain=scope_domain AND dimension=scope_dimension AND updated_at>=(SELECT t FROM win)),
 'provider_read_performed',false,
 'provider_quiescence_proved',false)
$$;
-- +goose StatementEnd

CREATE TABLE public.capacity_dispatch_abandoned_dispositions (
 id uuid PRIMARY KEY,
 job_id uuid NOT NULL UNIQUE REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
 realm text NOT NULL CHECK(length(realm) BETWEEN 1 AND 64),
 environment text NOT NULL CHECK(length(environment) BETWEEN 1 AND 128),
 domain text NOT NULL CHECK(length(domain) BETWEEN 1 AND 128),
 dimension text NOT NULL CHECK(length(dimension) BETWEEN 1 AND 128),
 envelope_sha256 text NOT NULL CHECK(envelope_sha256 ~ '^[a-f0-9]{64}$'),
 fencing_token bigint NOT NULL CHECK(fencing_token BETWEEN 1 AND 9007199254740991),
 lease_owner uuid NOT NULL,
 lease_expires_at timestamptz NOT NULL,
 started_at timestamptz NOT NULL,
 pending_wake_count integer NOT NULL CHECK(pending_wake_count BETWEEN 1 AND 32),
 original_dispatch_sha256 text NOT NULL CHECK(original_dispatch_sha256 ~ '^[a-f0-9]{64}$'),
 original_run_sha256 text NOT NULL CHECK(original_run_sha256 ~ '^[a-f0-9]{64}$'),
 executor_barrier text NOT NULL CHECK(executor_barrier='disposing_core_process_started_after_lease_expiry_v1'),
 disposing_core_process_started_at timestamptz NOT NULL,
 disposing_core_hostname text NOT NULL CHECK(disposing_core_hostname ~ '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'),
 disposing_core_pid integer NOT NULL CHECK(disposing_core_pid > 0),
 disposing_core_source_commit text NOT NULL CHECK(disposing_core_source_commit ~ '^([0-9a-f]{40})?$'),
 minimum_lease_age_seconds integer NOT NULL CHECK(minimum_lease_age_seconds=900),
 recorded_at timestamptz NOT NULL,
 issuer text NOT NULL CHECK(issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
 reason text NOT NULL CHECK(reason='abandoned_started_dispatch_disposed'),
 historical_return text NOT NULL CHECK(historical_return='unknown'),
 run_status text NOT NULL CHECK(run_status='failed'),
 run_error text NOT NULL CHECK(run_error='abandoned_started_dispatch_disposed: historical outcome unknown'),
 provider_mutation_evidence jsonb NOT NULL CHECK(jsonb_typeof(provider_mutation_evidence)='object'
   AND provider_mutation_evidence->>'schema'='abandoned_started_dispatch_effect_scan_v2'
   AND provider_mutation_evidence->'clock_skew_margin_seconds'='30'::jsonb
   AND provider_mutation_evidence->'provider_read_performed'='false'::jsonb
   AND provider_mutation_evidence->'provider_quiescence_proved'='false'::jsonb),
 CHECK(started_at < lease_expires_at),
 CHECK(recorded_at >= lease_expires_at + interval '15 minutes'),
 CHECK(disposing_core_process_started_at > lease_expires_at AND disposing_core_process_started_at <= recorded_at),
 UNIQUE(id,job_id)
);

ALTER TABLE public.capacity_dispatch_jobs ADD COLUMN abandoned_disposition_id uuid;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_abandoned_matching_job_fk
 FOREIGN KEY(abandoned_disposition_id,id) REFERENCES public.capacity_dispatch_abandoned_dispositions(id,job_id);
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_state_v5_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_lifecycle_v5_check;
-- Only the new terminal keeps returned_at NULL after a possible start. Every
-- earlier state keeps its exact migration76 lifecycle predicate.
ALTER TABLE public.capacity_dispatch_jobs
 ADD CONSTRAINT capacity_dispatch_jobs_state_v6_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed')),
 ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v6_check CHECK(
  (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
  OR (state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
  OR (state='unknown' AND started_at IS NOT NULL)
  OR (state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
  OR (state='abandoned_disposed' AND started_at IS NOT NULL AND returned_at IS NULL)),
 ADD CONSTRAINT capacity_dispatch_jobs_abandoned_check CHECK(
  (state='abandoned_disposed' AND abandoned_disposition_id IS NOT NULL AND returned_at IS NULL
   AND return_status IS NULL AND return_error IS NULL AND finalization_ack_at IS NULL)
  OR (state<>'abandoned_disposed' AND abandoned_disposition_id IS NULL));

-- The receipt is written first, under the same scope advisory lock as Enqueue
-- and the job/run row locks. It re-derives every fact from the locked rows.
-- +goose StatementBegin
CREATE FUNCTION public.guard_abandoned_dispatch_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs; scan jsonb;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 -- The scope lock key must be byte-identical to Go json.Marshal, which
 -- HTML-escapes <, > and & and escapes U+2028/U+2029 where array_to_json does
 -- not. Printable ASCII without those three characters encodes identically.
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[j.realm,j.environment,j.domain,j.dimension]) n
           WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'abandoned dispatch disposition requires a scope name with one lock encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[j.realm,j.environment,j.domain,j.dimension])::text,0));
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=j.run_id FOR UPDATE;
 IF j.protocol<>'capacity_dispatch_prestart_v1' OR j.state<>'started' OR j.started_at IS NULL
 OR j.returned_at IS NOT NULL OR j.return_status IS NOT NULL OR j.return_error IS NOT NULL
 OR j.finalization_error IS NOT NULL OR j.finalization_ack_at IS NOT NULL
 OR j.failed_original_disposition_id IS NOT NULL OR j.native_denied_disposition_id IS NOT NULL
 OR j.enrolled_failed_disposition_id IS NOT NULL OR j.abandoned_disposition_id IS NOT NULL
 OR j.lease_owner IS NULL OR j.lease_expires_at IS NULL
 OR j.lease_expires_at > clock_timestamp()-interval '15 minutes'
 THEN RAISE EXCEPTION 'abandoned dispatch disposition requires an expired started job with no actual return'; END IF;
 IF (NEW.run_id,NEW.realm,NEW.environment,NEW.domain,NEW.dimension,NEW.envelope_sha256,NEW.fencing_token,
     NEW.lease_owner,NEW.lease_expires_at,NEW.started_at,NEW.pending_wake_count)
 IS DISTINCT FROM
    (j.run_id,j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,
     j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count)
 OR NEW.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')
 OR NEW.original_run_sha256<>encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')
 OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 THEN RAISE EXCEPTION 'abandoned dispatch disposition requires the exact locked original job and run'; END IF;
 IF w.status<>'running' OR w.started_at IS DISTINCT FROM j.started_at OR w.finished_at IS NOT NULL
 OR w.result IS NOT NULL OR w.error IS NOT NULL
 THEN RAISE EXCEPTION 'abandoned dispatch disposition requires the original running workflow'; END IF;
 scan=public.abandoned_started_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at);
 IF NEW.provider_mutation_evidence IS DISTINCT FROM scan
 OR EXISTS(SELECT 1 FROM jsonb_each(scan) e WHERE e.key NOT IN('schema','clock_skew_margin_seconds') AND e.value NOT IN('0'::jsonb,'false'::jsonb))
 THEN RAISE EXCEPTION 'abandoned dispatch disposition requires zero recorded effects in scope since start'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER abandoned_dispatch_disposition_insert BEFORE INSERT ON public.capacity_dispatch_abandoned_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.guard_abandoned_dispatch_disposition_insert();

-- +goose StatementBegin
CREATE FUNCTION public.immutable_abandoned_dispatch_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'abandoned dispatch disposition is immutable'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER abandoned_dispatch_disposition_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_abandoned_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.immutable_abandoned_dispatch_disposition();

-- +goose StatementBegin
CREATE FUNCTION public.check_abandoned_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE d public.capacity_dispatch_abandoned_dispositions;
BEGIN
 IF old_row.abandoned_disposition_id IS NOT NULL OR old_row.state='abandoned_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'abandoned disposed dispatch is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'started' OR new_row.state<>'abandoned_disposed' OR new_row.abandoned_disposition_id IS NULL
 OR old_row.started_at IS NULL OR old_row.returned_at IS NOT NULL OR old_row.finalization_ack_at IS NOT NULL
 OR old_row.return_status IS NOT NULL OR old_row.return_error IS NOT NULL OR old_row.finalization_error IS NOT NULL
 OR old_row.lease_owner IS NULL OR old_row.lease_expires_at IS NULL
 OR old_row.lease_expires_at>clock_timestamp()-interval '15 minutes'
 OR (to_jsonb(new_row)-ARRAY['state','updated_at','abandoned_disposition_id'])
    IS DISTINCT FROM (to_jsonb(old_row)-ARRAY['state','updated_at','abandoned_disposition_id'])
 THEN RAISE EXCEPTION 'abandoned disposition requires an unchanged expired started job with no actual return'; END IF;
 SELECT * INTO STRICT d FROM public.capacity_dispatch_abandoned_dispositions WHERE id=new_row.abandoned_disposition_id AND job_id=old_row.id;
 IF d.run_id<>old_row.run_id
 OR d.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(old_row)::text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'abandoned disposition requires same transaction original snapshot'; END IF;
 RETURN new_row;
END; $$;
-- +goose StatementEnd

-- The replacement below is the exact migration76 function with one narrow
-- terminal branch first; every other transition keeps its original guard.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
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
CREATE FUNCTION public.guard_abandoned_dispatch_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='abandoned_disposed' OR NEW.abandoned_disposition_id IS NOT NULL
 THEN RAISE EXCEPTION 'abandoned disposition requires a retained original started job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER abandoned_dispatch_insert BEFORE INSERT ON public.capacity_dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION public.guard_abandoned_dispatch_insert();

-- The original run gets one administrative close (status failed, the fixed
-- error, finished_at = recorded_at). It is not the original return; afterwards
-- the run is immutable, so abort/replay/retry cannot rewrite it.
-- +goose StatementBegin
CREATE FUNCTION public.guard_abandoned_dispatch_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d public.capacity_dispatch_abandoned_dispositions;
BEGIN
 SELECT * INTO d FROM public.capacity_dispatch_abandoned_dispositions WHERE run_id=OLD.id;
 IF NOT FOUND OR NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF OLD.status<>'running' OR OLD.started_at IS DISTINCT FROM d.started_at OR OLD.finished_at IS NOT NULL
 OR OLD.result IS NOT NULL OR OLD.error IS NOT NULL
 OR NEW.status<>d.run_status OR NEW.error IS DISTINCT FROM d.run_error
 OR NEW.finished_at IS DISTINCT FROM d.recorded_at OR NEW.result IS NOT NULL
 OR (to_jsonb(NEW)-ARRAY['status','error','finished_at','updated_at'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','error','finished_at','updated_at'])
 THEN RAISE EXCEPTION 'abandoned disposed original workflow history is immutable'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER abandoned_dispatch_workflow_immutable BEFORE UPDATE ON public.workflow_runs
 FOR EACH ROW EXECUTE FUNCTION public.guard_abandoned_dispatch_workflow();

-- Receipt first, then the job terminal and the run close in the SAME commit.
-- +goose StatementBegin
CREATE FUNCTION public.require_abandoned_dispatch_disposition_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=NEW.run_id;
 IF j.abandoned_disposition_id IS DISTINCT FROM NEW.id OR j.state<>'abandoned_disposed'
 OR j.returned_at IS NOT NULL OR j.finalization_ack_at IS NOT NULL
 OR w.status<>NEW.run_status OR w.error IS DISTINCT FROM NEW.run_error
 OR w.finished_at IS DISTINCT FROM NEW.recorded_at OR w.started_at IS DISTINCT FROM NEW.started_at OR w.result IS NOT NULL
 THEN RAISE EXCEPTION 'abandoned dispatch disposition requires the linked job terminal and run close in the same commit'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER abandoned_dispatch_disposition_complete_links AFTER INSERT ON public.capacity_dispatch_abandoned_dispositions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_abandoned_dispatch_disposition_links();

-- Grants are append/transition-only history. The effect scan above trusts that
-- a grant written after a dispatch start cannot be removed; refuse DELETE.
-- +goose StatementBegin
CREATE FUNCTION public.guard_capacity_mutation_grant_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'capacity mutation grant history cannot be deleted'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_mutation_grant_no_delete BEFORE DELETE ON public.capacity_mutation_grants
 FOR EACH ROW EXECUTE FUNCTION public.guard_capacity_mutation_grant_delete();

-- +goose Down
-- This terminal is a permanent no-replay boundary, including its migration.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'abandoned started dispatch dispositions require retained forward-only schema'; END; $$;
-- +goose StatementEnd
