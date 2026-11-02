-- +goose Up
-- An administrative terminal for a started capacity dispatch whose original
-- executor DID return, but whose first finalization write was lost (the
-- process that held the in-memory return is gone) (ADR-0090). It is NOT a
-- return, an acknowledgment, a replay or proof that no provider effect
-- happened: returned_at, return_status, return_error and finalization_ack_at
-- stay NULL forever and the receipt records historical_return='unknown'.
-- Operator evidence of the observed return (for example the PostgreSQL log
-- lines of the cancelled finalization) is retained as opaque text with its
-- SHA-256; Core never parses it as authority.

-- The scan extends the migration83 scan with exactly two tolerated effects,
-- each proved from row data:
--  * the scope's capacity_intents row may have been rewritten once by an
--    unleased hold (counted as pure_assessment_intent_updates): no lease,
--    decision hold without execution permission, written before the original
--    lease expired, and its (generation, fencing_token, phase) equal to the
--    newest intent event, which itself predates the window
--    (intent_events_since_start must be zero), so no phase/fence moved. Other
--    intent fields (failed_installed_disposal, installed_guest_reconcile,
--    floor_degraded, recovery_only) are not compared: no pre-window copy of
--    the intent exists, so the count proves only this predicate (ADR-0090);
--  * resource slots may have been rewritten by pure observation refreshes: an
--    existing (revision >= 2), non-tombstone, non-authority slot whose
--    resource_id column equals its record, whose resource existed before the
--    window (when its creation time is a timestamp), written before the lease
--    expired, with a fresh observed_at inside the window.
-- Every other migration83 counter must stay zero.
-- +goose StatementBegin
CREATE FUNCTION public.finalization_lost_dispatch_effect_scan(scope_realm text,scope_environment text,scope_domain text,scope_dimension text,job uuid,since timestamptz,lease_expires timestamptz)
RETURNS jsonb LANGUAGE sql STABLE AS $$
WITH win AS (
 SELECT since - interval '30 seconds' AS t
), base AS (
 SELECT public.abandoned_started_dispatch_effect_scan(scope_realm,scope_environment,scope_domain,scope_dimension,job,since) AS scan
), last_event AS (
 SELECT e.generation,e.fencing_token,e.phase,e.recorded_at FROM public.capacity_intent_events e
 WHERE e.namespace=scope_realm AND e.environment=scope_environment AND e.domain=scope_domain AND e.dimension=scope_dimension
 ORDER BY e.id DESC LIMIT 1
), it AS (
 SELECT i.intent,i.updated_at FROM public.capacity_intents i
 WHERE i.namespace=scope_realm AND i.environment=scope_environment AND i.domain=scope_domain AND i.dimension=scope_dimension
   AND i.updated_at>=(SELECT t FROM win)
), sl AS (
 SELECT s.resource_id,s.slot_record,s.revision,s.updated_at FROM public.capacity_resource_slots s
 WHERE s.namespace=scope_realm AND s.environment=scope_environment AND s.domain=scope_domain AND s.dimension=scope_dimension
   AND s.updated_at>=(SELECT t FROM win)
)
SELECT (SELECT scan FROM base) || jsonb_build_object(
 'schema','finalization_lost_dispatch_effect_scan_v1',
 'base_schema',(SELECT scan->>'schema' FROM base),
 'pure_assessment_intent_updates',(SELECT count(*) FROM it WHERE
    COALESCE(it.intent->>'lease_owner','')='' AND COALESCE(it.intent->>'lease_executor_id','')=''
    AND COALESCE(jsonb_typeof(it.intent->'lease_expires_at'),'null')='null'
    AND it.intent->'decision'->>'action'='hold'
    AND COALESCE(it.intent->'decision'->>'execution_permitted','false')='false'
    AND it.updated_at<lease_expires
    AND EXISTS(SELECT 1 FROM last_event l WHERE l.recorded_at<(SELECT t FROM win)
      AND l.generation::text=it.intent->>'generation' AND l.fencing_token::text=it.intent->>'fencing_token'
      AND l.phase=it.intent->>'phase')),
 'observation_refresh_slot_updates',(SELECT count(*) FROM sl WHERE
    NOT (sl.slot_record ? 'authority_kind') AND sl.resource_id<>'' AND sl.slot_record->>'resource_id'=sl.resource_id
    AND COALESCE(sl.slot_record->>'tombstone','false')='false' AND sl.revision>=2 AND sl.updated_at<lease_expires
    AND CASE WHEN jsonb_typeof(sl.slot_record->'observed_at')='string' AND sl.slot_record->>'observed_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'
        THEN (sl.slot_record->>'observed_at')::timestamptz>=(SELECT t FROM win)
         AND (sl.slot_record->>'observed_at')::timestamptz<=sl.updated_at+interval '30 seconds'
        ELSE false END
    AND CASE WHEN COALESCE(sl.slot_record->>'resource_created_at','')='' THEN false
        WHEN sl.slot_record->>'resource_created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'
        THEN (sl.slot_record->>'resource_created_at')::timestamptz<(SELECT t FROM win)
        ELSE true END))
$$;
-- +goose StatementEnd

-- The one acceptance rule, shared by the receipt CHECK and the insert guard.
-- +goose StatementBegin
CREATE FUNCTION public.finalization_lost_dispatch_effect_scan_tolerable(scan jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
SELECT jsonb_typeof(scan)='object'
 AND scan->>'schema'='finalization_lost_dispatch_effect_scan_v1'
 AND scan->>'base_schema'='abandoned_started_dispatch_effect_scan_v2'
 AND scan->'clock_skew_margin_seconds'='30'::jsonb
 AND scan->'provider_read_performed'='false'::jsonb
 AND scan->'provider_quiescence_proved'='false'::jsonb
 AND jsonb_typeof(scan->'intents_updated_since_start')='number'
 AND jsonb_typeof(scan->'resource_slots_updated_since_start')='number'
 AND (scan->>'intents_updated_since_start')::numeric<=1
 AND scan->'intents_updated_since_start'=scan->'pure_assessment_intent_updates'
 AND scan->'resource_slots_updated_since_start'=scan->'observation_refresh_slot_updates'
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(scan) e
   WHERE e.key NOT IN('schema','base_schema','clock_skew_margin_seconds','intents_updated_since_start','resource_slots_updated_since_start','pure_assessment_intent_updates','observation_refresh_slot_updates')
     AND e.value NOT IN('0'::jsonb,'false'::jsonb))
$$;
-- +goose StatementEnd

CREATE TABLE public.capacity_dispatch_finalization_lost_dispositions (
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
 reason text NOT NULL CHECK(reason='finalization_lost_started_dispatch_disposed'),
 return_observation text NOT NULL CHECK(return_observation='observed_by_operator_evidence_not_recorded'),
 historical_return text NOT NULL CHECK(historical_return='unknown'),
 run_status text NOT NULL CHECK(run_status='failed'),
 run_error text NOT NULL CHECK(run_error='finalization_lost_disposed: return observed but not recorded; historical outcome unknown'),
 operator_evidence text NOT NULL CHECK(octet_length(operator_evidence) BETWEEN 1 AND 8192 AND position(chr(0) IN operator_evidence)=0),
 operator_evidence_sha256 text NOT NULL CHECK(operator_evidence_sha256=encode(sha256(convert_to(operator_evidence,'UTF8')),'hex')),
 provider_mutation_evidence jsonb NOT NULL CHECK(public.finalization_lost_dispatch_effect_scan_tolerable(provider_mutation_evidence)),
 CHECK(started_at < lease_expires_at),
 CHECK(recorded_at >= lease_expires_at + interval '15 minutes'),
 CHECK(disposing_core_process_started_at > lease_expires_at AND disposing_core_process_started_at <= recorded_at),
 UNIQUE(id,job_id)
);

ALTER TABLE public.capacity_dispatch_jobs ADD COLUMN finalization_lost_disposition_id uuid;
ALTER TABLE public.capacity_dispatch_jobs ADD CONSTRAINT capacity_finalization_lost_matching_job_fk
 FOREIGN KEY(finalization_lost_disposition_id,id) REFERENCES public.capacity_dispatch_finalization_lost_dispositions(id,job_id);
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_state_v6_check;
ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT capacity_dispatch_jobs_lifecycle_v6_check;
-- Only the new terminal is added; every earlier state keeps its exact
-- migration83 lifecycle predicate.
ALTER TABLE public.capacity_dispatch_jobs
 ADD CONSTRAINT capacity_dispatch_jobs_state_v7_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed')),
 ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v7_check CHECK(
  (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
  OR (state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
  OR (state='unknown' AND started_at IS NOT NULL)
  OR (state IN('returned','failed_disposed','native_denied_disposed','enrolled_failed_disposed') AND started_at IS NOT NULL AND returned_at IS NOT NULL)
  OR (state IN('abandoned_disposed','finalization_lost_disposed') AND started_at IS NOT NULL AND returned_at IS NULL)),
 ADD CONSTRAINT capacity_dispatch_jobs_finalization_lost_check CHECK(
  (state='finalization_lost_disposed' AND finalization_lost_disposition_id IS NOT NULL AND abandoned_disposition_id IS NULL
   AND returned_at IS NULL AND return_status IS NULL AND return_error IS NULL AND finalization_ack_at IS NULL)
  OR (state<>'finalization_lost_disposed' AND finalization_lost_disposition_id IS NULL));

-- The receipt is written first, under the same scope advisory lock as Enqueue
-- and the job/run row locks. It re-derives every fact from the locked rows.
-- +goose StatementBegin
CREATE FUNCTION public.guard_finalization_lost_dispatch_disposition_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs; scan jsonb;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 -- Same single lock encoding rule as migration83 (Go json.Marshal vs array_to_json).
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[j.realm,j.environment,j.domain,j.dimension]) n
           WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'finalization-lost dispatch disposition requires a scope name with one lock encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[j.realm,j.environment,j.domain,j.dimension])::text,0));
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id FOR UPDATE;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=j.run_id FOR UPDATE;
 IF j.protocol<>'capacity_dispatch_prestart_v1' OR j.state<>'started' OR j.started_at IS NULL
 OR j.returned_at IS NOT NULL OR j.return_status IS NOT NULL OR j.return_error IS NOT NULL
 OR j.finalization_error IS NOT NULL OR j.finalization_ack_at IS NOT NULL
 OR j.failed_original_disposition_id IS NOT NULL OR j.native_denied_disposition_id IS NOT NULL
 OR j.enrolled_failed_disposition_id IS NOT NULL OR j.abandoned_disposition_id IS NOT NULL
 OR j.finalization_lost_disposition_id IS NOT NULL
 OR j.lease_owner IS NULL OR j.lease_expires_at IS NULL
 OR j.lease_expires_at > clock_timestamp()-interval '15 minutes'
 THEN RAISE EXCEPTION 'finalization-lost dispatch disposition requires an expired started job with no recorded return'; END IF;
 IF (NEW.run_id,NEW.realm,NEW.environment,NEW.domain,NEW.dimension,NEW.envelope_sha256,NEW.fencing_token,
     NEW.lease_owner,NEW.lease_expires_at,NEW.started_at,NEW.pending_wake_count)
 IS DISTINCT FROM
    (j.run_id,j.realm,j.environment,j.domain,j.dimension,j.envelope_sha256,j.fencing_token,
     j.lease_owner,j.lease_expires_at,j.started_at,j.pending_wake_count)
 OR NEW.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex')
 OR NEW.original_run_sha256<>encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex')
 OR NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 THEN RAISE EXCEPTION 'finalization-lost dispatch disposition requires the exact locked original job and run'; END IF;
 IF w.status<>'running' OR w.started_at IS DISTINCT FROM j.started_at OR w.finished_at IS NOT NULL
 OR w.result IS NOT NULL OR w.error IS NOT NULL
 THEN RAISE EXCEPTION 'finalization-lost dispatch disposition requires the original running workflow'; END IF;
 scan=public.finalization_lost_dispatch_effect_scan(j.realm,j.environment,j.domain,j.dimension,j.id,j.started_at,j.lease_expires_at);
 IF NEW.provider_mutation_evidence IS DISTINCT FROM scan OR NOT public.finalization_lost_dispatch_effect_scan_tolerable(scan)
 THEN RAISE EXCEPTION 'finalization-lost dispatch disposition requires only a pure assessment and observation refreshes since start'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER finalization_lost_dispatch_disposition_insert BEFORE INSERT ON public.capacity_dispatch_finalization_lost_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.guard_finalization_lost_dispatch_disposition_insert();

-- +goose StatementBegin
CREATE FUNCTION public.immutable_finalization_lost_dispatch_disposition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'finalization-lost dispatch disposition is immutable'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER finalization_lost_dispatch_disposition_immutable BEFORE UPDATE OR DELETE ON public.capacity_dispatch_finalization_lost_dispositions
 FOR EACH ROW EXECUTE FUNCTION public.immutable_finalization_lost_dispatch_disposition();

-- +goose StatementBegin
CREATE FUNCTION public.check_finalization_lost_dispatch_transition(old_row public.capacity_dispatch_jobs,new_row public.capacity_dispatch_jobs)
RETURNS public.capacity_dispatch_jobs LANGUAGE plpgsql AS $$
DECLARE d public.capacity_dispatch_finalization_lost_dispositions;
BEGIN
 IF old_row.finalization_lost_disposition_id IS NOT NULL OR old_row.state='finalization_lost_disposed' THEN
  IF new_row IS DISTINCT FROM old_row THEN RAISE EXCEPTION 'finalization-lost disposed dispatch is immutable'; END IF;
  RETURN new_row;
 END IF;
 IF old_row.state<>'started' OR new_row.state<>'finalization_lost_disposed' OR new_row.finalization_lost_disposition_id IS NULL
 OR old_row.started_at IS NULL OR old_row.returned_at IS NOT NULL OR old_row.finalization_ack_at IS NOT NULL
 OR old_row.return_status IS NOT NULL OR old_row.return_error IS NOT NULL OR old_row.finalization_error IS NOT NULL
 OR old_row.abandoned_disposition_id IS NOT NULL
 OR old_row.lease_owner IS NULL OR old_row.lease_expires_at IS NULL
 OR old_row.lease_expires_at>clock_timestamp()-interval '15 minutes'
 OR (to_jsonb(new_row)-ARRAY['state','updated_at','finalization_lost_disposition_id'])
    IS DISTINCT FROM (to_jsonb(old_row)-ARRAY['state','updated_at','finalization_lost_disposition_id'])
 THEN RAISE EXCEPTION 'finalization-lost disposition requires an unchanged expired started job with no recorded return'; END IF;
 SELECT * INTO STRICT d FROM public.capacity_dispatch_finalization_lost_dispositions WHERE id=new_row.finalization_lost_disposition_id AND job_id=old_row.id;
 IF d.run_id<>old_row.run_id
 OR d.original_dispatch_sha256<>encode(sha256(convert_to(to_jsonb(old_row)::text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'finalization-lost disposition requires same transaction original snapshot'; END IF;
 RETURN new_row;
END; $$;
-- +goose StatementEnd

-- The replacement below is the exact migration83 function with one narrow
-- terminal branch first; every other transition keeps its original guard.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_capacity_dispatch_job() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
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
CREATE FUNCTION public.guard_finalization_lost_dispatch_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='finalization_lost_disposed' OR NEW.finalization_lost_disposition_id IS NOT NULL
 THEN RAISE EXCEPTION 'finalization-lost disposition requires a retained original started job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER finalization_lost_dispatch_insert BEFORE INSERT ON public.capacity_dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION public.guard_finalization_lost_dispatch_insert();

-- The original run gets one administrative close (status failed, the fixed
-- error, finished_at = recorded_at). It is not the original return; afterwards
-- the run is immutable, so abort/replay/retry cannot rewrite it.
-- +goose StatementBegin
CREATE FUNCTION public.guard_finalization_lost_dispatch_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d public.capacity_dispatch_finalization_lost_dispositions;
BEGIN
 SELECT * INTO d FROM public.capacity_dispatch_finalization_lost_dispositions WHERE run_id=OLD.id;
 IF NOT FOUND OR NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF OLD.status<>'running' OR OLD.started_at IS DISTINCT FROM d.started_at OR OLD.finished_at IS NOT NULL
 OR OLD.result IS NOT NULL OR OLD.error IS NOT NULL
 OR NEW.status<>d.run_status OR NEW.error IS DISTINCT FROM d.run_error
 OR NEW.finished_at IS DISTINCT FROM d.recorded_at OR NEW.result IS NOT NULL
 OR (to_jsonb(NEW)-ARRAY['status','error','finished_at','updated_at'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','error','finished_at','updated_at'])
 THEN RAISE EXCEPTION 'finalization-lost disposed original workflow history is immutable'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER finalization_lost_dispatch_workflow_immutable BEFORE UPDATE ON public.workflow_runs
 FOR EACH ROW EXECUTE FUNCTION public.guard_finalization_lost_dispatch_workflow();

-- Receipt first, then the job terminal and the run close in the SAME commit.
-- +goose StatementBegin
CREATE FUNCTION public.require_finalization_lost_dispatch_disposition_links() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j public.capacity_dispatch_jobs; w public.workflow_runs;
BEGIN
 SELECT * INTO STRICT j FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=NEW.run_id;
 IF j.finalization_lost_disposition_id IS DISTINCT FROM NEW.id OR j.state<>'finalization_lost_disposed'
 OR j.returned_at IS NOT NULL OR j.finalization_ack_at IS NOT NULL
 OR w.status<>NEW.run_status OR w.error IS DISTINCT FROM NEW.run_error
 OR w.finished_at IS DISTINCT FROM NEW.recorded_at OR w.started_at IS DISTINCT FROM NEW.started_at OR w.result IS NOT NULL
 THEN RAISE EXCEPTION 'finalization-lost dispatch disposition requires the linked job terminal and run close in the same commit'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER finalization_lost_dispatch_disposition_complete_links AFTER INSERT ON public.capacity_dispatch_finalization_lost_dispositions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.require_finalization_lost_dispatch_disposition_links();

-- +goose Down
-- This terminal is a permanent no-replay boundary, including its migration.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'finalization-lost started dispatch dispositions require retained forward-only schema'; END; $$;
-- +goose StatementEnd
