-- +goose Up
-- This is an administrative pre-start disposition, never a workflow execution,
-- return/acknowledgment, new claim, or native capacity grant. The original
-- envelope, ownership, fence and exact wake history remain on their original job.
ALTER TABLE public.capacity_dispatch_jobs
 ADD COLUMN rejected_at timestamptz,
 ADD COLUMN rejection_reason text,
 ADD COLUMN rejection_issuer text,
 ADD COLUMN superseded_policy_id uuid REFERENCES public.manifests(id),
 ADD COLUMN superseded_policy_checksum text,
 ADD COLUMN superseding_policy_id uuid REFERENCES public.manifests(id),
 ADD COLUMN superseding_policy_checksum text;

-- Name the two replacements explicitly. The original migration used unnamed
-- CHECKs; identify precisely their column sets, rather than guessing generated
-- names or weakening any lease/return/acknowledgment invariant.
-- +goose StatementBegin
DO $$
DECLARE state_attribute smallint; start_attribute smallint; return_attribute smallint; constraint_name text;
BEGIN
 SELECT attnum INTO STRICT state_attribute FROM pg_attribute
 WHERE attrelid='public.capacity_dispatch_jobs'::regclass AND attname='state' AND NOT attisdropped;
 SELECT attnum INTO STRICT start_attribute FROM pg_attribute
 WHERE attrelid='public.capacity_dispatch_jobs'::regclass AND attname='started_at' AND NOT attisdropped;
 SELECT attnum INTO STRICT return_attribute FROM pg_attribute
 WHERE attrelid='public.capacity_dispatch_jobs'::regclass AND attname='returned_at' AND NOT attisdropped;
 SELECT conname INTO STRICT constraint_name FROM pg_constraint
 WHERE conrelid='public.capacity_dispatch_jobs'::regclass AND contype='c'
 AND cardinality(conkey)=1 AND conkey @> ARRAY[state_attribute];
 EXECUTE format('ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT %I',constraint_name);
 SELECT conname INTO STRICT constraint_name FROM pg_constraint
 WHERE conrelid='public.capacity_dispatch_jobs'::regclass AND contype='c'
 AND cardinality(conkey)=3 AND conkey @> ARRAY[state_attribute,start_attribute,return_attribute];
 EXECUTE format('ALTER TABLE public.capacity_dispatch_jobs DROP CONSTRAINT %I',constraint_name);
END; $$;
-- +goose StatementEnd
ALTER TABLE public.capacity_dispatch_jobs
 ADD CONSTRAINT capacity_dispatch_jobs_state_v2_check
 CHECK(state IN('queued','started','unknown','returned','prestart_rejected')),
 ADD CONSTRAINT capacity_dispatch_jobs_lifecycle_v2_check CHECK(
  (state IN('queued','prestart_rejected') AND started_at IS NULL AND returned_at IS NULL)
  OR (state='started' AND started_at IS NOT NULL AND returned_at IS NULL)
  OR (state='unknown' AND started_at IS NOT NULL)
  OR (state='returned' AND started_at IS NOT NULL AND returned_at IS NOT NULL)),
 ADD CONSTRAINT capacity_dispatch_jobs_prestart_rejection_check CHECK(
  (state='prestart_rejected' AND rejected_at IS NOT NULL
   AND rejection_reason IS NOT DISTINCT FROM 'policy_superseded_before_start'
   AND rejection_issuer IS NOT NULL AND rejection_issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND superseded_policy_id IS NOT NULL AND superseding_policy_id IS NOT NULL
   AND superseded_policy_id<>superseding_policy_id
   AND superseded_policy_checksum IS NOT NULL AND superseded_policy_checksum ~ '^[a-f0-9]{64}$'
   AND superseding_policy_checksum IS NOT NULL AND superseding_policy_checksum ~ '^[a-f0-9]{64}$'
   AND started_at IS NULL AND returned_at IS NULL AND return_status IS NULL AND return_error IS NULL
   AND finalization_error IS NULL AND finalization_ack_at IS NULL)
  OR (state<>'prestart_rejected' AND rejected_at IS NULL AND rejection_reason IS NULL AND rejection_issuer IS NULL
   AND superseded_policy_id IS NULL AND superseded_policy_checksum IS NULL
   AND superseding_policy_id IS NULL AND superseding_policy_checksum IS NULL));

-- The existing active-scope/claim indexes already exclude prestart_rejected.
-- Do not broaden them or replace the original start/claim/return/ack guard.
-- +goose StatementBegin
CREATE FUNCTION public.guard_capacity_dispatch_prestart_rejection() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_policy public.manifests; new_policy public.manifests; run public.workflow_runs; e jsonb;
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.state='prestart_rejected' THEN RAISE EXCEPTION 'capacity dispatch rejection requires retained original queued job'; END IF;
  RETURN NEW;
 END IF;
 IF OLD.state='prestart_rejected' THEN
  IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'capacity dispatch prestart rejection is terminal and immutable'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.state<>'prestart_rejected' THEN RETURN NEW; END IF;
 IF OLD.protocol<>'capacity_dispatch_prestart_v1' OR OLD.state<>'queued'
 OR OLD.started_at IS NOT NULL OR OLD.returned_at IS NOT NULL OR OLD.return_status IS NOT NULL
 OR OLD.return_error IS NOT NULL OR OLD.finalization_error IS NOT NULL OR OLD.finalization_ack_at IS NOT NULL
 OR (OLD.lease_expires_at IS NOT NULL AND OLD.lease_expires_at>clock_timestamp())
 OR NEW.rejected_at IS NULL OR NEW.rejected_at<statement_timestamp() OR NEW.rejected_at>clock_timestamp()
 OR NEW.rejection_reason IS DISTINCT FROM 'policy_superseded_before_start'
 OR (to_jsonb(NEW)-ARRAY['state','updated_at','rejected_at','rejection_reason','rejection_issuer','superseded_policy_id',
      'superseded_policy_checksum','superseding_policy_id','superseding_policy_checksum'])
 IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['state','updated_at','rejected_at','rejection_reason','rejection_issuer','superseded_policy_id',
      'superseded_policy_checksum','superseding_policy_id','superseding_policy_checksum'])
 THEN RAISE EXCEPTION 'capacity dispatch rejection requires expired untouched original prestart boundary'; END IF;
 e=OLD.envelope::jsonb;
 IF OLD.envelope_sha256 IS DISTINCT FROM encode(sha256(convert_to(OLD.envelope,'UTF8')),'hex')
 OR e->>'protocol' IS DISTINCT FROM OLD.protocol OR e->>'job_id' IS DISTINCT FROM OLD.id::text
 OR e->>'run_id' IS DISTINCT FROM OLD.run_id::text OR e->>'realm' IS DISTINCT FROM OLD.realm
 OR e->>'environment' IS DISTINCT FROM OLD.environment OR e->>'domain' IS DISTINCT FROM OLD.domain
 OR e->>'dimension' IS DISTINCT FROM OLD.dimension OR e->>'source_tick' IS DISTINCT FROM OLD.source_tick
 THEN RAISE EXCEPTION 'capacity dispatch rejection requires byte-exact original envelope identity'; END IF;
 -- StartPossible takes the job lock first too. Locking the original run closes
 -- a concurrent pending->running race before either side can commit.
 SELECT * INTO STRICT run FROM public.workflow_runs WHERE id=OLD.run_id FOR UPDATE;
 IF run.status<>'pending' OR run.started_at IS NOT NULL OR run.finished_at IS NOT NULL
 OR run.result IS NOT NULL OR run.error IS NOT NULL
 OR run.workflow_namespace IS DISTINCT FROM (e#>>'{workflow,namespace}')
 OR run.workflow_name IS DISTINCT FROM (e#>>'{workflow,name}')
 OR run.workflow_version::text IS DISTINCT FROM (e#>>'{workflow,version}')
 OR (run.workflow_id IS NOT NULL AND run.workflow_id::text IS DISTINCT FROM (e#>>'{workflow,id}'))
 OR run.inputs IS DISTINCT FROM e->'inputs' OR run.metadata IS DISTINCT FROM e->'metadata'
 THEN RAISE EXCEPTION 'capacity dispatch rejection requires untouched original pending workflow'; END IF;
 -- This rare administrative transaction freezes catalog writes too: row locks
 -- alone cannot exclude a concurrent later inactive-version INSERT phantom.
 LOCK TABLE public.manifests IN SHARE MODE;
 SELECT * INTO STRICT old_policy FROM public.manifests WHERE id=NEW.superseded_policy_id FOR SHARE;
 SELECT * INTO STRICT new_policy FROM public.manifests WHERE id=NEW.superseding_policy_id FOR SHARE;
 IF old_policy.kind<>'capacity_policy' OR old_policy.active OR NOT new_policy.active
 OR (new_policy.kind,new_policy.namespace,new_policy.name)
 IS DISTINCT FROM (old_policy.kind,old_policy.namespace,old_policy.name)
 OR old_policy.namespace IS DISTINCT FROM OLD.realm OR new_policy.version<=old_policy.version
 OR old_policy.checksum IS DISTINCT FROM NEW.superseded_policy_checksum
 OR new_policy.checksum IS DISTINCT FROM NEW.superseding_policy_checksum
 OR e->'policy' IS DISTINCT FROM jsonb_build_object('id',old_policy.id::text,'namespace',old_policy.namespace,
      'name',old_policy.name,'version',old_policy.version,'checksum',old_policy.checksum)
 OR EXISTS(SELECT 1 FROM public.manifests later WHERE later.kind=new_policy.kind
      AND later.namespace=new_policy.namespace AND later.name=new_policy.name AND later.version>new_policy.version)
 THEN RAISE EXCEPTION 'capacity dispatch rejection requires exact inactive policy and latest active same identity successor'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_dispatch_prestart_rejection_guard BEFORE INSERT OR UPDATE ON public.capacity_dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION public.guard_capacity_dispatch_prestart_rejection();

-- An append-only original disposition record is created by the same job
-- transition. No deletion path is introduced; UPDATE cannot rewrite the audit.
CREATE TABLE public.capacity_dispatch_prestart_rejections (
 job_id uuid PRIMARY KEY REFERENCES public.capacity_dispatch_jobs(id),
 run_id uuid NOT NULL UNIQUE REFERENCES public.workflow_runs(id),
 envelope_sha256 text NOT NULL CHECK(envelope_sha256 ~ '^[a-f0-9]{64}$'),
 fencing_token bigint NOT NULL CHECK(fencing_token BETWEEN 0 AND 9007199254740991),
 reason text NOT NULL CHECK(reason='policy_superseded_before_start'),
 issuer text NOT NULL CHECK(issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
 recorded_at timestamptz NOT NULL,
 superseded_policy_id uuid NOT NULL REFERENCES public.manifests(id),
 superseded_policy_checksum text NOT NULL CHECK(superseded_policy_checksum ~ '^[a-f0-9]{64}$'),
 superseding_policy_id uuid NOT NULL REFERENCES public.manifests(id),
 superseding_policy_checksum text NOT NULL CHECK(superseding_policy_checksum ~ '^[a-f0-9]{64}$'),
 CHECK(superseded_policy_id<>superseding_policy_id)
);
-- +goose StatementBegin
CREATE FUNCTION public.guard_capacity_dispatch_prestart_rejection_record() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE job public.capacity_dispatch_jobs;
BEGIN
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'capacity dispatch prestart rejection record is immutable'; END IF;
 SELECT * INTO STRICT job FROM public.capacity_dispatch_jobs WHERE id=NEW.job_id;
 IF job.state<>'prestart_rejected'
 OR (NEW.run_id,NEW.envelope_sha256,NEW.fencing_token,NEW.reason,NEW.issuer,NEW.recorded_at,
     NEW.superseded_policy_id,NEW.superseded_policy_checksum,NEW.superseding_policy_id,NEW.superseding_policy_checksum)
 IS DISTINCT FROM
    (job.run_id,job.envelope_sha256,job.fencing_token,job.rejection_reason,job.rejection_issuer,job.rejected_at,
     job.superseded_policy_id,job.superseded_policy_checksum,job.superseding_policy_id,job.superseding_policy_checksum)
 THEN RAISE EXCEPTION 'capacity dispatch rejection record requires exact original terminal job'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_dispatch_prestart_rejection_record_guard BEFORE INSERT OR UPDATE ON public.capacity_dispatch_prestart_rejections
 FOR EACH ROW EXECUTE FUNCTION public.guard_capacity_dispatch_prestart_rejection_record();

-- The workflow cannot be revived or given execution/result markers after the
-- administrative disposition. The only first transition is the exact pending
-- cancellation performed by the job's AFTER trigger below in this transaction.
-- +goose StatementBegin
CREATE FUNCTION public.guard_capacity_dispatch_rejected_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE job public.capacity_dispatch_jobs;
BEGIN
 SELECT * INTO job FROM public.capacity_dispatch_jobs WHERE run_id=OLD.id AND state='prestart_rejected';
 IF NOT FOUND THEN RETURN NEW; END IF;
 IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF OLD.status<>'pending' OR OLD.started_at IS NOT NULL OR OLD.finished_at IS NOT NULL
 OR OLD.result IS NOT NULL OR OLD.error IS NOT NULL OR NEW.status<>'cancelled'
 OR NEW.started_at IS NOT NULL OR NEW.result IS NOT NULL
 OR NEW.finished_at IS DISTINCT FROM job.rejected_at OR NEW.error IS DISTINCT FROM job.rejection_reason
 OR (to_jsonb(NEW)-ARRAY['status','finished_at','error','updated_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','finished_at','error','updated_at'])
 THEN RAISE EXCEPTION 'capacity dispatch rejected workflow cannot start or rewrite original history'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_dispatch_rejected_workflow_guard BEFORE UPDATE ON public.workflow_runs
 FOR EACH ROW EXECUTE FUNCTION public.guard_capacity_dispatch_rejected_workflow();

-- +goose StatementBegin
CREATE FUNCTION public.cancel_capacity_dispatch_rejected_workflow() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE affected integer;
BEGIN
 IF NEW.state='prestart_rejected' AND OLD.state='queued' THEN
  INSERT INTO public.capacity_dispatch_prestart_rejections
   (job_id,run_id,envelope_sha256,fencing_token,reason,issuer,recorded_at,
    superseded_policy_id,superseded_policy_checksum,superseding_policy_id,superseding_policy_checksum)
  VALUES(NEW.id,NEW.run_id,NEW.envelope_sha256,NEW.fencing_token,NEW.rejection_reason,NEW.rejection_issuer,NEW.rejected_at,
    NEW.superseded_policy_id,NEW.superseded_policy_checksum,NEW.superseding_policy_id,NEW.superseding_policy_checksum);
  UPDATE public.workflow_runs SET status='cancelled',finished_at=NEW.rejected_at,
   error=NEW.rejection_reason,updated_at=clock_timestamp()
  WHERE id=NEW.run_id AND status='pending' AND started_at IS NULL AND finished_at IS NULL
   AND result IS NULL AND error IS NULL;
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>1 THEN RAISE EXCEPTION 'capacity dispatch rejection requires atomic original workflow cancellation'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER capacity_dispatch_rejected_workflow_cancel AFTER UPDATE ON public.capacity_dispatch_jobs
 FOR EACH ROW EXECUTE FUNCTION public.cancel_capacity_dispatch_rejected_workflow();

-- +goose Down
-- The terminal disposition is a permanent no-replay boundary. Application
-- rollback must retain its schema and history; removal requires a new reviewed
-- forward migration instead of silently forgetting original rejections.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'capacity dispatch prestart rejections require retained forward-only schema'; END; $$;
-- +goose StatementEnd
