-- +goose Up
-- ADR-0091: an immutable operator admission that lets the failed-installed
-- replacement gate accept the UNCHANGED blocked binding of one terminal,
-- historical (no replacement_mode) disposal, because the original failure had
-- an external cause and a promoted peer Guest of the very same Guest build in
-- a DIFFERENT dimension later passed an accepted canary read.
--
-- The admission does not rewrite, reopen or reinterpret the disposal: the
-- original failed run, its ACK, canaries and business effects stay as they are.
-- The operator's cause evidence is opaque UTF-8 text (at most 8 KiB) retained
-- with its SHA-256 and never parsed as authority. Every fact the gate relies on
-- is re-derived below from the locked original rows, including the admitted
-- binding digest (the SHA-256 of the disposed Guest's own binding_wire) and
-- the active policy revision of the disposal's scope. The Go admission path
-- additionally proves that this active policy carries exactly that binding
-- (structural equality with the decoded wire) and its compiled approval; the
-- gate re-reads the same wire, so a row can never admit any other binding.
-- One admission per disposal and per disposed preregistration, never updated.
CREATE TABLE public.capacity_guest_failed_installed_external_cause_admissions (
 id uuid PRIMARY KEY,
 schema text NOT NULL CHECK(schema='failed_installed_external_cause_replacement_admission_v1'),
 disposal_id uuid NOT NULL UNIQUE,
 disposal_stage text NOT NULL CHECK(disposal_stage='terminal'),
 preregistration_id uuid NOT NULL UNIQUE REFERENCES public.capacity_vm_provisioning_preregistrations(id),
 namespace text NOT NULL CHECK(length(namespace) BETWEEN 1 AND 64),
 environment text NOT NULL CHECK(length(environment) BETWEEN 1 AND 128),
 domain text NOT NULL CHECK(length(domain) BETWEEN 1 AND 128),
 dimension text NOT NULL CHECK(length(dimension) BETWEEN 1 AND 128),
 blocked_guest_source text NOT NULL CHECK(blocked_guest_source ~ '^[0-9a-f]{40}$'),
 blocked_profile_sha256 text NOT NULL CHECK(blocked_profile_sha256 ~ '^[0-9a-f]{64}$'),
 admitted_binding_sha256 text NOT NULL CHECK(admitted_binding_sha256 ~ '^[0-9a-f]{64}$'),
 admitted_policy_id uuid NOT NULL REFERENCES public.manifests(id),
 admitted_policy_checksum text NOT NULL CHECK(length(admitted_policy_checksum) BETWEEN 1 AND 256),
 original_failed_run_id uuid NOT NULL REFERENCES public.workflow_runs(id),
 original_failed_run_finished_at timestamptz NOT NULL,
 peer_preregistration_id uuid NOT NULL REFERENCES public.capacity_vm_original_enrollments(preregistration_id),
 peer_namespace text NOT NULL CHECK(length(peer_namespace) BETWEEN 1 AND 64),
 peer_environment text NOT NULL CHECK(length(peer_environment) BETWEEN 1 AND 128),
 peer_domain text NOT NULL CHECK(length(peer_domain) BETWEEN 1 AND 128),
 peer_dimension text NOT NULL CHECK(length(peer_dimension) BETWEEN 1 AND 128),
 peer_guest_source text NOT NULL CHECK(peer_guest_source ~ '^[0-9a-f]{40}$'),
 peer_profile_sha256 text NOT NULL CHECK(peer_profile_sha256 ~ '^[0-9a-f]{64}$'),
 peer_read_challenge_id uuid NOT NULL UNIQUE REFERENCES public.capacity_guest_notify_canary_challenges(id),
 peer_read_recorded_at timestamptz NOT NULL,
 peer_read_return_recorded_at timestamptz NOT NULL,
 peer_intent_generation bigint NOT NULL CHECK(peer_intent_generation BETWEEN 1 AND 9007199254740991),
 peer_intent_fencing_token bigint NOT NULL CHECK(peer_intent_fencing_token BETWEEN 1 AND 9007199254740991),
 peer_resource_id text NOT NULL CHECK(length(peer_resource_id) BETWEEN 1 AND 256),
 admitting_core_source text NOT NULL CHECK(admitting_core_source ~ '^([0-9a-f]{40})?$'),
 issuer text NOT NULL CHECK(issuer ~ '^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
 reason text NOT NULL CHECK(reason='external_cause_same_build_replacement'),
 -- PostgreSQL text can never hold NUL (and chr(0) itself raises 54000, so it
 -- cannot appear in a CHECK); the remaining controls the Go validator refuses
 -- (everything below 0x20 except tab, LF and CR, plus DEL) are refused here.
 cause_evidence text NOT NULL CHECK(octet_length(cause_evidence) BETWEEN 1 AND 8192
  AND cause_evidence !~ '[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]'),
 cause_evidence_sha256 text NOT NULL CHECK(cause_evidence_sha256=encode(sha256(convert_to(cause_evidence,'UTF8')),'hex')),
 original_failure_preserved boolean NOT NULL CHECK(original_failure_preserved),
 original_failure_cause_claimed_by_core boolean NOT NULL CHECK(NOT original_failure_cause_claimed_by_core),
 recorded_at timestamptz NOT NULL,
 FOREIGN KEY(disposal_id,disposal_stage) REFERENCES public.capacity_guest_failed_installed_disposals(id,stage),
 CHECK(peer_preregistration_id<>preregistration_id),
 CHECK((peer_namespace,peer_environment,peer_domain,peer_dimension) IS DISTINCT FROM (namespace,environment,domain,dimension)),
 CHECK(peer_guest_source=blocked_guest_source),
 CHECK(peer_read_recorded_at>original_failed_run_finished_at AND peer_read_return_recorded_at>original_failed_run_finished_at),
 CHECK(recorded_at>peer_read_return_recorded_at)
);

-- The admission is written under the disposal scope advisory lock (the same
-- key Go's lockMutationScope takes) and re-derives every row fact it records.
-- +goose StatementBegin
CREATE FUNCTION public.guard_failed_installed_external_cause_admission_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE req public.capacity_guest_failed_installed_disposals;
        term public.capacity_guest_failed_installed_disposals;
        w public.workflow_runs;
        old_pre public.capacity_vm_provisioning_preregistrations;
        peer_pre public.capacity_vm_provisioning_preregistrations;
        g public.capacity_mutation_grants;
        c public.capacity_guest_notify_canary_challenges;
        x public.capacity_guest_notify_canary_returns;
BEGIN
 -- Same single lock encoding rule as migrations 83/84 (Go json.Marshal vs array_to_json).
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension]) n
           WHERE n IS NULL OR n !~ '^[ -~]+$' OR n ~ '[<>&]')
 THEN RAISE EXCEPTION 'external-cause replacement admission requires a scope name with one lock encoding'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(array_to_json(ARRAY[NEW.namespace,NEW.environment,NEW.domain,NEW.dimension])::text,0));

 SELECT * INTO STRICT req FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.disposal_id AND stage='requested' FOR SHARE;
 SELECT * INTO STRICT term FROM public.capacity_guest_failed_installed_disposals WHERE id=NEW.disposal_id AND stage='terminal' FOR SHARE;
 IF req.preregistration_id<>NEW.preregistration_id OR term.preregistration_id<>NEW.preregistration_id
 OR (req.namespace,req.environment,req.domain,req.dimension) IS DISTINCT FROM (NEW.namespace,NEW.environment,NEW.domain,NEW.dimension)
 OR (term.namespace,term.environment,term.domain,term.dimension) IS DISTINCT FROM (NEW.namespace,NEW.environment,NEW.domain,NEW.dimension)
 OR req.original_record ? 'replacement_mode' OR term.original_record ? 'replacement_mode'
 OR req.original_record->>'blocked_guest_source' IS DISTINCT FROM NEW.blocked_guest_source
 OR term.original_record->>'blocked_guest_source' IS DISTINCT FROM NEW.blocked_guest_source
 OR req.original_record->>'blocked_profile_sha256' IS DISTINCT FROM NEW.blocked_profile_sha256
 OR term.original_record->>'blocked_profile_sha256' IS DISTINCT FROM NEW.blocked_profile_sha256
 THEN RAISE EXCEPTION 'external-cause replacement admission requires one terminal historical disposal without a replacement mode'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.capacity_intents i
   WHERE i.namespace=NEW.namespace AND i.environment=NEW.environment AND i.domain=NEW.domain AND i.dimension=NEW.dimension
     AND i.intent->'failed_installed_disposal'->>'id'=NEW.disposal_id::text
     AND i.intent->'failed_installed_disposal'->>'stage'='terminal')
 THEN RAISE EXCEPTION 'external-cause replacement admission requires the current intent to still name the terminal disposal'; END IF;

 SELECT * INTO STRICT w FROM public.workflow_runs WHERE id=NEW.original_failed_run_id;
 IF (req.original_record->>'original_run')::jsonb->>'id' IS DISTINCT FROM NEW.original_failed_run_id::text
 OR w.status<>'failed' OR w.finished_at IS NULL OR w.finished_at IS DISTINCT FROM NEW.original_failed_run_finished_at
 THEN RAISE EXCEPTION 'external-cause replacement admission requires the disposal''s own original failed run'; END IF;

 SELECT * INTO STRICT old_pre FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.preregistration_id;
 IF old_pre.binding_wire IS NULL
 OR convert_from(old_pre.binding_wire,'UTF8')::jsonb->>'guest_source_commit' IS DISTINCT FROM NEW.blocked_guest_source
 OR old_pre.profile_manifest_sha256 IS DISTINCT FROM NEW.blocked_profile_sha256
 OR NEW.admitted_binding_sha256 IS DISTINCT FROM encode(sha256(old_pre.binding_wire),'hex')
 THEN RAISE EXCEPTION 'external-cause replacement admission requires the disposed Guest''s own blocked build'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.manifests m
   WHERE m.id=NEW.admitted_policy_id AND m.kind='capacity_policy' AND m.active AND m.checksum=NEW.admitted_policy_checksum
     AND m.namespace=NEW.namespace AND m.spec->>'environment'=NEW.environment AND m.spec->>'domain'=NEW.domain AND m.spec->>'dimension'=NEW.dimension
     AND NOT EXISTS(SELECT 1 FROM public.manifests o WHERE o.kind='capacity_policy' AND o.active AND o.namespace=m.namespace AND o.name=m.name AND o.id<>m.id))
 THEN RAISE EXCEPTION 'external-cause replacement admission requires the single active policy revision of the disposal''s scope'; END IF;

 SELECT * INTO STRICT peer_pre FROM public.capacity_vm_provisioning_preregistrations WHERE id=NEW.peer_preregistration_id;
 SELECT * INTO STRICT g FROM public.capacity_mutation_grants WHERE id=peer_pre.create_grant_id;
 IF (g.namespace,g.environment,g.domain,g.dimension) IS DISTINCT FROM (NEW.peer_namespace,NEW.peer_environment,NEW.peer_domain,NEW.peer_dimension)
 OR peer_pre.binding_wire IS NULL
 OR convert_from(peer_pre.binding_wire,'UTF8')::jsonb->>'guest_source_commit' IS DISTINCT FROM NEW.peer_guest_source
 OR peer_pre.profile_manifest_sha256 IS DISTINCT FROM NEW.peer_profile_sha256
 THEN RAISE EXCEPTION 'external-cause replacement admission requires the peer''s own scope and Guest build'; END IF;

 SELECT * INTO STRICT c FROM public.capacity_guest_notify_canary_challenges WHERE id=NEW.peer_read_challenge_id;
 SELECT * INTO STRICT x FROM public.capacity_guest_notify_canary_returns WHERE challenge_id=c.id;
 IF c.preregistration_id<>NEW.peer_preregistration_id OR c.phase<>'read' OR x.outcome<>'accepted'
 OR c.recorded_at IS DISTINCT FROM NEW.peer_read_recorded_at OR x.recorded_at IS DISTINCT FROM NEW.peer_read_return_recorded_at
 OR c.recorded_at<=w.finished_at OR x.recorded_at<=w.finished_at
 THEN RAISE EXCEPTION 'external-cause replacement admission requires an accepted peer canary read after the original failure'; END IF;

 IF NOT EXISTS(SELECT 1 FROM public.capacity_intents i
   WHERE i.namespace=NEW.peer_namespace AND i.environment=NEW.peer_environment AND i.domain=NEW.peer_domain AND i.dimension=NEW.peer_dimension
     AND i.intent->>'phase'='promoted' AND i.intent->'failed_installed_disposal' IS NULL
     AND i.intent->>'generation'=NEW.peer_intent_generation::text AND i.intent->>'fencing_token'=NEW.peer_intent_fencing_token::text)
 OR NOT EXISTS(SELECT 1 FROM public.capacity_resource_slots s
   WHERE s.namespace=NEW.peer_namespace AND s.environment=NEW.peer_environment AND s.domain=NEW.peer_domain AND s.dimension=NEW.peer_dimension
     AND s.resource_id=NEW.peer_resource_id AND s.slot_record->>'resource_id'=NEW.peer_resource_id
     AND COALESCE(s.slot_record->>'tombstone','false')='false')
 OR EXISTS(SELECT 1 FROM public.capacity_vm_retirement_intents r WHERE r.preregistration_id=NEW.peer_preregistration_id)
 OR EXISTS(SELECT 1 FROM public.capacity_guest_failed_installed_disposals d WHERE d.preregistration_id=NEW.peer_preregistration_id)
 THEN RAISE EXCEPTION 'external-cause replacement admission requires the peer to be a current member of a promoted intent'; END IF;

 IF NEW.recorded_at<transaction_timestamp() OR NEW.recorded_at>clock_timestamp()
 THEN RAISE EXCEPTION 'external-cause replacement admission requires a server-side recording time'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_installed_external_cause_admission_insert BEFORE INSERT ON public.capacity_guest_failed_installed_external_cause_admissions
 FOR EACH ROW EXECUTE FUNCTION public.guard_failed_installed_external_cause_admission_insert();

-- +goose StatementBegin
CREATE FUNCTION public.immutable_failed_installed_external_cause_admission() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'external-cause replacement admission is immutable'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER failed_installed_external_cause_admission_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_failed_installed_external_cause_admissions
 FOR EACH ROW EXECUTE FUNCTION public.immutable_failed_installed_external_cause_admission();

-- +goose Down
-- An admission is permanent replacement provenance, including its migration.
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'external-cause replacement admissions require retained forward-only schema'; END; $$;
-- +goose StatementEnd
