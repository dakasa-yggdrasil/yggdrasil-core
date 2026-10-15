-- +goose Up
-- Original source facts are append-only. This schema grants no native permission.
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_roots (
    scope_root_id uuid PRIMARY KEY,
    factory_realm_id uuid NOT NULL UNIQUE,
    factory_attempt_id uuid NOT NULL UNIQUE,
    creator_owner_id uuid NOT NULL UNIQUE,
    factory_registry_class text NOT NULL CHECK (factory_registry_class='original_source_owned_factory'),
    root_key_sha256 text NOT NULL UNIQUE CHECK (root_key_sha256 ~ '^[0-9a-f]{64}$'),
    source_approval_sha256 text NOT NULL CHECK (source_approval_sha256 ~ '^[0-9a-f]{64}$'),
    source_approval_wire bytea NOT NULL CHECK (octet_length(source_approval_wire) BETWEEN 1 AND 65536),
    root_preparation_sha256 text NOT NULL UNIQUE CHECK (root_preparation_sha256 ~ '^[0-9a-f]{64}$'),
    root_preparation_wire bytea NOT NULL CHECK (octet_length(root_preparation_wire) BETWEEN 1 AND 65536),
    original_started_at timestamptz NOT NULL,
    original_deadline timestamptz NOT NULL CHECK (original_deadline > original_started_at),
    root_device numeric(20,0) NOT NULL CHECK (root_device > 0),
    root_inode numeric(20,0) NOT NULL CHECK (root_inode > 0),
    source_closure_sha256 text NOT NULL CHECK (source_closure_sha256 ~ '^[0-9a-f]{64}$'),
    UNIQUE (root_device,root_inode,source_closure_sha256),
    UNIQUE (scope_root_id,factory_realm_id),
    UNIQUE (scope_root_id,factory_attempt_id,creator_owner_id)
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_stable_targets (
    stable_target_sha256 text PRIMARY KEY CHECK (stable_target_sha256 ~ '^[0-9a-f]{64}$'),
    target_wire bytea NOT NULL UNIQUE CHECK (octet_length(target_wire) BETWEEN 1 AND 65536),
    root_id uuid NOT NULL REFERENCES public.capacity_host_factory_roots(scope_root_id) ON DELETE RESTRICT,
    namespace text NOT NULL, environment text NOT NULL, domain text NOT NULL, dimension text NOT NULL,
    target_identity text NOT NULL, mutation_binding_name text NOT NULL, slot integer NOT NULL CHECK (slot BETWEEN 1 AND 64),
    factory_class text NOT NULL CHECK (factory_class='original_source_owned_factory'),
    integration_instance_id uuid NOT NULL,
    integration_type_id uuid NOT NULL,
    integration_checksum text NOT NULL CHECK (integration_checksum ~ '^[0-9a-f]{64}$'),
    integration_type_checksum text NOT NULL CHECK (integration_type_checksum ~ '^[0-9a-f]{64}$'),
    scope_checksum text NOT NULL CHECK (scope_checksum ~ '^[0-9a-f]{64}$'),
    profile_name text NOT NULL,
    factory_attempt_id uuid NOT NULL,
    original_owner_id uuid NOT NULL,
    entry_class text NOT NULL CHECK (entry_class IN ('sealed_a0','sealed_a1','ordinary_original_create')),
    UNIQUE(namespace,environment,domain,dimension,target_identity,mutation_binding_name,slot,factory_class),
    UNIQUE(root_id,factory_attempt_id,original_owner_id),
    UNIQUE(root_id,factory_attempt_id,original_owner_id,stable_target_sha256),
    FOREIGN KEY(root_id,factory_attempt_id,original_owner_id)
        REFERENCES public.capacity_host_factory_roots(scope_root_id,factory_attempt_id,creator_owner_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_owners (
    owner_id uuid PRIMARY KEY,
    root_id uuid NOT NULL REFERENCES public.capacity_host_factory_roots(scope_root_id) ON DELETE RESTRICT,
    attempt_id uuid NOT NULL,
    stable_target_sha256 text NOT NULL UNIQUE REFERENCES public.capacity_host_factory_stable_targets(stable_target_sha256) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN ('awaiting_native_preparation','registered')),
    awaiting_sha256 text NOT NULL CHECK (awaiting_sha256 ~ '^[0-9a-f]{64}$'),
    awaiting_wire bytea NOT NULL CHECK (octet_length(awaiting_wire) BETWEEN 1 AND 65536),
    prepared_handle_id uuid UNIQUE,
    worker_primitive_sha256 text UNIQUE CHECK (worker_primitive_sha256 ~ '^[0-9a-f]{64}$'),
    prepared_plan_sha256 text UNIQUE CHECK (prepared_plan_sha256 ~ '^[0-9a-f]{64}$'),
    prepared_plan_wire bytea CHECK (octet_length(prepared_plan_wire) BETWEEN 1 AND 65536),
    native_registration_wire bytea CHECK (octet_length(native_registration_wire) BETWEEN 1 AND 65536),
    UNIQUE(root_id,attempt_id),
    UNIQUE(root_id,attempt_id,owner_id),
    UNIQUE(root_id,attempt_id,owner_id,stable_target_sha256),
    UNIQUE(root_id,attempt_id,owner_id,prepared_handle_id,stable_target_sha256),
    UNIQUE(owner_id,prepared_handle_id),
    FOREIGN KEY(root_id,attempt_id,owner_id,stable_target_sha256)
        REFERENCES public.capacity_host_factory_stable_targets(root_id,factory_attempt_id,original_owner_id,stable_target_sha256) ON DELETE RESTRICT,
    CHECK ((state='awaiting_native_preparation' AND prepared_handle_id IS NULL AND worker_primitive_sha256 IS NULL AND prepared_plan_sha256 IS NULL AND prepared_plan_wire IS NULL AND native_registration_wire IS NULL) OR
           (state='registered' AND prepared_handle_id IS NOT NULL AND worker_primitive_sha256 IS NOT NULL AND prepared_plan_sha256 IS NOT NULL AND prepared_plan_wire IS NOT NULL AND native_registration_wire IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_scopes (
    scope_sha256 text PRIMARY KEY CHECK (scope_sha256 ~ '^[0-9a-f]{64}$'),
    root_id uuid NOT NULL REFERENCES public.capacity_host_factory_roots(scope_root_id) ON DELETE RESTRICT,
    attempt_id uuid NOT NULL, owner_id uuid NOT NULL,
    stable_target_sha256 text NOT NULL UNIQUE REFERENCES public.capacity_host_factory_stable_targets(stable_target_sha256) ON DELETE RESTRICT,
    binding_schema text NOT NULL CHECK (binding_schema IN ('original_host_factory_pre_authority_scope_v4','factory_ordinary_source_binding_v4')),
    original_wire bytea NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 65536),
    UNIQUE(root_id,attempt_id,owner_id),
    FOREIGN KEY(root_id,attempt_id,owner_id,stable_target_sha256)
        REFERENCES public.capacity_host_factory_owners(root_id,attempt_id,owner_id,stable_target_sha256) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_leases (
    root_id uuid NOT NULL REFERENCES public.capacity_host_factory_roots(scope_root_id) ON DELETE RESTRICT,
    original_invocation_id uuid NOT NULL,
    namespace text NOT NULL, environment text NOT NULL, domain text NOT NULL, dimension text NOT NULL,
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    fence bigint NOT NULL CHECK (fence BETWEEN 1 AND 9007199254740991),
    original_intent_sha256 text NOT NULL UNIQUE CHECK (original_intent_sha256 ~ '^[0-9a-f]{64}$'),
    original_intent_wire bytea NOT NULL CHECK (octet_length(original_intent_wire) BETWEEN 1 AND 65536),
    original_assessment_sha256 text NOT NULL CHECK (original_assessment_sha256 ~ '^[0-9a-f]{64}$'),
    original_assessment_wire bytea NOT NULL CHECK (octet_length(original_assessment_wire) BETWEEN 1 AND 65536),
    initial_empty_sha256 text NOT NULL CHECK (initial_empty_sha256 ~ '^[0-9a-f]{64}$'),
    initial_empty_wire bytea NOT NULL CHECK (octet_length(initial_empty_wire) BETWEEN 1 AND 65536),
    PRIMARY KEY(root_id,original_invocation_id),
    UNIQUE(namespace,environment,domain,dimension,generation,fence)
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_stage_returns (
    root_id uuid NOT NULL REFERENCES public.capacity_host_factory_roots(scope_root_id) ON DELETE RESTRICT,
    subject_owner_id uuid NOT NULL,
    stage text NOT NULL CHECK (stage IN ('source-approval','basal-owner-core','bootstrap-return-core','root-preparation','basal-owner-registrar','bootstrap-return-registrar','native-leaf-core-by-registrar','native-leaf-registrar-by-core','initial-empty-realm-read','root-completion','ordinary-basal-owner','ordinary-bootstrap-return','ordinary-prepared-create-plan','ordinary-native-leaf-worker','ordinary-guard-read','basal-owner-worker','bootstrap-return-worker','prepared-create-plan','native-leaf-worker','original-start-return','alive-native-read','poststart-empty-realm-read','choice-return','exterior-join','terminal-read','bootstrap-write-registrar','bootstrap-write-worker','ordinary-bootstrap-write','original-lease-provenance','preauthority-scope','alive-registration','issued-attachment','unissued-choice-reservation','issued-choice-reservation','unissued-disposition','issued-disposition')),
    binding_schema text NOT NULL CHECK (binding_schema IN ('original_host_factory_source_approval_v4','original_host_factory_root_preparation_v4','original_host_factory_pre_authority_scope_v4','factory_ordinary_source_binding_v4','original_host_factory_basal_owner_observation_v3')),
    binding_sha256 text NOT NULL CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    signer_role text NOT NULL CHECK (signer_role IN ('host_core_issuer','host_source_approver','host_exterior','host_registrar','host_worker','factory_ordinary_worker','factory_ordinary_guard_reader')),
    raw_body_sha256 text NOT NULL CHECK (raw_body_sha256 ~ '^[0-9a-f]{64}$'),
    raw_body_wire bytea NOT NULL CHECK (octet_length(raw_body_wire) BETWEEN 1 AND 65536),
    raw_envelope_sha256 text NOT NULL UNIQUE CHECK (raw_envelope_sha256 ~ '^[0-9a-f]{64}$'),
    raw_envelope_wire bytea NOT NULL CHECK (octet_length(raw_envelope_wire) BETWEEN 1 AND 65536),
    native_phase_wire bytea,
    original_poststart_ledger_wire bytea,
    CHECK ((stage='poststart-empty-realm-read' AND original_poststart_ledger_wire IS NOT NULL
            AND octet_length(original_poststart_ledger_wire) BETWEEN 1 AND 65536
            AND jsonb_typeof(convert_from(original_poststart_ledger_wire,'UTF8')::jsonb)='object') OR
           (stage<>'poststart-empty-realm-read' AND original_poststart_ledger_wire IS NULL)),
    CHECK ((stage IN ('original-start-return','alive-native-read','exterior-join','terminal-read','native-leaf-core-by-registrar','native-leaf-registrar-by-core','native-leaf-worker','ordinary-native-leaf-worker','initial-empty-realm-read','poststart-empty-realm-read') AND native_phase_wire IS NOT NULL AND octet_length(native_phase_wire) BETWEEN 1 AND 65536 AND jsonb_typeof(convert_from(native_phase_wire,'UTF8')::jsonb)='object') OR
           (stage NOT IN ('original-start-return','alive-native-read','exterior-join','terminal-read','native-leaf-core-by-registrar','native-leaf-registrar-by-core','native-leaf-worker','ordinary-native-leaf-worker','initial-empty-realm-read','poststart-empty-realm-read') AND native_phase_wire IS NULL)),
    PRIMARY KEY(root_id,subject_owner_id,stage)
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_registrations (
    scope_sha256 text PRIMARY KEY REFERENCES public.capacity_host_factory_scopes(scope_sha256) ON DELETE RESTRICT,
    owner_id uuid NOT NULL REFERENCES public.capacity_host_factory_owners(owner_id) ON DELETE RESTRICT,
    prepared_handle_id uuid NOT NULL,
    registration_sha256 text NOT NULL UNIQUE CHECK (registration_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire bytea NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 65536),
    UNIQUE(owner_id,prepared_handle_id),
    FOREIGN KEY(owner_id,prepared_handle_id) REFERENCES public.capacity_host_factory_owners(owner_id,prepared_handle_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS public.capacity_factory_original_grant_bindings (
    grant_id uuid PRIMARY KEY REFERENCES public.capacity_mutation_grants(id) ON DELETE RESTRICT,
    preregistration_id uuid NOT NULL UNIQUE REFERENCES public.capacity_vm_provisioning_preregistrations(id) ON DELETE RESTRICT,
    root_id uuid NOT NULL REFERENCES public.capacity_host_factory_roots(scope_root_id) ON DELETE RESTRICT,
    attempt_id uuid NOT NULL, owner_id uuid NOT NULL,
    prepared_handle_id uuid NOT NULL,
    stable_target_sha256 text NOT NULL REFERENCES public.capacity_host_factory_stable_targets(stable_target_sha256) ON DELETE RESTRICT,
    entry_class text NOT NULL CHECK (entry_class IN ('sealed_a1','ordinary_original_create')),
    original_grant_sha256 text NOT NULL CHECK (original_grant_sha256 ~ '^[0-9a-f]{64}$'),
    original_grant_wire bytea NOT NULL CHECK (octet_length(original_grant_wire) BETWEEN 1 AND 65536),
    original_preregistration_sha256 text NOT NULL CHECK (original_preregistration_sha256 ~ '^[0-9a-f]{64}$'),
    original_preregistration_wire bytea NOT NULL CHECK (octet_length(original_preregistration_wire) BETWEEN 1 AND 65536),
    original_request_sha256 text NOT NULL CHECK (original_request_sha256 ~ '^[0-9a-f]{64}$'),
    original_grant_expires_at timestamptz NOT NULL,
    original_provisioning_deadline timestamptz NOT NULL,
    CHECK (original_grant_expires_at <= original_provisioning_deadline),
    UNIQUE(root_id,attempt_id,owner_id,prepared_handle_id),
    FOREIGN KEY(root_id,attempt_id,owner_id,prepared_handle_id,stable_target_sha256)
        REFERENCES public.capacity_host_factory_owners(root_id,attempt_id,owner_id,prepared_handle_id,stable_target_sha256) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_issued_attachments (
    grant_id uuid PRIMARY KEY REFERENCES public.capacity_factory_original_grant_bindings(grant_id) ON DELETE RESTRICT,
    preregistration_id uuid NOT NULL UNIQUE REFERENCES public.capacity_vm_provisioning_preregistrations(id) ON DELETE RESTRICT,
    scope_sha256 text NOT NULL UNIQUE REFERENCES public.capacity_host_factory_registrations(scope_sha256) ON DELETE RESTRICT,
    attachment_sha256 text NOT NULL UNIQUE CHECK (attachment_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire bytea NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 65536)
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_sealed_reservations (
    scope_sha256 text PRIMARY KEY REFERENCES public.capacity_host_factory_registrations(scope_sha256) ON DELETE RESTRICT,
    root_id uuid NOT NULL, attempt_id uuid NOT NULL, owner_id uuid NOT NULL,
    reservation_id uuid NOT NULL UNIQUE,
    branch text NOT NULL CHECK (branch IN ('sealed_a0','sealed_a1')),
    reservation_sha256 text NOT NULL UNIQUE CHECK (reservation_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire bytea NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 65536),
    UNIQUE(root_id,attempt_id,owner_id),
    FOREIGN KEY(root_id,attempt_id,owner_id) REFERENCES public.capacity_host_factory_owners(root_id,attempt_id,owner_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_dispositions (
    scope_sha256 text PRIMARY KEY REFERENCES public.capacity_host_factory_sealed_reservations(scope_sha256) ON DELETE RESTRICT,
    root_id uuid NOT NULL, attempt_id uuid NOT NULL, owner_id uuid NOT NULL,
    branch text NOT NULL CHECK (branch IN ('sealed_a0','sealed_a1')),
    disposition_sha256 text NOT NULL UNIQUE CHECK (disposition_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire bytea NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 65536),
    UNIQUE(root_id,attempt_id,owner_id),
    FOREIGN KEY(root_id,attempt_id,owner_id) REFERENCES public.capacity_host_factory_owners(root_id,attempt_id,owner_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_io_returns (
    root_id uuid NOT NULL REFERENCES public.capacity_host_factory_roots(scope_root_id) ON DELETE RESTRICT,
    binding_schema text NOT NULL CHECK (binding_schema IN ('original_host_factory_source_approval_v4','original_host_factory_root_preparation_v4','original_host_factory_pre_authority_scope_v4','factory_ordinary_source_binding_v4','original_host_factory_basal_owner_observation_v3')),
    binding_sha256 text NOT NULL CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    original_owner_id uuid NOT NULL,
    record_kind text NOT NULL CHECK (record_kind IN ('chunk','manifest','handle-inventory','failure-part','native-record','native-manifest')),
    record_identity_sha256 text NOT NULL CHECK (record_identity_sha256 ~ '^[0-9a-f]{64}$'),
    original_handle_id uuid,
    operation text,
    first_ordinal bigint, last_ordinal bigint,
    failure_collection_id uuid, part_ordinal integer,
    previous_part_raw_sha256 text CHECK (previous_part_raw_sha256 ~ '^[0-9a-f]{64}$'),
    -- PROPOSED ONLY: explicit native publication tags, not IO/failure aliases.
    native_factory_root_id uuid,
    native_observation_id uuid,
    native_observation_kind text CHECK (native_observation_kind IN ('process','task_directory','thread_children')),
    native_subject_owner_id uuid,
    native_observer_primitive_sha256 text CHECK (native_observer_primitive_sha256 ~ '^[0-9a-f]{64}$'),
    native_subject_primitive_sha256 text CHECK (native_subject_primitive_sha256 ~ '^[0-9a-f]{64}$'),
    native_collection_id uuid,
    native_census_ordinal integer,
    native_manifest_level integer,
    native_first_ordinal integer,
    native_last_ordinal integer,
    native_observation_count integer,
    -- Original source publication selects exact vector/inventory pairs once.
    -- Private custody only; no latest-handle search or public relation dump.
    native_inventory_relations_wire bytea CHECK (native_inventory_relations_wire IS NULL OR octet_length(native_inventory_relations_wire) BETWEEN 1 AND 65536),
    raw_body_sha256 text NOT NULL CHECK (raw_body_sha256 ~ '^[0-9a-f]{64}$'),
    raw_body_wire bytea NOT NULL CHECK (octet_length(raw_body_wire) BETWEEN 1 AND 65536),
    raw_envelope_sha256 text NOT NULL CHECK (raw_envelope_sha256 ~ '^[0-9a-f]{64}$'),
    raw_envelope_wire bytea NOT NULL CHECK (octet_length(raw_envelope_wire) BETWEEN 1 AND 65536),
    PRIMARY KEY(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256),
    UNIQUE(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,raw_body_sha256),
    UNIQUE(root_id,binding_schema,binding_sha256,original_owner_id,failure_collection_id,part_ordinal),
    FOREIGN KEY(root_id,native_factory_root_id)
        REFERENCES public.capacity_host_factory_roots(scope_root_id,factory_realm_id) ON DELETE RESTRICT,
    CHECK ((record_kind='native-record' AND native_inventory_relations_wire IS NOT NULL AND jsonb_typeof(convert_from(native_inventory_relations_wire,'UTF8')::jsonb)='array' AND jsonb_array_length(convert_from(native_inventory_relations_wire,'UTF8')::jsonb) BETWEEN 1 AND 20) OR (record_kind<>'native-record' AND native_inventory_relations_wire IS NULL)),
    CHECK (((record_kind IN ('chunk','manifest','handle-inventory','failure-part')) AND (native_factory_root_id IS NULL AND native_observation_id IS NULL AND native_observation_kind IS NULL AND native_subject_owner_id IS NULL AND native_observer_primitive_sha256 IS NULL AND native_subject_primitive_sha256 IS NULL AND native_collection_id IS NULL AND native_census_ordinal IS NULL AND native_manifest_level IS NULL AND native_first_ordinal IS NULL AND native_last_ordinal IS NULL AND native_observation_count IS NULL)) OR
           (record_kind='native-record' AND native_factory_root_id IS NOT NULL AND native_observation_id IS NOT NULL AND native_observation_kind IS NOT NULL AND native_subject_owner_id IS NOT NULL AND native_observer_primitive_sha256 IS NOT NULL AND native_subject_primitive_sha256 IS NOT NULL AND original_handle_id IS NULL AND operation IS NULL AND first_ordinal IS NULL AND last_ordinal IS NULL AND failure_collection_id IS NULL AND part_ordinal IS NULL AND previous_part_raw_sha256 IS NULL AND native_manifest_level IS NULL AND native_first_ordinal IS NULL AND native_last_ordinal IS NULL AND native_observation_count IS NULL AND ((native_observation_kind IN ('process','task_directory') AND native_collection_id IS NULL AND native_census_ordinal IS NULL) OR (native_observation_kind='thread_children' AND native_collection_id IS NOT NULL AND native_census_ordinal IS NOT NULL AND native_census_ordinal BETWEEN 1 AND 4096))) OR
           (record_kind='native-manifest' AND native_factory_root_id IS NOT NULL AND native_observation_id IS NULL AND native_observation_kind IS NOT NULL AND native_observation_kind='thread_children' AND native_subject_owner_id IS NULL AND native_observer_primitive_sha256 IS NOT NULL AND native_subject_primitive_sha256 IS NULL AND native_collection_id IS NOT NULL AND native_census_ordinal IS NULL AND native_manifest_level IS NOT NULL AND native_manifest_level BETWEEN 0 AND 3 AND native_first_ordinal IS NOT NULL AND native_last_ordinal IS NOT NULL AND native_observation_count IS NOT NULL AND native_first_ordinal BETWEEN 1 AND 4096 AND native_last_ordinal BETWEEN native_first_ordinal AND 4096 AND native_observation_count=native_last_ordinal-native_first_ordinal+1 AND original_handle_id IS NULL AND operation IS NULL AND first_ordinal IS NULL AND last_ordinal IS NULL AND failure_collection_id IS NULL AND part_ordinal IS NULL AND previous_part_raw_sha256 IS NULL)),
    CHECK (record_kind IN ('native-record','native-manifest') OR ((record_kind IN ('chunk','manifest') AND original_handle_id IS NOT NULL AND operation IS NOT NULL AND first_ordinal IS NOT NULL AND last_ordinal IS NOT NULL AND first_ordinal BETWEEN 1 AND 65536 AND last_ordinal BETWEEN first_ordinal AND 65536 AND failure_collection_id IS NULL AND part_ordinal IS NULL AND previous_part_raw_sha256 IS NULL) OR
           (record_kind='handle-inventory' AND original_handle_id IS NOT NULL AND operation IS NULL AND ((first_ordinal IS NOT NULL AND last_ordinal IS NOT NULL AND first_ordinal=1 AND last_ordinal BETWEEN 1 AND 65536) OR (first_ordinal IS NULL AND last_ordinal IS NULL)) AND failure_collection_id IS NULL AND part_ordinal IS NULL AND previous_part_raw_sha256 IS NULL) OR
           (record_kind='failure-part' AND original_handle_id IS NULL AND operation IS NULL AND first_ordinal IS NULL AND last_ordinal IS NULL AND failure_collection_id IS NOT NULL AND part_ordinal BETWEEN 1 AND 2048 AND ((part_ordinal=1 AND previous_part_raw_sha256 IS NULL) OR (part_ordinal>1 AND previous_part_raw_sha256 IS NOT NULL)))))
);
-- Original publication identity excludes both raw hashes and mutable ranges.
CREATE UNIQUE INDEX IF NOT EXISTS capacity_host_native_observation_original_identity
    ON public.capacity_host_factory_io_returns(root_id,native_observation_id)
    WHERE record_kind='native-record';
CREATE UNIQUE INDEX IF NOT EXISTS capacity_host_native_manifest_original_identity
    ON public.capacity_host_factory_io_returns(root_id,native_collection_id,native_manifest_level,native_first_ordinal)
    WHERE record_kind='native-manifest';
-- Same original collection/level cannot publish overlapping whole ranges under
-- another first ordinal. This is storage serialization, not native approval.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_host_factory_native_manifest_range() RETURNS trigger AS $$
BEGIN
    IF NEW.record_kind='native-manifest' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.root_id::text||':native-manifest:'||NEW.native_collection_id::text||':'||NEW.native_manifest_level::text,0));
        IF EXISTS (SELECT 1 FROM public.capacity_host_factory_io_returns
                   WHERE root_id=NEW.root_id AND record_kind='native-manifest'
                     AND native_collection_id=NEW.native_collection_id
                     AND native_manifest_level=NEW.native_manifest_level
                     AND native_first_ordinal<=NEW.native_last_ordinal
                     AND native_last_ordinal>=NEW.native_first_ordinal) THEN
            RAISE EXCEPTION 'original native manifest range overlap';
        END IF;
    END IF;
    RETURN NEW;
END; $$ LANGUAGE plpgsql;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_host_factory_io_returns'::regclass AND tgname='capacity_host_factory_native_manifest_range') THEN
        CREATE TRIGGER capacity_host_factory_native_manifest_range BEFORE INSERT ON public.capacity_host_factory_io_returns
        FOR EACH ROW EXECUTE FUNCTION public.capacity_host_factory_native_manifest_range();
    END IF;
END $$;
-- +goose StatementEnd
CREATE TABLE IF NOT EXISTS public.capacity_host_factory_call_snapshot_links (
    root_id uuid NOT NULL,
    binding_schema text NOT NULL CHECK (binding_schema IN ('original_host_factory_source_approval_v4','original_host_factory_root_preparation_v4','original_host_factory_pre_authority_scope_v4','factory_ordinary_source_binding_v4','original_host_factory_basal_owner_observation_v3')),
    binding_sha256 text NOT NULL CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    original_owner_id uuid NOT NULL,
    original_handle_id uuid NOT NULL,
    original_call_id text NOT NULL CHECK (original_call_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[1-9][0-9]{0,4}$'),
    version_kind text NOT NULL CHECK (version_kind IN ('first','pending_to_returned')),
    current_chunk_raw_body_sha256 text NOT NULL CHECK (current_chunk_raw_body_sha256 ~ '^[0-9a-f]{64}$'),
    current_fact_index integer NOT NULL CHECK (current_fact_index BETWEEN 0 AND 15),
    predecessor_chunk_raw_body_sha256 text CHECK (predecessor_chunk_raw_body_sha256 ~ '^[0-9a-f]{64}$'),
    predecessor_fact_index integer,
    predecessor_version_kind text,
    original_called_at timestamptz NOT NULL,
    original_operation_deadline timestamptz NOT NULL CHECK (original_operation_deadline > original_called_at),
    original_getdents_wire bytea CHECK (original_getdents_wire IS NULL OR octet_length(original_getdents_wire)<=65536),
    original_getdents_source_audit_wire bytea CHECK (original_getdents_source_audit_wire IS NULL OR octet_length(original_getdents_source_audit_wire) BETWEEN 1 AND 65536),
    original_final_source_audit_wire bytea CHECK (original_final_source_audit_wire IS NULL OR (octet_length(original_final_source_audit_wire) BETWEEN 1 AND 1048576 AND jsonb_typeof(convert_from(original_final_source_audit_wire,'UTF8')::jsonb)='object')),
    CHECK (original_getdents_source_audit_wire IS NULL OR original_getdents_wire IS NOT NULL),
    chunk_kind text NOT NULL DEFAULT 'chunk' CHECK (chunk_kind='chunk'),
    PRIMARY KEY(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind),
    UNIQUE(root_id,binding_schema,binding_sha256,original_owner_id,current_chunk_raw_body_sha256,current_fact_index),
    UNIQUE(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind,current_chunk_raw_body_sha256,current_fact_index),
    FOREIGN KEY(root_id,binding_schema,binding_sha256,original_owner_id,chunk_kind,current_chunk_raw_body_sha256)
        REFERENCES public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,raw_body_sha256) ON DELETE RESTRICT,
    FOREIGN KEY(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,predecessor_version_kind,predecessor_chunk_raw_body_sha256,predecessor_fact_index)
        REFERENCES public.capacity_host_factory_call_snapshot_links(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind,current_chunk_raw_body_sha256,current_fact_index) ON DELETE RESTRICT,
    FOREIGN KEY(root_id,binding_schema,binding_sha256,original_owner_id,chunk_kind,predecessor_chunk_raw_body_sha256)
        REFERENCES public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,raw_body_sha256) ON DELETE RESTRICT,
    CHECK ((version_kind='first' AND predecessor_chunk_raw_body_sha256 IS NULL AND predecessor_fact_index IS NULL AND predecessor_version_kind IS NULL) OR
           (version_kind='pending_to_returned' AND current_fact_index=0 AND predecessor_fact_index=0 AND predecessor_version_kind='first' AND predecessor_chunk_raw_body_sha256 IS NOT NULL AND predecessor_chunk_raw_body_sha256<>current_chunk_raw_body_sha256))
);

-- The final Source bundle is PRIVATE and inserts only with the actual Core
-- held-root Close link. 'returned' is the signed fact state; existing relation
-- kinds remain first|pending_to_returned. SQL shape never supplies approval.
CREATE UNIQUE INDEX IF NOT EXISTS capacity_host_factory_final_source_audit_once
    ON public.capacity_host_factory_call_snapshot_links(root_id)
    WHERE original_final_source_audit_wire IS NOT NULL;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_host_factory_final_source_audit_link_shape() RETURNS trigger AS $$
DECLARE original_fact jsonb; original_root jsonb; original_bundle jsonb; held_ref jsonb; root_approval_sha text; root_preparation_sha text; core_owner uuid; roster_count integer; saved_inventory_count integer;
BEGIN
    IF NEW.original_final_source_audit_wire IS NULL THEN RETURN NEW; END IF;
    original_bundle:=convert_from(NEW.original_final_source_audit_wire,'UTF8')::jsonb;
    held_ref:=original_bundle->'original_parent_held_root_anchor';
    SELECT convert_from(raw_body_wire,'UTF8')::jsonb->'original_calls'->NEW.current_fact_index
      INTO original_fact FROM public.capacity_host_factory_io_returns
      WHERE root_id=NEW.root_id AND binding_schema=NEW.binding_schema AND binding_sha256=NEW.binding_sha256
        AND original_owner_id=NEW.original_owner_id AND record_kind='chunk'
        AND raw_body_sha256=NEW.current_chunk_raw_body_sha256;
    SELECT convert_from(root_preparation_wire,'UTF8')::jsonb,source_approval_sha256,root_preparation_sha256
      INTO original_root,root_approval_sha,root_preparation_sha
      FROM public.capacity_host_factory_roots WHERE scope_root_id=NEW.root_id;
    SELECT subject_owner_id INTO core_owner FROM public.capacity_host_factory_stage_returns
      WHERE root_id=NEW.root_id AND stage='basal-owner-core'
        AND raw_body_sha256=original_root->>'core_basal_owner_raw_sha256';
    SELECT count(*) INTO roster_count FROM jsonb_array_elements_text(COALESCE(original_root->'original_handle_inventory_sh_as','[]'::jsonb)) AS members(sha)
      WHERE members.sha=held_ref->>'original_inventory_body_sha256';
    SELECT count(*) INTO saved_inventory_count FROM public.capacity_host_factory_io_returns
      WHERE root_id=NEW.root_id AND record_kind='handle-inventory'
        AND binding_schema='original_host_factory_source_approval_v4' AND binding_sha256=root_approval_sha
        AND original_owner_id=core_owner AND original_handle_id::text=held_ref->>'original_handle_id'
        AND raw_body_sha256=held_ref->>'original_inventory_body_sha256'
        AND raw_envelope_sha256=held_ref->>'original_inventory_envelope_sha256';
    IF original_fact IS NULL OR original_root IS NULL OR core_owner IS NULL
       OR original_bundle->>'schema' IS DISTINCT FROM 'source_private_original_final_source_audit_custody_v2'
       OR original_bundle->>'logical_scope_root_id' IS DISTINCT FROM NEW.root_id::text
       OR original_bundle->>'source_approval_body_sha256' IS DISTINCT FROM root_approval_sha
       OR original_bundle->>'root_preparation_body_sha256' IS DISTINCT FROM root_preparation_sha
       OR jsonb_typeof(held_ref) IS DISTINCT FROM 'object'
       OR held_ref->>'original_handle_id' IS DISTINCT FROM NEW.original_handle_id::text
       OR held_ref->>'original_handle_id' IS NOT DISTINCT FROM original_root->'root_directory_source'->>'original_handle_id'
       OR held_ref->>'original_acquisition_call_id' IS DISTINCT FROM NEW.original_handle_id::text||':1'
       OR held_ref->>'original_fstat_call_id' IS DISTINCT FROM NEW.original_handle_id::text||':2'
       OR roster_count<>1 OR saved_inventory_count<>1
       OR original_fact->>'original_state' IS DISTINCT FROM 'returned'
       OR original_fact->>'operation' IS DISTINCT FROM 'root_directory_close'
       OR original_fact->>'original_call_id' IS DISTINCT FROM NEW.original_call_id
       OR split_part(NEW.original_call_id,':',2)::bigint<=4
       OR original_fact->>'original_handle_id' IS DISTINCT FROM NEW.original_handle_id::text
       OR NEW.original_owner_id<>core_owner
       OR original_fact->>'subject_owner_id' IS DISTINCT FROM core_owner::text
       OR original_fact->>'owner_primitive_raw_sha256' IS DISTINCT FROM original_root->>'core_basal_owner_raw_sha256'
       OR original_fact->'original_native_return'->>'kind' IS DISTINCT FROM 'original_file_close'
       OR original_fact->'original_native_return'->>'original_error_present' IS DISTINCT FROM 'false'
       OR NEW.binding_schema<>'original_host_factory_source_approval_v4' OR NEW.binding_sha256<>root_approval_sha THEN
        RAISE EXCEPTION 'final Source audit custody requires exact original Core held-root returned Close';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_host_factory_call_snapshot_links'::regclass AND tgname='capacity_host_factory_final_source_audit_link_shape') THEN
        CREATE TRIGGER capacity_host_factory_final_source_audit_link_shape BEFORE INSERT ON public.capacity_host_factory_call_snapshot_links
            FOR EACH ROW EXECUTE FUNCTION public.capacity_host_factory_final_source_audit_link_shape();
    END IF;
END $$;
-- +goose StatementEnd


-- Native original getdents bytes join the exact returned call BEFORE INSERT.
-- This checks SQL shape/count, not native/Source authority or a fresh read.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_host_factory_getdents_link_shape() RETURNS trigger AS $$
DECLARE original_fact jsonb;
BEGIN
    SELECT convert_from(raw_body_wire,'UTF8')::jsonb->'original_calls'->NEW.current_fact_index
      INTO original_fact FROM public.capacity_host_factory_io_returns
      WHERE root_id=NEW.root_id AND binding_schema=NEW.binding_schema AND binding_sha256=NEW.binding_sha256
        AND original_owner_id=NEW.original_owner_id AND record_kind='chunk'
        AND raw_body_sha256=NEW.current_chunk_raw_body_sha256;
    IF original_fact IS NULL THEN RAISE EXCEPTION 'original getdents call relation absent'; END IF;
    IF original_fact->>'original_state'='returned'
       AND original_fact->'original_native_return'->>'kind'='unix_getdents64'
       AND original_fact->'original_native_return'->>'original_error_present'='false' THEN
        IF NEW.original_getdents_wire IS NULL
           OR (original_fact->>'original_count') IS NULL
           OR (original_fact->'original_native_return'->>'original_scalar') IS NULL
           OR (original_fact->>'original_eof') IS NULL
           OR octet_length(NEW.original_getdents_wire)<>(original_fact->>'original_count')::bigint
           OR octet_length(NEW.original_getdents_wire)<>(original_fact->'original_native_return'->>'original_scalar')::bigint
           OR original_fact->>'original_eof'<>'false' THEN
            RAISE EXCEPTION 'original getdents returned bytes unknown or inconsistent';
        END IF;
    ELSIF NEW.original_getdents_wire IS NOT NULL OR NEW.original_getdents_source_audit_wire IS NOT NULL THEN
        RAISE EXCEPTION 'private getdents bytes cannot alias another operation/pending/error';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_host_factory_call_snapshot_links'::regclass AND tgname='capacity_host_factory_getdents_link_shape') THEN
        CREATE TRIGGER capacity_host_factory_getdents_link_shape BEFORE INSERT ON public.capacity_host_factory_call_snapshot_links
            FOR EACH ROW EXECUTE FUNCTION public.capacity_host_factory_getdents_link_shape();
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_host_factory_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'original host factory facts are immutable';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
-- Only an owning native preparation can fill the initially absent owner facts
-- once. Original root/attempt/target columns remain identical.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_host_factory_owner_once() RETURNS trigger AS $$
BEGIN
    IF TG_OP='UPDATE' AND OLD.state='awaiting_native_preparation' AND NEW.state='registered'
       AND OLD.owner_id=NEW.owner_id AND OLD.root_id=NEW.root_id AND OLD.attempt_id=NEW.attempt_id
       AND OLD.stable_target_sha256=NEW.stable_target_sha256
       AND OLD.awaiting_sha256=NEW.awaiting_sha256 AND OLD.awaiting_wire=NEW.awaiting_wire THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'original host factory owner cannot be replaced';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE n text;
BEGIN
    FOREACH n IN ARRAY ARRAY['capacity_host_factory_roots','capacity_host_factory_stable_targets','capacity_host_factory_scopes','capacity_host_factory_leases','capacity_host_factory_stage_returns','capacity_host_factory_registrations','capacity_factory_original_grant_bindings','capacity_host_factory_issued_attachments','capacity_host_factory_sealed_reservations','capacity_host_factory_dispositions','capacity_host_factory_io_returns','capacity_host_factory_call_snapshot_links'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=('public.'||n)::regclass AND tgname=n||'_immutable') THEN
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.capacity_host_factory_immutable()',n||'_immutable',n);
        END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.capacity_host_factory_owners'::regclass AND tgname='capacity_host_factory_owners_once') THEN
        CREATE TRIGGER capacity_host_factory_owners_once BEFORE UPDATE OR DELETE ON public.capacity_host_factory_owners FOR EACH ROW EXECUTE FUNCTION public.capacity_host_factory_owner_once();
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- Deliberately no destructive reversal of original sticky exclusions.
SELECT 1;
