-- +goose Up
-- Literal canonical signed bytes remain independent of PostgreSQL's JSONB
-- rendering and native microsecond timestamp representation. No UPDATE,
-- expiration, lease renewal or GET can create another original action.
ALTER TABLE public.capacity_vm_provisioning_preregistrations
    ADD COLUMN IF NOT EXISTS original_wire BYTEA,
    ADD COLUMN IF NOT EXISTS binding_wire BYTEA;
ALTER TABLE public.capacity_vm_original_enrollments
    ADD COLUMN IF NOT EXISTS registration_wire BYTEA,
    ADD COLUMN IF NOT EXISTS receipt_wire BYTEA;
ALTER TABLE public.capacity_vm_retirement_intents
    ADD COLUMN IF NOT EXISTS original_wire BYTEA;
ALTER TABLE public.capacity_vm_retirement_original_returns
    ADD COLUMN IF NOT EXISTS original_wire BYTEA;
ALTER TABLE public.capacity_vm_retirement_delete_bindings
    ADD COLUMN IF NOT EXISTS original_wire BYTEA;
ALTER TABLE public.capacity_vm_retirement_native_readbacks
    ADD COLUMN IF NOT EXISTS original_wire BYTEA;

CREATE TABLE IF NOT EXISTS public.capacity_guest_original_create_witnesses (
    preregistration_id UUID PRIMARY KEY REFERENCES public.capacity_vm_provisioning_preregistrations(id),
    original_create_attempt_id UUID NOT NULL UNIQUE,
	resource_tuple_sha256 TEXT NOT NULL UNIQUE CHECK (resource_tuple_sha256 ~ '^[0-9a-f]{64}$'),
    witness_sha256 TEXT NOT NULL UNIQUE CHECK (witness_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 1048576),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_runtime_snapshot_challenges (
    id UUID PRIMARY KEY,
    intent_id UUID NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
    phase TEXT NOT NULL CHECK (phase IN ('before_start','before_poweroff')),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 1),
    challenge_sha256 TEXT NOT NULL UNIQUE CHECK (challenge_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 1048576),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record) = 'object'),
    original_deadline TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE (intent_id, phase, ordinal),
    CHECK (original_deadline = (original_record->>'original_deadline')::timestamptz),
    CHECK (recorded_at = (original_record->>'issued_at')::timestamptz),
    CHECK (original_deadline > recorded_at AND original_deadline <= recorded_at + interval '30 seconds')
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_runtime_snapshot_returns (
    challenge_id UUID PRIMARY KEY REFERENCES public.capacity_guest_runtime_snapshot_challenges(id),
    return_sha256 TEXT NOT NULL UNIQUE CHECK (return_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 1048576),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL
);
-- The original workflow marks possible-send BEFORE its single POST. A lost
-- HTTP result leaves this permanent identity reserved, including after restart.
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_caller_attempts (
    intent_id UUID PRIMARY KEY REFERENCES public.capacity_vm_retirement_intents(id),
    attempt_id UUID NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL UNIQUE CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    principal_id TEXT NOT NULL,
    possible_send_at TIMESTAMPTZ NOT NULL,
    original_deadline TIMESTAMPTZ NOT NULL,
    CHECK (original_deadline > possible_send_at)
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_retirement_contexts (
    intent_id UUID PRIMARY KEY REFERENCES public.capacity_vm_retirement_intents(id),
    executor_id UUID NOT NULL,
    original_step_id TEXT NOT NULL,
    original_step_timeout_seconds INTEGER NOT NULL CHECK (original_step_timeout_seconds BETWEEN 1 AND 86400),
    original_context_deadline TIMESTAMPTZ NOT NULL,
    core_actual_source_commit TEXT NOT NULL CHECK (core_actual_source_commit ~ '^[0-9a-f]{40}$'),
    recorded_at TIMESTAMPTZ NOT NULL,
    CHECK (original_context_deadline > recorded_at)
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_caller_returns (
    intent_id UUID PRIMARY KEY REFERENCES public.capacity_guest_original_caller_attempts(intent_id),
    return_sha256 TEXT NOT NULL UNIQUE CHECK (return_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 1048576),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_authority_reads (
    id UUID PRIMARY KEY,
    intent_id UUID NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
    phase TEXT NOT NULL CHECK (phase IN ('before_start','before_poweroff')),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 4),
    original_deadline TIMESTAMPTZ NOT NULL,
    possible_read_at TIMESTAMPTZ NOT NULL,
    UNIQUE (intent_id, phase, ordinal),
    CHECK (original_deadline > possible_read_at)
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_authority_returns (
    read_id UUID PRIMARY KEY REFERENCES public.capacity_guest_original_authority_reads(id),
    authority_sha256 TEXT NOT NULL UNIQUE CHECK (authority_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 1048576),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_native_poweroff_reads (
    id UUID PRIMARY KEY,
    intent_id UUID NOT NULL REFERENCES public.capacity_vm_retirement_intents(id),
    observation_sha256 TEXT NOT NULL CHECK (observation_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 1048576),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record) = 'object'),
    original_native_join_wire BYTEA,
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE(intent_id, observation_sha256)
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_original_authority_transport_returns (
    read_id UUID NOT NULL REFERENCES public.capacity_guest_original_authority_reads(id),
    native_stage TEXT NOT NULL CHECK (native_stage IN ('snapshot','journal')),
    return_sha256 TEXT NOT NULL CHECK (return_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 8192),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record)='object'),
    original_reply_wire BYTEA CHECK (octet_length(original_reply_wire) BETWEEN 1 AND 1048576),
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (read_id,native_stage)
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_qualification_probe_challenges (
    challenge_id UUID PRIMARY KEY,
    preregistration_id UUID NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id),
    challenge_sha256 TEXT NOT NULL UNIQUE CHECK (challenge_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 16384),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record)='object'),
    usage_class TEXT NOT NULL DEFAULT 'capacity_phase' CHECK (usage_class IN ('capacity_phase','diagnostic_only')),
    original_deadline TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS public.capacity_guest_qualification_native_source_returns (
    id UUID PRIMARY KEY,
    preregistration_id UUID NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id),
    native_stage TEXT NOT NULL CHECK (native_stage IN ('native_read','serving_probe','source_refusal','diagnostic_serving_probe','diagnostic_native_read')),
    return_sha256 TEXT NOT NULL CHECK (return_sha256 ~ '^[0-9a-f]{64}$'),
    original_wire BYTEA NOT NULL CHECK (octet_length(original_wire) BETWEEN 1 AND 1048576),
    original_record JSONB NOT NULL CHECK (jsonb_typeof(original_record)='object'),
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE(preregistration_id,native_stage,return_sha256)
);
-- +goose StatementBegin
DO $$
DECLARE relation_name TEXT;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY[
        'capacity_guest_original_create_witnesses',
        'capacity_guest_runtime_snapshot_challenges',
        'capacity_guest_runtime_snapshot_returns',
        'capacity_guest_original_caller_attempts',
        'capacity_guest_original_caller_returns'
        ,'capacity_guest_original_authority_reads'
        ,'capacity_guest_original_authority_returns'
        ,'capacity_guest_original_native_poweroff_reads'
        ,'capacity_guest_original_retirement_contexts'
        ,'capacity_guest_original_authority_transport_returns'
        ,'capacity_guest_qualification_probe_challenges'
        ,'capacity_guest_qualification_native_source_returns'
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname=relation_name || '_immutable' AND tgrelid=('public.' || relation_name)::regclass) THEN
            EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable()', relation_name || '_immutable', relation_name);
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd
-- +goose Down
-- Operational migrations are append-only. Permanent original identities are
-- intentionally retained; a rollback never makes an uncertain action reusable.
SELECT 1;
