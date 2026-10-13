-- +goose Up
-- Original adapter and original Core caller acknowledgements are independent.
-- No TTL/deadline cleanup releases an unresolved record.
CREATE TABLE IF NOT EXISTS public.capacity_native_release_results (
    command_id UUID PRIMARY KEY REFERENCES public.capacity_native_command_identities(id),
    attempt_id UUID NOT NULL UNIQUE,
    protocol TEXT NOT NULL,
    adapter_source_commit TEXT NOT NULL,
    return_nonce_sha256 TEXT NOT NULL UNIQUE,
    original_deadline TIMESTAMPTZ NOT NULL,
    adapter_result JSONB,
    adapter_result_sha256 TEXT,
    adapter_ack_at TIMESTAMPTZ,
    caller_ack_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS public.capacity_native_release_recovery_decisions (
    id UUID PRIMARY KEY,
    parent_command_id UUID NOT NULL UNIQUE REFERENCES public.capacity_native_command_identities(id),
    parent_attempt_id UUID NOT NULL UNIQUE,
    command_id UUID NOT NULL UNIQUE REFERENCES public.capacity_native_command_identities(id),
    fence UUID NOT NULL UNIQUE,
    decision_record JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.capacity_native_original_ack_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.command_id<>OLD.command_id OR NEW.attempt_id<>OLD.attempt_id
       OR NEW.protocol<>OLD.protocol OR NEW.adapter_source_commit<>OLD.adapter_source_commit
       OR NEW.return_nonce_sha256<>OLD.return_nonce_sha256 OR NEW.original_deadline<>OLD.original_deadline
       OR (OLD.adapter_result IS NOT NULL AND NEW.adapter_result IS DISTINCT FROM OLD.adapter_result)
       OR (OLD.adapter_result_sha256 IS NOT NULL AND NEW.adapter_result_sha256 IS DISTINCT FROM OLD.adapter_result_sha256)
       OR (OLD.adapter_ack_at IS NOT NULL AND NEW.adapter_ack_at IS DISTINCT FROM OLD.adapter_ack_at)
       OR (OLD.caller_ack_at IS NOT NULL AND NEW.caller_ack_at IS DISTINCT FROM OLD.caller_ack_at) THEN
        RAISE EXCEPTION 'original native return records are immutable once acknowledged';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capacity_native_original_ack_immutable' AND tgrelid='public.capacity_native_release_results'::regclass) THEN
        CREATE TRIGGER capacity_native_original_ack_immutable BEFORE UPDATE OR DELETE ON public.capacity_native_release_results FOR EACH ROW EXECUTE FUNCTION public.capacity_native_original_ack_immutable();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capacity_native_release_decision_immutable' AND tgrelid='public.capacity_native_release_recovery_decisions'::regclass) THEN
        CREATE TRIGGER capacity_native_release_decision_immutable BEFORE UPDATE OR DELETE ON public.capacity_native_release_recovery_decisions FOR EACH ROW EXECUTE FUNCTION public.capacity_native_archive_immutable();
    END IF;
END; $$;
-- +goose StatementEnd
-- +goose Down
DROP TABLE IF EXISTS public.capacity_native_release_recovery_decisions;
DROP TABLE IF EXISTS public.capacity_native_release_results;
DROP FUNCTION IF EXISTS public.capacity_native_original_ack_immutable();
