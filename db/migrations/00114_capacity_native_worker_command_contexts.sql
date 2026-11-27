-- +goose Up
-- Private immutable command authority is committed with its reserved attempt.
-- No controller executor/workflow identity is added to the public Attempt DTO.
CREATE TABLE IF NOT EXISTS public.capacity_native_worker_command_contexts (
    attempt_id UUID PRIMARY KEY REFERENCES public.capacity_native_worker_attempts(id),
    record JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK((record->>'attempt_id'=attempt_id::text) IS TRUE)
);
CREATE INDEX IF NOT EXISTS capacity_native_worker_command_machine
ON public.capacity_native_worker_command_contexts
((record#>>'{execution,adapter,manifest_id}'),(record#>>'{execution,sdk_source_commit}'));
DROP TRIGGER IF EXISTS capacity_native_worker_command_immutable ON public.capacity_native_worker_command_contexts;
CREATE TRIGGER capacity_native_worker_command_immutable BEFORE UPDATE OR DELETE
ON public.capacity_native_worker_command_contexts FOR EACH ROW EXECUTE FUNCTION public.capacity_native_worker_archive_immutable();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 LOCK TABLE public.capacity_native_worker_command_contexts IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.capacity_native_worker_command_contexts)
 THEN RAISE EXCEPTION 'Native command authority and possible sends cannot be discarded'; END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_worker_command_contexts;
