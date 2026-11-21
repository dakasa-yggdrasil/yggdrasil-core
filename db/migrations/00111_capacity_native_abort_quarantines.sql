-- +goose Up
CREATE TABLE IF NOT EXISTS public.capacity_native_abort_quarantines (
    command_id UUID PRIMARY KEY REFERENCES public.capacity_native_command_identities(id),
    subject_uid TEXT NOT NULL UNIQUE,
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    quarantine_record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capacity_native_abort_quarantine_immutable' AND tgrelid='public.capacity_native_abort_quarantines'::regclass) THEN
        CREATE TRIGGER capacity_native_abort_quarantine_immutable
            BEFORE UPDATE OR DELETE ON public.capacity_native_abort_quarantines
            FOR EACH ROW EXECUTE FUNCTION public.capacity_native_archive_immutable();
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- An exercised administrative receipt is a permanent UID deny/audit fact.
-- Never erase it to make an uncertain mutation eligible again.
-- +goose StatementBegin
DO $$
BEGIN
    LOCK TABLE public.capacity_native_abort_quarantines IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM public.capacity_native_abort_quarantines) THEN
        RAISE EXCEPTION 'retained native abort quarantine prevents rollback';
    END IF;
END;
$$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_abort_quarantines;
