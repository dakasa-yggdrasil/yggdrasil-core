-- +goose Up
CREATE TABLE IF NOT EXISTS public.capacity_native_migrated_origin_retirements (
    subject_uid TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    environment TEXT NOT NULL,
    domain TEXT NOT NULL,
    dimension TEXT NOT NULL,
    origin_policy_id UUID NOT NULL REFERENCES public.manifests(id),
    checkpoint_sha256 TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    retirement_record JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
-- +goose StatementBegin
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='capacity_native_migrated_origin_immutable' AND tgrelid='public.capacity_native_migrated_origin_retirements'::regclass) THEN
        CREATE TRIGGER capacity_native_migrated_origin_immutable
            BEFORE UPDATE OR DELETE ON public.capacity_native_migrated_origin_retirements
            FOR EACH ROW EXECUTE FUNCTION public.capacity_native_archive_immutable();
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Administrative retirement permanently denies the old UID; never erase it.
-- +goose StatementBegin
DO $$ BEGIN
    LOCK TABLE public.capacity_native_migrated_origin_retirements IN ACCESS EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM public.capacity_native_migrated_origin_retirements) THEN
        RAISE EXCEPTION 'retained migrated native origin prevents rollback';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE IF EXISTS public.capacity_native_migrated_origin_retirements;
