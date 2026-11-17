-- Preserve the complete provider resource identity used by mutation events.
-- The original VWC identity is 131 characters; no truncation or renaming is safe.
-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE current_type text;
BEGIN
    LOCK TABLE public.event_log IN ACCESS EXCLUSIVE MODE;
    SELECT format_type(a.atttypid, a.atttypmod) INTO current_type
      FROM pg_attribute a
     WHERE a.attrelid = 'public.event_log'::regclass
       AND a.attname = 'aggregate_id' AND NOT a.attisdropped;
    IF current_type = 'character varying(128)' THEN
        ALTER TABLE public.event_log ALTER COLUMN aggregate_id TYPE TEXT;
    ELSIF current_type IS DISTINCT FROM 'text' THEN
        RAISE EXCEPTION 'event_log.aggregate_id has an unexpected type';
    END IF;
END;
$$;
-- +goose StatementEnd

-- A used widening cannot be reversed by dropping or truncating audit identities.
-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE current_type text;
BEGIN
    LOCK TABLE public.event_log IN ACCESS EXCLUSIVE MODE;
    SELECT format_type(a.atttypid, a.atttypmod) INTO current_type
      FROM pg_attribute a
     WHERE a.attrelid = 'public.event_log'::regclass
       AND a.attname = 'aggregate_id' AND NOT a.attisdropped;
    IF current_type = 'text' THEN
        IF EXISTS (SELECT 1 FROM public.event_log WHERE char_length(aggregate_id) > 128) THEN
            RAISE EXCEPTION 'event_log.aggregate_id widening is in use; refusing narrowing';
        END IF;
        ALTER TABLE public.event_log ALTER COLUMN aggregate_id TYPE VARCHAR(128);
    ELSIF current_type IS DISTINCT FROM 'character varying(128)' THEN
        RAISE EXCEPTION 'event_log.aggregate_id has an unexpected type';
    END IF;
END;
$$;
-- +goose StatementEnd
