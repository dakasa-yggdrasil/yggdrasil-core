-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.managed_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT managed_secrets_namespace_name_unique UNIQUE (namespace, name)
);

CREATE INDEX IF NOT EXISTS managed_secrets_namespace_status_idx
    ON public.managed_secrets (namespace, status, name);

DROP TRIGGER IF EXISTS managed_secrets_touch_updated_at ON public.managed_secrets;
CREATE TRIGGER managed_secrets_touch_updated_at
    BEFORE UPDATE ON public.managed_secrets
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS managed_secrets_touch_updated_at ON public.managed_secrets;
DROP INDEX IF EXISTS managed_secrets_namespace_status_idx;
DROP TABLE IF EXISTS public.managed_secrets;
-- +goose StatementEnd
