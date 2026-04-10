-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.product_materializations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    product_manifest_id UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
    product_version INTEGER NOT NULL,
    product_checksum TEXT NOT NULL,
    materialized_spec JSONB NOT NULL,
    materialized_checksum TEXT NOT NULL,
    components JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS product_materializations_manifest_lookup_idx
    ON public.product_materializations (product_manifest_id, created_at DESC);

CREATE INDEX IF NOT EXISTS product_materializations_checksum_lookup_idx
    ON public.product_materializations (product_checksum, materialized_checksum);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.product_materializations;
-- +goose StatementEnd
