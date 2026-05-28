-- +goose Up
-- +goose StatementBegin

-- Tenant-scoped taxonomy for integration_type.spec.domain. Each row
-- in integration_domain_catalog is one section the tenant wants on
-- /ops/integrations: the slug must match what the adapter declares,
-- and the rest is presentation (title, subtitle, order).
--
-- Stored as JSONB so the surface can hydrate the full catalog in a
-- single read and the schema stays flexible while the contract
-- (INTEGRATION_CONTRACT §17) settles. Default is an empty array;
-- consumers fall back to a built-in suggestion list when the array
-- is empty.

ALTER TABLE public.tenant_brand_settings
    ADD COLUMN IF NOT EXISTS integration_domain_catalog JSONB NOT NULL DEFAULT '[]'::jsonb;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE public.tenant_brand_settings
    DROP COLUMN IF EXISTS integration_domain_catalog;

-- +goose StatementEnd
