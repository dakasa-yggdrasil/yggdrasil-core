-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.saml_service_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    sp_entity_id TEXT NOT NULL,
    acs_url TEXT NOT NULL,
    slo_url TEXT NULL,
    name_id_format TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    signing_required BOOLEAN NOT NULL DEFAULT TRUE,
    encryption_required BOOLEAN NOT NULL DEFAULT FALSE,
    sp_x509_cert TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saml_service_providers_slug_unique UNIQUE (slug),
    CONSTRAINT saml_service_providers_sp_entity_id_unique UNIQUE (sp_entity_id)
);

DROP TRIGGER IF EXISTS saml_service_providers_touch_updated_at ON public.saml_service_providers;
CREATE TRIGGER saml_service_providers_touch_updated_at
    BEFORE UPDATE ON public.saml_service_providers
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.saml_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id TEXT NOT NULL,
    private_key_ciphertext BYTEA NOT NULL,
    private_key_dek BYTEA NOT NULL,
    x509_cert_pem TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'RSA-SHA256',
    status TEXT NOT NULL DEFAULT 'active',
    activated_at TIMESTAMPTZ NULL,
    retired_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT saml_signing_keys_key_id_unique UNIQUE (key_id)
);

CREATE INDEX IF NOT EXISTS saml_signing_keys_status_idx
    ON public.saml_signing_keys (status, activated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.saml_signing_keys;
DROP TRIGGER IF EXISTS saml_service_providers_touch_updated_at ON public.saml_service_providers;
DROP TABLE IF EXISTS public.saml_service_providers;
-- +goose StatementEnd
