-- +goose Up
CREATE TABLE IF NOT EXISTS public.tenant_brand_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    name TEXT NOT NULL DEFAULT 'Sua organização',
    short_name TEXT NOT NULL DEFAULT 'ORG',
    product_label TEXT NOT NULL DEFAULT 'Yggdrasil Console',
    locale TEXT NOT NULL DEFAULT 'pt-BR',
    accent_override TEXT,
    logo_url TEXT,
    support_email TEXT,
    updated_by UUID REFERENCES public.collaborators(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.tenant_brand_settings (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS public.tenant_brand_settings;
