-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.collaborator_third_party_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    login TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    profile_url TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    claims JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_authenticated_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT collaborator_third_party_identities_provider_subject_unique UNIQUE (provider, subject),
    CONSTRAINT collaborator_third_party_identities_collaborator_provider_unique UNIQUE (collaborator_id, provider)
);

CREATE INDEX IF NOT EXISTS collaborator_third_party_identities_collaborator_lookup_idx
    ON public.collaborator_third_party_identities (collaborator_id, provider, status);

CREATE INDEX IF NOT EXISTS collaborator_third_party_identities_login_lookup_idx
    ON public.collaborator_third_party_identities (provider, login);

DROP TRIGGER IF EXISTS collaborator_third_party_identities_touch_updated_at ON public.collaborator_third_party_identities;
CREATE TRIGGER collaborator_third_party_identities_touch_updated_at
    BEFORE UPDATE ON public.collaborator_third_party_identities
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS collaborator_third_party_identities_touch_updated_at ON public.collaborator_third_party_identities;
DROP TABLE IF EXISTS public.collaborator_third_party_identities;
-- +goose StatementEnd
