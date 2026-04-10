-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'team',
    status TEXT NOT NULL DEFAULT 'active',
    parent_team_id UUID NULL REFERENCES public.teams(id) ON DELETE SET NULL,
    owners JSONB NOT NULL DEFAULT '[]'::jsonb,
    traits JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS teams_slug_uidx
    ON public.teams (slug);

CREATE INDEX IF NOT EXISTS teams_lookup_idx
    ON public.teams (status, type, slug);

DROP TRIGGER IF EXISTS teams_touch_updated_at ON public.teams;
CREATE TRIGGER teams_touch_updated_at
    BEFORE UPDATE ON public.teams
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.collaborators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    display_name TEXT NOT NULL,
    primary_email TEXT NOT NULL DEFAULT '',
    manager_id UUID NULL REFERENCES public.collaborators(id) ON DELETE SET NULL,
    primary_team_id UUID NULL REFERENCES public.teams(id) ON DELETE SET NULL,
    personal_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    employment_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    third_party_identities JSONB NOT NULL DEFAULT '{}'::jsonb,
    traits JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS collaborators_slug_uidx
    ON public.collaborators (slug);

CREATE INDEX IF NOT EXISTS collaborators_lookup_idx
    ON public.collaborators (status, slug);

DROP TRIGGER IF EXISTS collaborators_touch_updated_at ON public.collaborators;
CREATE TRIGGER collaborators_touch_updated_at
    BEFORE UPDATE ON public.collaborators
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.team_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES public.teams(id) ON DELETE CASCADE,
    collaborator_id UUID NOT NULL REFERENCES public.collaborators(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'manual',
    starts_at TIMESTAMPTZ NULL,
    ends_at TIMESTAMPTZ NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT team_memberships_unique_link UNIQUE (team_id, collaborator_id)
);

CREATE INDEX IF NOT EXISTS team_memberships_collaborator_lookup_idx
    ON public.team_memberships (collaborator_id, active, team_id);

CREATE INDEX IF NOT EXISTS team_memberships_team_lookup_idx
    ON public.team_memberships (team_id, active, collaborator_id);

DROP TRIGGER IF EXISTS team_memberships_touch_updated_at ON public.team_memberships;
CREATE TRIGGER team_memberships_touch_updated_at
    BEFORE UPDATE ON public.team_memberships
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS team_memberships_touch_updated_at ON public.team_memberships;
DROP TABLE IF EXISTS public.team_memberships;

DROP TRIGGER IF EXISTS collaborators_touch_updated_at ON public.collaborators;
DROP TABLE IF EXISTS public.collaborators;

DROP TRIGGER IF EXISTS teams_touch_updated_at ON public.teams;
DROP TABLE IF EXISTS public.teams;
-- +goose StatementEnd
