-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.team_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES public.teams(id) ON DELETE CASCADE,
    integration_instance_namespace TEXT NOT NULL,
    integration_instance_name TEXT NOT NULL,
    action_name TEXT NOT NULL DEFAULT '*',
    scope JSONB NOT NULL DEFAULT '{}'::jsonb,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by UUID NULL REFERENCES public.collaborators(id) ON DELETE SET NULL,
    CONSTRAINT team_grants_unique
        UNIQUE (team_id, integration_instance_namespace, integration_instance_name, action_name)
);

CREATE INDEX IF NOT EXISTS team_grants_team_idx
    ON public.team_grants (team_id);

CREATE INDEX IF NOT EXISTS team_grants_integration_idx
    ON public.team_grants (integration_instance_namespace, integration_instance_name);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS public.team_grants;
-- +goose StatementEnd
