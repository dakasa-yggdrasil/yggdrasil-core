-- +goose Up
-- +goose StatementBegin

-- Lookup index for the GitHub webhook handler: routes push events to the
-- workflow declared on the repository_binding manifest matching the pushed
-- repository slug.
CREATE INDEX IF NOT EXISTS manifests_repository_binding_lookup
    ON public.manifests USING btree ((spec->>'repository'))
    WHERE kind = 'repository_binding';

-- Uniqueness constraint: at most one repository_binding per repository slug.
-- Multi-branch / multi-environment dispatch is modelled inside a single
-- binding via spec.deploy.branch_filter, not via multiple bindings.
CREATE UNIQUE INDEX IF NOT EXISTS manifests_repository_binding_unique_repo
    ON public.manifests ((spec->>'repository'))
    WHERE kind = 'repository_binding';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.manifests_repository_binding_unique_repo;
DROP INDEX IF EXISTS public.manifests_repository_binding_lookup;

-- +goose StatementEnd
