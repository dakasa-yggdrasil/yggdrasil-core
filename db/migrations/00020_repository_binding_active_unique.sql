-- +goose Up
-- +goose StatementBegin

-- Restrict the per-repository uniqueness check to ACTIVE bindings only.
--
-- Without this filter, soft-deleting a repository_binding (active=FALSE) leaves
-- the partial index entry in place under the SAME (spec->>'repository') key,
-- which then collides with any new binding pointing at the same repo slug.
-- The collision surfaces as a 23505 unique_violation on POST /api/v1/manifests
-- and there is no public API to PATCH/PUT a binding, so the only escape today
-- is to delete the dead row directly in Postgres — defeats the whole point of
-- soft delete + audit history.
--
-- The lookup index in 00016 deliberately matches across active/inactive rows
-- so deactivated bindings remain auditable; only the *uniqueness* invariant
-- needs to scope to active rows.

DROP INDEX IF EXISTS public.manifests_repository_binding_unique_repo;

CREATE UNIQUE INDEX IF NOT EXISTS manifests_repository_binding_unique_repo
    ON public.manifests ((spec->>'repository'))
    WHERE kind = 'repository_binding' AND active = TRUE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.manifests_repository_binding_unique_repo;

-- Restore the original (pre-00020) uniqueness across all rows so a rollback
-- leaves the schema identical to migration 00016.
CREATE UNIQUE INDEX IF NOT EXISTS manifests_repository_binding_unique_repo
    ON public.manifests ((spec->>'repository'))
    WHERE kind = 'repository_binding';

-- +goose StatementEnd
