-- +goose Up
-- +goose StatementBegin

-- permissions_catalog is the registry where integrations declare the
-- permission types they expose (e.g. clt:vacation:request-own,
-- core:collaborators:read). registered_by is the integration slug,
-- which lets a reinstall reset its rows without touching others.
--
-- role_permission_bindings is the tenant-side mapping (lives logically
-- in dakasa-system-yggdrasil-v2 config but persisted here for runtime
-- evaluation). A row binds one role to one permission; multiple rows
-- per role accumulate. `role` is a free-form string matching the value
-- on collaborators.role.

CREATE TABLE IF NOT EXISTS public.permissions_catalog (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    registered_by   TEXT NOT NULL,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT permissions_catalog_name_unique UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS permissions_catalog_registered_by_idx
    ON public.permissions_catalog (registered_by);

DROP TRIGGER IF EXISTS permissions_catalog_touch_updated_at
    ON public.permissions_catalog;
CREATE TRIGGER permissions_catalog_touch_updated_at
    BEFORE UPDATE ON public.permissions_catalog
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.role_permission_bindings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role            TEXT NOT NULL,
    permission_name TEXT NOT NULL REFERENCES public.permissions_catalog(name) ON DELETE CASCADE,
    bound_by        TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT role_permission_bindings_unique
        UNIQUE (role, permission_name)
);

CREATE INDEX IF NOT EXISTS role_permission_bindings_role_idx
    ON public.role_permission_bindings (role);

CREATE INDEX IF NOT EXISTS role_permission_bindings_permission_idx
    ON public.role_permission_bindings (permission_name);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS public.role_permission_bindings_permission_idx;
DROP INDEX IF EXISTS public.role_permission_bindings_role_idx;
DROP TABLE IF EXISTS public.role_permission_bindings;

DROP TRIGGER IF EXISTS permissions_catalog_touch_updated_at
    ON public.permissions_catalog;
DROP INDEX IF EXISTS public.permissions_catalog_registered_by_idx;
DROP TABLE IF EXISTS public.permissions_catalog;

-- +goose StatementEnd
