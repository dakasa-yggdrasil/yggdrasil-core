-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.topology_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    parent_id UUID NULL REFERENCES public.topology_nodes(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS topology_nodes_parent_lookup_idx
    ON public.topology_nodes (parent_id, kind, slug);

CREATE INDEX IF NOT EXISTS topology_nodes_kind_lookup_idx
    ON public.topology_nodes (kind, slug);

DROP TRIGGER IF EXISTS topology_nodes_touch_updated_at ON public.topology_nodes;
CREATE TRIGGER topology_nodes_touch_updated_at
    BEFORE UPDATE ON public.topology_nodes
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.topology_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES public.topology_nodes(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    target_id UUID NOT NULL REFERENCES public.topology_nodes(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS topology_edges_unique_relation_idx
    ON public.topology_edges (source_id, relation, target_id);

CREATE INDEX IF NOT EXISTS topology_edges_target_lookup_idx
    ON public.topology_edges (target_id, relation, source_id);

DROP TRIGGER IF EXISTS topology_edges_touch_updated_at ON public.topology_edges;
CREATE TRIGGER topology_edges_touch_updated_at
    BEFORE UPDATE ON public.topology_edges
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.topology_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id UUID NOT NULL REFERENCES public.topology_nodes(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    body JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS topology_documents_node_kind_lookup_idx
    ON public.topology_documents (node_id, kind, name);

CREATE INDEX IF NOT EXISTS topology_documents_kind_lookup_idx
    ON public.topology_documents (kind, name);

DROP TRIGGER IF EXISTS topology_documents_touch_updated_at ON public.topology_documents;
CREATE TRIGGER topology_documents_touch_updated_at
    BEFORE UPDATE ON public.topology_documents
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();

CREATE TABLE IF NOT EXISTS public.topology_build_projects (
    id UUID PRIMARY KEY,
    project_node_id UUID NOT NULL REFERENCES public.topology_nodes(id) ON DELETE CASCADE,
    infra_map_document_id UUID NOT NULL REFERENCES public.topology_documents(id) ON DELETE RESTRICT,
    project_env_resource_id UUID NOT NULL REFERENCES public.topology_documents(id) ON DELETE RESTRICT,
    build_name TEXT NOT NULL,
    env_type TEXT NOT NULL,
    cloud TEXT NOT NULL,
    ephemeral BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TEXT NOT NULL DEFAULT '',
    cluster_name TEXT NOT NULL DEFAULT '',
    cluster_zone TEXT NOT NULL DEFAULT '',
    immutable BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS topology_build_projects_project_lookup_idx
    ON public.topology_build_projects (project_node_id, env_type, build_name);

DROP TRIGGER IF EXISTS topology_build_projects_touch_updated_at ON public.topology_build_projects;
CREATE TRIGGER topology_build_projects_touch_updated_at
    BEFORE UPDATE ON public.topology_build_projects
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS topology_build_projects_touch_updated_at ON public.topology_build_projects;
DROP TABLE IF EXISTS public.topology_build_projects;

DROP TRIGGER IF EXISTS topology_documents_touch_updated_at ON public.topology_documents;
DROP TABLE IF EXISTS public.topology_documents;

DROP TRIGGER IF EXISTS topology_edges_touch_updated_at ON public.topology_edges;
DROP TABLE IF EXISTS public.topology_edges;

DROP TRIGGER IF EXISTS topology_nodes_touch_updated_at ON public.topology_nodes;
DROP TABLE IF EXISTS public.topology_nodes;
-- +goose StatementEnd
