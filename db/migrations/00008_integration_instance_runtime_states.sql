-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS public.integration_instance_runtime_states (
    integration_instance_manifest_id UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
    integration_type_manifest_id UUID NOT NULL REFERENCES public.manifests(id) ON DELETE CASCADE,
    check_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_success_at TIMESTAMPTZ NULL,
    last_failure_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (integration_instance_manifest_id, check_kind)
);

CREATE INDEX IF NOT EXISTS integration_instance_runtime_states_type_idx
    ON public.integration_instance_runtime_states (integration_type_manifest_id, check_kind, status);

DROP TRIGGER IF EXISTS integration_instance_runtime_states_touch_updated_at ON public.integration_instance_runtime_states;
CREATE TRIGGER integration_instance_runtime_states_touch_updated_at
    BEFORE UPDATE ON public.integration_instance_runtime_states
    FOR EACH ROW
    EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS integration_instance_runtime_states_touch_updated_at ON public.integration_instance_runtime_states;
DROP TABLE IF EXISTS public.integration_instance_runtime_states;
-- +goose StatementEnd
