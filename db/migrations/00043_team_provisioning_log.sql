-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS team_provisioning_log (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                  UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    integration_instance_id  UUID NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    external_id              TEXT NOT NULL,
    external_metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_success_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_event_type          TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_id, integration_instance_id)
);

CREATE INDEX IF NOT EXISTS team_provisioning_log_team_idx ON team_provisioning_log(team_id);
CREATE INDEX IF NOT EXISTS team_provisioning_log_instance_idx ON team_provisioning_log(integration_instance_id);

DROP TRIGGER IF EXISTS team_provisioning_log_touch_updated_at ON team_provisioning_log;
CREATE TRIGGER team_provisioning_log_touch_updated_at
    BEFORE UPDATE ON team_provisioning_log
    FOR EACH ROW EXECUTE FUNCTION public.touch_updated_at();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS team_provisioning_log_touch_updated_at ON team_provisioning_log;
DROP TABLE IF EXISTS team_provisioning_log;
-- +goose StatementEnd
