-- +goose Up
-- +goose StatementBegin
CREATE TABLE team_provisioning_log (
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

CREATE INDEX idx_team_provisioning_log_team ON team_provisioning_log(team_id);
CREATE INDEX idx_team_provisioning_log_instance ON team_provisioning_log(integration_instance_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS team_provisioning_log;
-- +goose StatementEnd
