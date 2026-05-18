package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// UpsertTeamProvisioningLog inserts a new row or updates the existing one
// for the (team_id, integration_instance_id) pair. The adapter envelope
// extractor in addons/reactor_dispatcher.go calls this after a successful
// on_team_created / on_team_updated ack.
func UpsertTeamProvisioningLog(ctx context.Context, db *sql.DB, req model.UpsertTeamProvisioningLogRequest) (model.TeamProvisioningLog, error) {
	meta, err := json.Marshal(req.ExternalMetadata)
	if err != nil {
		return model.TeamProvisioningLog{}, fmt.Errorf("marshal external_metadata: %w", err)
	}
	if string(meta) == "null" {
		meta = []byte("{}")
	}
	var row model.TeamProvisioningLog
	err = db.QueryRowContext(ctx, `
		INSERT INTO team_provisioning_log
			(team_id, integration_instance_id, external_id, external_metadata, last_event_type)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (team_id, integration_instance_id) DO UPDATE
		SET external_id       = EXCLUDED.external_id,
		    external_metadata = EXCLUDED.external_metadata,
		    last_success_at   = NOW(),
		    last_event_type   = EXCLUDED.last_event_type,
		    updated_at        = NOW()
		RETURNING id, team_id, integration_instance_id, external_id,
		          external_metadata, last_success_at, last_event_type,
		          created_at, updated_at
	`, req.TeamID, req.IntegrationInstanceID, req.ExternalID, meta, req.LastEventType).
		Scan(&row.ID, &row.TeamID, &row.IntegrationInstanceID, &row.ExternalID,
			&row.ExternalMetadata, &row.LastSuccessAt, &row.LastEventType,
			&row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return model.TeamProvisioningLog{}, fmt.Errorf("upsert team_provisioning_log: %w", err)
	}
	return row, nil
}

// GetTeamProvisioningLog returns the log row for one (team, instance) pair,
// or a zero-value row with no error when no row exists. Used by the
// dispatcher to inject _context.team_provisioned for team.* reactions.
func GetTeamProvisioningLog(ctx context.Context, db *sql.DB, teamID, instanceID uuid.UUID) (model.TeamProvisioningLog, error) {
	var r model.TeamProvisioningLog
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, integration_instance_id, external_id, external_metadata,
		       last_success_at, last_event_type, created_at, updated_at
		FROM team_provisioning_log
		WHERE team_id = $1 AND integration_instance_id = $2
	`, teamID, instanceID).Scan(&r.ID, &r.TeamID, &r.IntegrationInstanceID, &r.ExternalID,
		&r.ExternalMetadata, &r.LastSuccessAt, &r.LastEventType, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return model.TeamProvisioningLog{}, nil
	}
	if err != nil {
		return model.TeamProvisioningLog{}, err
	}
	return r, nil
}

// ListTeamProvisioningLogByTeam returns every mirror entry for a single team.
// Used by GET /api/v1/teams/{id}/provisioning-status to render the
// per-adapter mirror state.
func ListTeamProvisioningLogByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]model.TeamProvisioningLog, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, integration_instance_id, external_id, external_metadata,
		       last_success_at, last_event_type, created_at, updated_at
		FROM team_provisioning_log
		WHERE team_id = $1
		ORDER BY created_at ASC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list team_provisioning_log: %w", err)
	}
	defer rows.Close()

	var out []model.TeamProvisioningLog
	for rows.Next() {
		var r model.TeamProvisioningLog
		if err := rows.Scan(&r.ID, &r.TeamID, &r.IntegrationInstanceID, &r.ExternalID,
			&r.ExternalMetadata, &r.LastSuccessAt, &r.LastEventType,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
