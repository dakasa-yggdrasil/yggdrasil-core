package httpapi

import (
	"fmt"
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleTeamSync re-emits a team.created canon event for the given team.
// Operator-triggered escape hatch when the automatic reconcile cron
// hasn't caught a gap yet (or as a debugging aid after an adapter fix).
// Adapter idempotency makes this safe to invoke arbitrarily.
//
// Returns 202 Accepted + {events_emitted: 1} on success — the event is
// inserted in event_log, and MaterializeReactions schedules one reaction
// row per matching active integration_instance.
func (s *Server) handleTeamSync(w http.ResponseWriter, r *http.Request) {
	teamIDStr := r.PathValue("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid team id"})
		return
	}

	team, err := repository.GetTeam(r.Context(), s.db, teamID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	payload := map[string]any{
		"id":   team.ID.String(),
		"slug": team.Slug,
		"name": team.Name,
		"type": team.Type,
	}
	if team.ParentTeamID != nil {
		payload["parent_team_id"] = team.ParentTeamID.String()
	}

	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamCreated,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload:       payload,
		Actor: &model.EventActor{
			Type: model.ActorTypeAPI,
			ID:   actorIDFromRequest(r),
		},
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit team.created: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit team.sync: %w", err))
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"team_id":        team.ID.String(),
		"events_emitted": 1,
		"event_type":     repository.EventTypeTeamCreated,
	})
}

// handleTeamProvisioningStatus returns the per-adapter provisioning state
// for a team: which integration_instances have a mirror (from
// team_provisioning_log), which have a pending/failed reaction
// (integration_event_reactions), and which were dead_lettered.
func (s *Server) handleTeamProvisioningStatus(w http.ResponseWriter, r *http.Request) {
	teamIDStr := r.PathValue("id")
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid team id"})
		return
	}

	provisioning, err := repository.ListTeamProvisioningLogByTeam(r.Context(), s.db, teamID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Reactions whose underlying event was emitted for this team.
	reactionRows, err := s.db.QueryContext(r.Context(), `
		SELECT r.integration_instance_id, r.capability, r.attempt,
		       COALESCE(r.last_error, ''), r.status
		FROM integration_event_reactions r
		JOIN event_log e ON e.event_id = r.event_id
		WHERE e.aggregate_type = 'team'
		  AND e.aggregate_id = $1
		  AND r.status IN ('pending','failed','dead_lettered')
		ORDER BY r.id DESC
		LIMIT 200
	`, teamID.String())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	defer reactionRows.Close()

	type reactionView struct {
		IntegrationInstanceID uuid.UUID `json:"integration_instance_id"`
		Capability            string    `json:"capability"`
		Attempt               int       `json:"attempt"`
		LastError             string    `json:"last_error,omitempty"`
	}
	pending := []reactionView{}
	deadLettered := []reactionView{}
	for reactionRows.Next() {
		var rx reactionView
		var status string
		if err := reactionRows.Scan(&rx.IntegrationInstanceID, &rx.Capability, &rx.Attempt, &rx.LastError, &status); err != nil {
			writeMappedError(w, err)
			return
		}
		if status == "dead_lettered" {
			deadLettered = append(deadLettered, rx)
		} else {
			pending = append(pending, rx)
		}
	}
	if err := reactionRows.Err(); err != nil {
		writeMappedError(w, err)
		return
	}

	if provisioning == nil {
		provisioning = []model.TeamProvisioningLog{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"team_id":       teamID.String(),
		"provisioning":  provisioning,
		"pending":       pending,
		"dead_lettered": deadLettered,
	})
}
