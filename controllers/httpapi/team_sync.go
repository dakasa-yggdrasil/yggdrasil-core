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
		"team_id":        team.ID,
		"events_emitted": 1,
		"event_type":     repository.EventTypeTeamCreated,
	})
}
