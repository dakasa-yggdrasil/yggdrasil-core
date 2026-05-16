package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/externalidentity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type postExternalIdentityRequest struct {
	CollaboratorID        string         `json:"collaborator_id"`
	IntegrationInstanceID string         `json:"integration_instance_id"`
	ExternalID            string         `json:"external_id"`
	ExternalMetadata      map[string]any `json:"external_metadata"`
}

func (s *Server) handleExternalIdentityPost(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}
	var body postExternalIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body: " + err.Error()})
		return
	}
	collabID, err := uuid.Parse(strings.TrimSpace(body.CollaboratorID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator_id"})
		return
	}
	instanceID, err := uuid.Parse(strings.TrimSpace(body.IntegrationInstanceID))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid integration_instance_id"})
		return
	}
	if strings.TrimSpace(body.ExternalID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "external_id is required"})
		return
	}

	id, outcome, err := externalidentity.Upsert(r.Context(), s.db, externalidentity.UpsertInput{
		CollaboratorID:        collabID,
		IntegrationInstanceID: instanceID,
		ExternalID:            body.ExternalID,
		ExternalMetadata:      body.ExternalMetadata,
	})
	if err != nil {
		var cerr *externalidentity.ConflictError
		if errors.As(err, &cerr) {
			_ = emitConflictEvent(r.Context(), s.db, cerr)
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":                    "external_id already active on different collaborator",
				"existing_collaborator_id": cerr.ExistingCollaboratorID.String(),
				"existing_external_id":     cerr.ExternalID,
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	_ = emitLinkedEvent(r.Context(), s.db, id, collabID, instanceID, body.ExternalID, body.ExternalMetadata, outcome == externalidentity.OutcomeReLinked)

	status := http.StatusCreated
	if outcome != externalidentity.OutcomeInserted {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"identity_id": id.String(),
		"outcome":     string(outcome),
	})
}

func (s *Server) handleExternalIdentityGet(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}
	q := r.URL.Query()
	activeFilter := q.Get("active")
	activeOnly := true
	if activeFilter == "false" || activeFilter == "all" {
		activeOnly = false
	}
	filters := externalidentity.ListFilters{
		ActiveOnly: activeOnly,
		TypeName:   q.Get("type_name"),
	}
	if v := q.Get("collaborator_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid collaborator_id"})
			return
		}
		filters.CollaboratorID = &id
	}
	if v := q.Get("integration_instance_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid integration_instance_id"})
		}
		filters.IntegrationInstanceID = &id
	}
	filters.Limit = parseIntOr(q.Get("limit"), 100)
	if filters.Limit > 500 {
		filters.Limit = 500
	}
	filters.Offset = parseIntOr(q.Get("offset"), 0)

	identities, err := externalidentity.List(r.Context(), s.db, filters)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(identities))
	for _, i := range identities {
		row := map[string]any{
			"id":                      i.ID.String(),
			"collaborator_id":         i.CollaboratorID.String(),
			"integration_instance_id": i.IntegrationInstanceID.String(),
			"external_id":             i.ExternalID,
			"external_metadata":       i.ExternalMetadata,
			"linked_at":               i.LinkedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			"last_seen_at":            i.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		}
		if i.UnlinkedAt != nil {
			row["unlinked_at"] = i.UnlinkedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		} else {
			row["unlinked_at"] = nil
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": out})
}

func parseIntOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func emitLinkedEvent(ctx context.Context, db *sql.DB, identityID, collabID, instanceID uuid.UUID, externalID string, metadata map[string]any, reLinked bool) error {
	return externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityLinked, identityID,
		externalidentity.BuildLinkedPayload(externalidentity.LinkedInputs{
			IdentityID: identityID, CollaboratorID: collabID,
			IntegrationInstanceID: instanceID, ExternalID: externalID,
			ReLinked: reLinked, LinkedAt: time.Now().UTC(),
			ExternalMetadata: metadata,
		}))
}

func emitConflictEvent(ctx context.Context, db *sql.DB, e *externalidentity.ConflictError) error {
	return externalidentity.EmitEvent(ctx, db, repository.EventTypeExternalIdentityConflictDetected, e.IntegrationInstanceID,
		externalidentity.BuildConflictPayload(externalidentity.ConflictInputs{
			IntegrationInstanceID:  e.IntegrationInstanceID,
			ExternalID:             e.ExternalID,
			IncomingCollaboratorID: e.IncomingCollaboratorID,
			ExistingCollaboratorID: e.ExistingCollaboratorID,
			DetectedAt:             time.Now().UTC(),
		}))
}

func (s *Server) handleExternalIdentityDelete(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}
	raw := strings.TrimSpace(r.PathValue("id"))
	id, err := uuid.Parse(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid uuid"})
		return
	}
	hard := r.URL.Query().Get("hard") == "true"

	if hard {
		if err := externalidentity.HardDelete(r.Context(), s.db, id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	identity, err := externalidentity.SoftDelete(r.Context(), s.db, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	unlinkedAt := time.Now().UTC()
	if identity.UnlinkedAt != nil {
		unlinkedAt = *identity.UnlinkedAt
	}
	_ = externalidentity.EmitEvent(r.Context(), s.db, repository.EventTypeExternalIdentityUnlinked, identity.ID,
		externalidentity.BuildUnlinkedPayload(externalidentity.UnlinkedInputs{
			IdentityID: identity.ID, CollaboratorID: identity.CollaboratorID,
			IntegrationInstanceID: identity.IntegrationInstanceID,
			ExternalID:            identity.ExternalID,
			UnlinkedAt:            unlinkedAt,
		}))
	writeJSON(w, http.StatusOK, map[string]any{"identity_id": identity.ID.String(), "outcome": "unlinked"})
}
