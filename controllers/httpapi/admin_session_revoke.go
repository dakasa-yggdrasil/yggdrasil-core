// Package httpapi — admin endpoint for revoking every active session for
// one collaborator.
//
// §13 INTEGRATION_CONTRACT: when an admin needs to forcibly log a
// collaborator out of every device + every OIDC client (incident response,
// suspected compromise, leaving the company without going through
// offboard), this endpoint does it atomically and propagates the
// revocation via the central authority table + RFC 8417 back-channel
// logout.
package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

type adminRevokeSessionsRequest struct {
	// Free-form note for audit. Optional but strongly encouraged.
	Note string `json:"note,omitempty"`
}

type adminRevokeSessionsResponse struct {
	CollaboratorID string `json:"collaborator_id"`
	Revoked        int    `json:"revoked_sessions"`
	RevocationID   string `json:"revocation_id"`
}

// handleAdminCollaboratorRevokeSessions — POST /api/v1/admin/collaborators/{id}/revoke-sessions
//
// Auth: shared admin token (YGGDRASIL_AUTH_ADMIN_TOKEN). Same auth model
// as the other /api/v1/auth/* admin endpoints — single trust boundary,
// not a per-user permission check, because this is a break-glass action.
//
// Behavior:
//   1. Resolve the collaborator (validates the id).
//   2. Revoke every active session in auth_sessions (UPDATE status='revoked').
//   3. Insert a single global session_revocation row (session_jti=NULL)
//      with reason=admin_revoked.
//   4. Emit collaborator.session.terminated with revocation_id.
//   5. Dispatch RFC 8417 back-channel logout to every OIDC client linked
//      to the collaborator (best-effort, goroutine).
//
// Idempotent: calling twice in succession revokes the (now zero) active
// sessions and emits a second revocation row — the second emit will be
// a no-op event because no sessions matched. The revocation row IS
// inserted on both calls so the audit trail captures the intent.
func (s *Server) handleAdminCollaboratorRevokeSessions(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}

	var req adminRevokeSessionsRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	collab, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	res, err := s.db.ExecContext(r.Context(), `
		UPDATE auth_sessions
		SET status = 'revoked',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE collaborator_id = $1 AND revoked_at IS NULL
	`, collab.ID)
	if err != nil {
		writeMappedError(w, fmt.Errorf("revoke sessions: %w", err))
		return
	}
	revoked, _ := res.RowsAffected()

	metadata := map[string]any{
		"source_ip":  clientIP(r),
		"user_agent": r.UserAgent(),
	}
	if note := strings.TrimSpace(req.Note); note != "" {
		metadata["note"] = note
	}

	// recordSessionRevocation handles insertion + canon event emit in a
	// single transaction; jti=nil scopes the revocation to "every session
	// since revoked_at" which is exactly what admin_revoked means.
	rev, err := repository.InsertSessionRevocation(r.Context(), s.db, nil, repository.InsertSessionRevocationRequest{
		CollaboratorID: collab.ID,
		SessionJTI:     nil,
		Reason:         repository.SessionRevocationReasonAdminRevoked,
		Metadata:       metadata,
	})
	if err != nil {
		writeMappedError(w, fmt.Errorf("insert revocation: %w", err))
		return
	}

	// Emit canon event outside the revocation tx (the revocation is
	// already persisted; event emission is best-effort).
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err == nil {
		payload := map[string]any{
			"collaborator_id": collab.ID.String(),
			"reason":          repository.SessionRevocationReasonAdminRevoked,
			"revocation_id":   rev.ID.String(),
			"emitted_at":      time.Now().UTC().Format(time.RFC3339),
		}
		if collab.PrimaryEmail != "" {
			payload["primary_email"] = collab.PrimaryEmail
		}
		_, emitErr := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
			Type:           repository.EventTypeCollaboratorSessionTerminated,
			SchemaVersion:  "v1",
			AggregateType:  "collaborator",
			AggregateID:    collab.ID.String(),
			Payload:        payload,
			IdempotencyKey: "session.terminated." + rev.ID.String(),
		})
		if emitErr != nil {
			_ = tx.Rollback()
		} else if err := tx.Commit(); err != nil {
			s.logger.Warn("admin revoke: commit event tx failed",
				zap.String("collaborator_id", collab.ID.String()),
				zap.Error(err))
		}
	}

	// Fire RFC 8417 back-channel logout for every OIDC client linked to
	// this collaborator (goroutine — caller doesn't wait).
	s.dispatchBackchannelLogoutForCollaborator(r.Context(), collab.ID)

	writeJSON(w, http.StatusOK, adminRevokeSessionsResponse{
		CollaboratorID: collab.ID.String(),
		Revoked:        int(revoked),
		RevocationID:   rev.ID.String(),
	})
}
