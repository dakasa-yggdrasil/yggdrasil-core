package httpapi

import (
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// handleMeSessionsList returns every active session for the caller.
//
// GET /api/v1/me/sessions
//
// Each entry includes a `is_current` flag so the FE can highlight the
// session the user is reading from. Tokens / hashes are NEVER returned;
// only the opaque session ID, expires_at, last_seen_at, and the
// metadata fields the user wrote at login (user_agent, ip_address,
// device_fingerprint).
//
// Audit ref: C8 / D2 (MeSessionsPage shows a placeholder; no list).
func (s *Server) handleMeSessionsList(w http.ResponseWriter, r *http.Request) {
	session, _, ok := s.resolveCurrentCollaborator(w, r)
	if !ok {
		return
	}

	rows, err := repository.ListActiveSessionsForCollaborator(r.Context(), s.db, session.CollaboratorID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	type sessionView struct {
		ID                string `json:"id"`
		ExpiresAt         string `json:"expires_at"`
		LastSeenAt        string `json:"last_seen_at,omitempty"`
		CreatedAt         string `json:"created_at"`
		UserAgent         string `json:"user_agent,omitempty"`
		IPAddress         string `json:"ip_address,omitempty"`
		DeviceFingerprint string `json:"device_fingerprint,omitempty"`
		IsCurrent         bool   `json:"is_current"`
	}

	out := make([]sessionView, 0, len(rows))
	for _, row := range rows {
		v := sessionView{
			ID:        row.ID.String(),
			ExpiresAt: row.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			CreatedAt: row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			IsCurrent: row.ID == session.ID,
		}
		if row.LastSeenAt != nil {
			v.LastSeenAt = row.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		v.UserAgent = row.UserAgent
		v.IPAddress = row.IPAddress
		v.DeviceFingerprint = row.DeviceFingerprint
		out = append(out, v)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": out,
	})
}

// handleMeSessionsRevoke revokes one OTHER session for the caller (not
// the current one — log out of the current session uses /auth/logout).
//
// DELETE /api/v1/me/sessions/{id}
//
// Returns 204 on success, 404 when the session doesn't belong to the
// caller, 403 when the ID is the caller's current session (use logout).
//
// §13 INTEGRATION_CONTRACT: emits session_revocation + back-channel
// logout for the targeted session so OIDC clients get notified.
//
// Audit ref: C8 (user cannot revoke "laptop I left at the conference").
func (s *Server) handleMeSessionsRevoke(w http.ResponseWriter, r *http.Request) {
	currentSession, _, ok := s.resolveCurrentCollaborator(w, r)
	if !ok {
		return
	}

	idStr := r.PathValue("id")
	targetID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid session id")
		return
	}

	if targetID == currentSession.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "cannot revoke the current session via this endpoint; use POST /api/v1/auth/logout",
			"code":  "current_session_revoke_forbidden",
		})
		return
	}

	revoked, err := repository.RevokeSessionByIDForCollaborator(r.Context(), s.db, targetID, currentSession.CollaboratorID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if revoked == nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}

	// §A5/G1 + §13: bump metric, write audit, persist §13 revocation
	// row, dispatch RFC 8417 back-channel logout to every OIDC client
	// linked to this session.
	metrics.IncAuthSessionRevoked()
	s.recordAuthAuditCollaborator(r, AuditAuthSessionRevoked, currentSession.CollaboratorID, AuditOutcomeSuccess, map[string]any{
		"session_id": targetID.String(),
		"reason":     "self_service_revoke",
	})
	jti := targetID
	s.recordSessionRevocation(r, currentSession.CollaboratorID, &jti, repository.SessionRevocationReasonLogout, map[string]any{
		"source_ip":     clientIP(r),
		"user_agent":    r.UserAgent(),
		"revoke_origin": "self_service",
	})
	s.dispatchBackchannelLogoutForSession(r.Context(), targetID)

	w.WriteHeader(http.StatusNoContent)
}
