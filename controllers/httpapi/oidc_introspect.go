// Package httpapi — RFC 7662 OAuth 2.0 Token Introspection endpoint.
//
// §13 INTEGRATION_CONTRACT lists introspection as the fallback path for
// legacy OIDC consumers that can't be modified to support RFC 8417
// back-channel logout. Consumers SHOULD call this on every request (with
// a ≤30s cache) — accepting some staleness in exchange for not requiring
// back-channel.
//
// Wire shape per RFC 7662 §2.1:
//
//	POST /api/v1/oidc/introspect
//	Authorization: Bearer <auth-admin-or-console-token>
//	Content-Type: application/x-www-form-urlencoded
//
//	token=<opaque-or-jwt-token>
//
// Response per RFC 7662 §2.2 — `active` ALWAYS present, additional claims
// only when active=true:
//
//	200 OK
//	Content-Type: application/json
//
//	{"active": true,  "sub": "...", "iat": 1234567890, "exp": ..., "client_id": "..."}
//	or
//	{"active": false}
package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// introspectResponse is the active claim set serialized per RFC 7662 §2.2.
// Field order in JSON output matches the spec to ease debugging.
type introspectResponse struct {
	Active    bool   `json:"active"`
	Subject   string `json:"sub,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// handleOIDCIntrospect implements RFC 7662 against:
//   - opaque yggdrasil session tokens (auth_sessions table — looked up by hash)
//   - OIDC opaque refresh tokens (oidc_refresh_tokens table)
//
// Stateless JWT access tokens are NOT introspected here: callers who hold
// a JWT can use it directly; revocation is enforced by the
// session_revocation lookup once a (collaborator, jti) pair is supplied.
// Future enhancement: parse the JWT, extract sub+jti+iat, and use
// IsSessionRevoked to test against §13 revocations.
//
// Authorization: requires the dedicated auth-admin credential or a console
// identity with a real admin capability. Workflow machine credentials are
// dispatch-only and never authorize introspection. RFC 7662 §2.1 requires the
// resource server to authenticate to the AS.
func (s *Server) handleOIDCIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r, s.db); err != nil {
		// Per RFC 7662 §2.3 the AS MUST NOT echo token validity to
		// unauthenticated callers (would leak token-state info to
		// anyone with the raw token). Emit a proper 401 not a 200
		// {active: false}.
		writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid form body")
		return
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	if token == "" {
		// RFC 7662 §2.2: no token → 200 with {active: false} is acceptable
		// (the spec wants resource servers to treat unknown tokens as
		// inactive). Matches the inactive response shape.
		writeJSON(w, http.StatusOK, introspectResponse{Active: false})
		return
	}
	// `token_type_hint` is advisory per RFC 7662 §2.1 — we IGNORE it and
	// try both lookups in turn. The spec allows the AS to use the hint as
	// a perf hint only; correctness comes from exhaustive lookup.

	if resp, ok := s.introspectSessionToken(r.Context(), token); ok {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if resp, ok := s.introspectRefreshToken(r.Context(), token); ok {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Inactive — token doesn't match any known credential.
	writeJSON(w, http.StatusOK, introspectResponse{Active: false})
}

// introspectSessionToken treats the supplied token as an opaque
// yggdrasil session token (cookie value) and resolves it against
// auth_sessions, then runs the §13 revocation check.
func (s *Server) introspectSessionToken(ctx context.Context, token string) (introspectResponse, bool) {
	session, collab, err := repository.ResolveAuthSession(ctx, s.db, token)
	if err != nil {
		return introspectResponse{}, false
	}
	if session.RevokedAt != nil {
		return introspectResponse{Active: false}, true
	}
	if !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(time.Now().UTC()) {
		return introspectResponse{Active: false}, true
	}

	// §13: a global revocation row inserted AFTER session creation
	// invalidates the token even though the session row itself is still
	// live. The session_revocation lookup is the central authority.
	revoked, err := repository.IsSessionRevoked(ctx, s.db, collab.ID, ptrUUID(session.ID), session.CreatedAt)
	if err == nil && revoked {
		return introspectResponse{Active: false}, true
	}

	return introspectResponse{
		Active:    true,
		Subject:   collab.ID.String(),
		IssuedAt:  session.CreatedAt.Unix(),
		ExpiresAt: session.ExpiresAt.Unix(),
		TokenType: "session",
	}, true
}

// introspectRefreshToken treats the supplied token as an OIDC refresh
// token. Reuses the existing oidc_refresh_tokens record — including the
// revoke chain semantics inherited from the OP storage layer.
func (s *Server) introspectRefreshToken(ctx context.Context, token string) (introspectResponse, bool) {
	r, err := repository.GetOIDCRefreshToken(ctx, s.db, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return introspectResponse{Active: false}, false
		}
		return introspectResponse{Active: false}, false
	}
	if r.RevokedAt != nil {
		return introspectResponse{Active: false}, true
	}
	if !r.ExpiresAt.IsZero() && r.ExpiresAt.Before(time.Now().UTC()) {
		return introspectResponse{Active: false}, true
	}
	// §13 global revocation overlay on OIDC refresh chains: when an admin
	// revoke / password rotation inserts a global revocation row for the
	// collaborator after the refresh token was issued, the refresh row is
	// effectively dead too. Mirrors the back-channel logout semantics.
	revoked, err := repository.IsSessionRevoked(ctx, s.db, r.CollaboratorID, nil, r.CreatedAt)
	if err == nil && revoked {
		return introspectResponse{Active: false}, true
	}

	return introspectResponse{
		Active:    true,
		Subject:   r.CollaboratorID.String(),
		IssuedAt:  r.CreatedAt.Unix(),
		ExpiresAt: r.ExpiresAt.Unix(),
		ClientID:  r.ClientID,
		TokenType: "refresh",
	}, true
}

// ptrUUID is a tiny helper so the IsSessionRevoked call site reads
// cleanly — Go has no `&uuid.UUID{...}` shorthand for value receivers.
func ptrUUID(u uuid.UUID) *uuid.UUID {
	return &u
}
