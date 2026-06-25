package httpapi

import (
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// handleAuthVerify is the target of the Traefik ForwardAuth middleware that
// guards the operator/AI surfaces under /s/*. It is SELF-CONTAINED: it does its
// own authentication (it is NOT in the console gate allowlist), so a token
// scoped to a single surface audience can authenticate the núcleo without being
// accepted by the console gate (/api/v1/*).
//
// Two credential paths, in order:
//
//  1. Bearer JWT scoped to the expected audience. The expected audience comes
//     from the ?aud=<surface> query param, which the ForwardAuth middleware
//     hard-codes in its `address` (NOT client-controllable). The JWT itself is
//     cryptographically verified (RS256/iss/exp) and its `aud` claim must equal
//     ?aud. This is the path AI clients use (e.g. aud=dakasa-ai). Only attempted
//     when ?aud is present AND s.surfaceVerify is wired.
//  2. Session cookie (or X-Session-Token) → repository.ResolveAuthSession. Any
//     authenticated collaborator passes. This is the unchanged browser path.
//
// Anything else → 401, so ForwardAuth blocks the surface.
//
// Response on success: 200 + X-Auth-Kind (human|system) and, for a human,
// X-Auth-Subject/-Collaborator-Id/-Session-Id.
//
// SECURITY: every X-Auth-* value comes ONLY from server-validated identity (a
// DB-resolved session or an RS256/iss/exp/aud-verified OP JWT). This handler
// never reads inbound X-Auth-* request headers, so a client cannot forge
// identity. Stripping forged inbound X-Auth-* on the original /s/* request is
// the edge middleware's job (authResponseHeadersRegex "^X-Auth-"). GET-only by
// design — Traefik ForwardAuth issues GET (preserveRequestMethod=false).
func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	// Path 1: surface-scoped Bearer JWT.
	if expectedAud := r.URL.Query().Get("aud"); expectedAud != "" && s.surfaceVerify != nil {
		if claims, ok := s.tryBearerForAudience(r, expectedAud); ok {
			writeVerifyIdentity(w, claims)
			return
		}
	}

	// Path 2: session cookie / X-Session-Token (any authenticated collaborator).
	if token, ok := extractAuthToken(r); ok && s.db != nil {
		session, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
		if err == nil {
			writeVerifyIdentity(w, map[string]any{
				"sub":             collaborator.ID.String(),
				"collaborator_id": collaborator.ID.String(),
				"session_id":      session.ID.String(),
			})
			return
		}
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// tryBearerForAudience extracts the Bearer token and validates it against the
// expected audience via the wired surface verifier. Returns (claims, true) on
// success; (nil, false) when there is no Bearer or it fails verification.
func (s *Server) tryBearerForAudience(r *http.Request, expectedAud string) (map[string]any, bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return nil, false
	}
	token := strings.TrimSpace(h[7:])
	if token == "" {
		return nil, false
	}
	claims, err := s.surfaceVerify(r.Context(), token, expectedAud)
	if err != nil {
		return nil, false
	}
	return claims, true
}

// writeVerifyIdentity surfaces the resolved identity as X-Auth-* response
// headers and answers 200. A human is anyone with a non-empty sub; otherwise
// the request is tagged system with no identity headers. Mirrors the original
// contract so upstream surfaces stay unchanged.
func writeVerifyIdentity(w http.ResponseWriter, claims map[string]any) {
	kind := "system"
	if sub, _ := claims["sub"].(string); sub != "" {
		kind = "human"
		w.Header().Set("X-Auth-Subject", sub)
	}
	if cid, _ := claims["collaborator_id"].(string); cid != "" {
		w.Header().Set("X-Auth-Collaborator-Id", cid)
	}
	// session_id may arrive as "session_id" (cookie path) or "sid" (OP JWT).
	if sid, _ := claims["session_id"].(string); sid != "" {
		w.Header().Set("X-Auth-Session-Id", sid)
	} else if sid, _ := claims["sid"].(string); sid != "" {
		w.Header().Set("X-Auth-Session-Id", sid)
	}
	w.Header().Set("X-Auth-Kind", kind)
	w.WriteHeader(http.StatusOK)
}
