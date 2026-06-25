package httpapi

import "net/http"

// handleAuthVerify is the target of the Traefik ForwardAuth middleware that
// guards the operator/AI surfaces under /s/*. The request only reaches this
// handler after requireAuthenticatedConsoleAPIs has authenticated it (the
// path is in the gated allowlist) — an anonymous caller already received a
// 401 from the gate. So the job here is to surface the resolved identity to
// the ForwardAuth caller as response headers (Traefik copies the configured
// authResponseHeaders onto the upstream request) and answer 200.
//
// Three states, distinguishable upstream via X-Auth-Kind:
//   - human  → 200, X-Auth-Kind: human + X-Auth-Subject/-Collaborator-Id/-Session-Id
//     (a session cookie or an OP-issued JWT was resolved),
//   - system → 200, X-Auth-Kind: system, no identity headers
//     (the shared workflow-run token authenticated it; no human actor).
//
// A surface that gets a 200 with NO X-Auth-* header at all is looking at a
// ForwardAuth MISCONFIGURATION (the middleware did not copy the headers) and
// must fail closed rather than infer a privileged identity.
//
// SECURITY: every header value here comes ONLY from server-validated identity
// (a DB-resolved session or an RS256/iss/exp/aud-verified OP JWT, attached by
// the gate). This handler never reads inbound request headers, so a client
// cannot forge identity through this endpoint. Stripping any forged inbound
// X-Auth-* on the original /s/* request is the edge middleware's job
// (authResponseHeadersRegex "^X-Auth-" overwrites + strips). The route is
// GET-only by design — Traefik's ForwardAuth issues GET by default
// (preserveRequestMethod=false); the real method, if ever needed, arrives as
// X-Forwarded-Method.
func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	kind := "system" // authenticated, but no human actor (shared workflow-run token)
	if claims, ok := claimsFromContext(r.Context()); ok {
		if sub, _ := claims["sub"].(string); sub != "" {
			kind = "human"
			w.Header().Set("X-Auth-Subject", sub)
		}
		if cid, _ := claims["collaborator_id"].(string); cid != "" {
			w.Header().Set("X-Auth-Collaborator-Id", cid)
		}
		if sid, _ := claims["session_id"].(string); sid != "" {
			w.Header().Set("X-Auth-Session-Id", sid)
		}
	}
	w.Header().Set("X-Auth-Kind", kind)
	w.WriteHeader(http.StatusOK)
}
