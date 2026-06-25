package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// GET /api/v1/auth/verify is the target of the Traefik ForwardAuth middleware
// that guards the operator/AI surfaces (/s/*). It is SELF-CONTAINED (not in the
// console gate). Contract:
//   - no credential                        → 401 (ForwardAuth blocks the surface),
//   - Bearer JWT whose aud == ?aud          → 200 + X-Auth-Kind: human + identity,
//   - Bearer JWT whose aud != ?aud          → 401,
//   - valid session cookie (any collaborator) → 200 + X-Auth-Kind: human + identity.
//
// X-Auth-Kind lets a surface tell human from system; a 200 with NO X-Auth-*
// header at all means a ForwardAuth misconfiguration and the surface must fail
// closed.

// After Task 1, /api/v1/auth/verify is NO LONGER in the console gate
// allowlist — it self-gates inside handleAuthVerify. This asserts the gate
// passes the path straight through (the handler, not the gate, decides 200/401).
func TestAuthVerify_NotInConsoleGateAllowlist(t *testing.T) {
	if requiresAuthenticatedConsoleAPI("/api/v1/auth/verify") {
		t.Fatal("/api/v1/auth/verify must NOT be gated by requireAuthenticatedConsoleAPIs; handleAuthVerify self-gates")
	}
}

// With ?aud set + a valid Bearer for that audience, the self-contained handler
// answers 200 + human identity headers. Uses a fake surface verifier so the
// test is env- and DB-independent.
func TestAuthVerify_BearerAudienceMatch(t *testing.T) {
	s := &Server{surfaceJWTVerifier: nil} // replaced below via the seam
	s.surfaceVerify = func(_ context.Context, token, aud string) (map[string]any, error) {
		if token == "good-token" && aud == "dakasa-ai" {
			return map[string]any{"sub": "collab-9", "collaborator_id": "collab-9", "sid": "sess-x"}, nil
		}
		return nil, errInvalidFakeToken
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify?aud=dakasa-ai", nil)
	r.Header.Set("Authorization", "Bearer good-token")
	w := httptest.NewRecorder()
	s.handleAuthVerify(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("bearer aud-match: got %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-Kind"); got != "human" {
		t.Errorf("X-Auth-Kind: got %q, want human", got)
	}
	if got := w.Header().Get("X-Auth-Subject"); got != "collab-9" {
		t.Errorf("X-Auth-Subject: got %q, want collab-9", got)
	}
	if got := w.Header().Get("X-Auth-Session-Id"); got != "sess-x" {
		t.Errorf("X-Auth-Session-Id: got %q, want sess-x", got)
	}
}

func TestAuthVerify_BearerAudienceMismatch(t *testing.T) {
	s := &Server{}
	s.surfaceVerify = func(_ context.Context, token, aud string) (map[string]any, error) {
		return nil, errInvalidFakeToken // verifier rejects wrong audience
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify?aud=dakasa-ai", nil)
	r.Header.Set("Authorization", "Bearer wrong-aud-token")
	w := httptest.NewRecorder()
	s.handleAuthVerify(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bearer aud-mismatch: got %d, want 401", w.Code)
	}
}

func TestAuthVerify_NoCredential401(t *testing.T) {
	s := &Server{}
	s.surfaceVerify = func(_ context.Context, _, _ string) (map[string]any, error) {
		return nil, errInvalidFakeToken
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify?aud=dakasa-ai", nil)
	w := httptest.NewRecorder()
	s.handleAuthVerify(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no credential: got %d, want 401", w.Code)
	}
}
