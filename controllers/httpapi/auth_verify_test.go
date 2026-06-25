package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// GET /api/v1/auth/verify is the target of the Traefik ForwardAuth middleware
// that guards the operator/AI surfaces (/s/*). Contract:
//   - anonymous request          → 401 (so ForwardAuth blocks the surface),
//   - authenticated human        → 200 + X-Auth-Kind: human + identity headers,
//   - authenticated system token → 200 + X-Auth-Kind: system, no identity headers.
//
// X-Auth-Kind makes the three states distinguishable upstream: a surface that
// receives a 200 but NO X-Auth-* header at all is looking at a ForwardAuth
// misconfiguration (the middleware forgot to copy the headers) and must
// fail closed, instead of mistaking it for a privileged identity.

// After Task 1, /api/v1/auth/verify is NO LONGER in the console gate
// allowlist — it self-gates inside handleAuthVerify. This asserts the gate
// passes the path straight through (the handler, not the gate, decides 200/401).
func TestAuthVerify_NotInConsoleGateAllowlist(t *testing.T) {
	if requiresAuthenticatedConsoleAPI("/api/v1/auth/verify") {
		t.Fatal("/api/v1/auth/verify must NOT be gated by requireAuthenticatedConsoleAPIs; handleAuthVerify self-gates")
	}
}

func TestAuthVerify_SurfacesIdentityHeaders(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify", nil)
	r = r.WithContext(contextWithClaims(r.Context(), map[string]any{
		"sub":             "collab-123",
		"collaborator_id": "collab-123",
		"session_id":      "sess-abc",
	}))
	w := httptest.NewRecorder()

	s.handleAuthVerify(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("authenticated verify: got %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-Kind"); got != "human" {
		t.Errorf("X-Auth-Kind: got %q, want %q", got, "human")
	}
	if got := w.Header().Get("X-Auth-Subject"); got != "collab-123" {
		t.Errorf("X-Auth-Subject: got %q, want %q", got, "collab-123")
	}
	if got := w.Header().Get("X-Auth-Collaborator-Id"); got != "collab-123" {
		t.Errorf("X-Auth-Collaborator-Id: got %q, want %q", got, "collab-123")
	}
	if got := w.Header().Get("X-Auth-Session-Id"); got != "sess-abc" {
		t.Errorf("X-Auth-Session-Id: got %q, want %q", got, "sess-abc")
	}
}

// No claims on the context (e.g. the shared workflow-run-token path, which the
// gate authenticates without attaching a collaborator) → still 200, but tagged
// system with no identity headers. This calls the handler directly; the gate
// integration of the same path is covered by TestAuthVerify_GateAcceptsWorkflowRunToken.
func TestAuthVerify_NoClaimsEmitsSystemKind(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify", nil)
	w := httptest.NewRecorder()

	s.handleAuthVerify(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("system verify: got %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-Kind"); got != "system" {
		t.Errorf("X-Auth-Kind: got %q, want %q", got, "system")
	}
	for _, h := range []string{"X-Auth-Subject", "X-Auth-Collaborator-Id", "X-Auth-Session-Id"} {
		if got := w.Header().Get(h); got != "" {
			t.Errorf("%s should be empty for system token, got %q", h, got)
		}
	}
}

// Exercises the REAL gate path: a request carrying the shared workflow-run
// token authenticates at requireAuthenticatedConsoleAPIs without claims, so the
// verify handler answers 200 + X-Auth-Kind: system with no identity headers.
func TestAuthVerify_GateAcceptsWorkflowRunToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "s3cr3t-run-token")
	s := &Server{}
	gated := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(s.handleAuthVerify))

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify", nil)
	r.Header.Set("X-Yggdrasil-Workflow-Token", "s3cr3t-run-token")
	w := httptest.NewRecorder()
	gated.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("workflow-run-token verify: got %d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-Kind"); got != "system" {
		t.Errorf("X-Auth-Kind: got %q, want %q", got, "system")
	}
	if got := w.Header().Get("X-Auth-Subject"); got != "" {
		t.Errorf("X-Auth-Subject should be empty for system token, got %q", got)
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
