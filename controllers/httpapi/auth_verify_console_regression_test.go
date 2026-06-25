package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The privilege boundary: a token scoped to the surface audience (dakasa-ai)
// must NOT authenticate the console gate. The console gate only consults
// consoleJWTVerifier (a boot-time allowlist that excludes dakasa-ai) and the
// session/workflow-token paths — never surfaceVerify. With no consoleJWTVerifier
// configured (default) and no session, a Bearer to a gated path is rejected.
func TestConsoleGate_RejectsSurfaceAudienceToken(t *testing.T) {
	s := &Server{}
	// Even if the surface verifier WOULD accept this token for aud=dakasa-ai,
	// it is never invoked by the console gate. Wire it to prove that.
	s.surfaceVerify = func(_ context.Context, _, _ string) (map[string]any, error) {
		return map[string]any{"sub": "collab-1", "aud": "dakasa-ai"}, nil
	}

	gated := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("console handler must not be reached by a surface-audience token")
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/v1/ops/workflows", nil)
	r.Header.Set("Authorization", "Bearer dakasa-ai-scoped-token")
	w := httptest.NewRecorder()
	gated.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("surface token on console path: got %d, want 401", w.Code)
	}
}
