package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TestComputeCSRFToken_Deterministic locks down the HMAC-binding contract:
// same session ID + same secret yields the same token. The SPA mirrors the
// returned value back to us; if this were non-deterministic the middleware
// couldn't recompute and compare without storing state.
func TestComputeCSRFToken_Deterministic(t *testing.T) {
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "test-secret-for-determinism")
	sessionID := uuid.MustParse("11111111-2222-3333-4444-555555555555")

	a := computeCSRFToken(sessionID)
	b := computeCSRFToken(sessionID)
	if a != b {
		t.Fatalf("CSRF token should be deterministic; got %q and %q", a, b)
	}
}

// TestComputeCSRFToken_PerSession proves different sessions get different
// tokens — otherwise a token leaked from one session would attack another.
func TestComputeCSRFToken_PerSession(t *testing.T) {
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "test-secret-per-session")
	s1 := uuid.MustParse("aaaaaaaa-1111-2222-3333-444444444444")
	s2 := uuid.MustParse("bbbbbbbb-1111-2222-3333-444444444444")

	if computeCSRFToken(s1) == computeCSRFToken(s2) {
		t.Fatalf("different session ids should produce different CSRF tokens")
	}
}

// TestComputeCSRFToken_SecretRotation: rotating the HMAC secret invalidates
// all outstanding CSRF tokens. Operators who suspect leaked tokens can
// rotate the secret to force every session to re-derive on next /auth/session.
func TestComputeCSRFToken_SecretRotation(t *testing.T) {
	sessionID := uuid.MustParse("11111111-2222-3333-4444-555555555555")

	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "old-secret")
	old := computeCSRFToken(sessionID)
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "new-secret")
	new := computeCSRFToken(sessionID)

	if old == new {
		t.Fatalf("rotating CSRF secret must change the token; both = %q", old)
	}
}

// TestCSRFEnforceMode_DefaultsToEnforce locks down fail-closed production
// behavior when the deployment omits the rollout switch.
func TestCSRFEnforceMode_DefaultsToEnforce(t *testing.T) {
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "")
	if got := csrfEnforceMode(); got != "enforce" {
		t.Fatalf("default mode: expected enforce, got %q", got)
	}
}

// TestCSRFEnforceMode_RespectsExplicitEnforce: production flips this once
// the FE rolls.
func TestCSRFEnforceMode_RespectsExplicitEnforce(t *testing.T) {
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	if got := csrfEnforceMode(); got != "enforce" {
		t.Fatalf("explicit enforce: expected enforce, got %q", got)
	}
}

// TestCSRFEnforceMode_GarbageDefaultsEnforce: typos cannot disable CSRF.
func TestCSRFEnforceMode_GarbageDefaultsEnforce(t *testing.T) {
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "panic")
	if got := csrfEnforceMode(); got != "enforce" {
		t.Fatalf("garbage mode should fall back to enforce, got %q", got)
	}
}

func TestCSRFEnforceMode_RespectsExplicitWarn(t *testing.T) {
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "warn")
	if got := csrfEnforceMode(); got != "warn" {
		t.Fatalf("explicit warn: expected warn, got %q", got)
	}
}

// TestCSRFMethodRequiresToken locks down the state-changing method set.
// GET / HEAD / OPTIONS are exempt; POST / PUT / DELETE / PATCH require
// the header. A future change that adds an HTTP verb (e.g. MOVE for
// WebDAV) will fall through this switch and skip CSRF — explicit so the
// test breaks on a regression.
func TestCSRFMethodRequiresToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method   string
		requires bool
	}{
		{"GET", false},
		{"HEAD", false},
		{"OPTIONS", false},
		{"POST", true},
		{"PUT", true},
		{"DELETE", true},
		{"PATCH", true},
		// Case-insensitive for completeness; go stdlib uppercases methods
		// but defensive equality protects against handlers that don't.
		{"post", true},
		{"get", false},
	}
	for _, c := range cases {
		got := csrfMethodRequiresToken(c.method)
		if got != c.requires {
			t.Errorf("method %q: expected requires=%v, got %v", c.method, c.requires, got)
		}
	}
}

// TestCSRFPathExempt covers the exemption allowlist. Machine-token callers
// bypass by identity, not URL, so dual-auth routes stay protected. A regression here
// would either 403-storm legitimate automation (false positive) or open
// a CSRF hole in the SPA-routed endpoints (false negative).
func TestCSRFPathExempt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path   string
		exempt bool
	}{
		// Login/logout/setup flows have no session yet.
		{"/api/v1/auth/login", true},
		{"/api/v1/auth/logout", true},
		{"/api/v1/auth/passwords/setup-tokens", true},
		{"/api/v1/auth/passwords/setup", true},
		{"/api/v1/auth/passwords/reset", true},
		{"/api/v1/auth/passwords/forgot", true},
		{"/api/v1/auth/mfa/enroll/request", true},
		// Webhook automation stays exempt; dual-auth routes do not.
		{"/api/v1/workflow-runs", false},
		{"/api/v1/manifests", false},
		{"/api/v1/events", false},
		{"/api/v1/github/webhook", true},
		{"/api/v1/admin/collaborators/abc/revoke-sessions", false},
		// SAML SP-initiated POSTs are cross-site by spec.
		{"/saml/sso", true},
		{"/saml/slo", true},
		// SPA-routed mutations are NOT exempt.
		{"/api/v1/console/integration-instances", false},
		{"/api/v1/me/preferences", false},
		{"/api/v1/teams", false},
		{"/api/v1/team-memberships", false},
		{"/api/v1/collaborators", false},
		{"/api/v1/console/collaborators", false},
		{"/api/v1/me/sessions/abc", false},
	}
	for _, c := range cases {
		got := csrfPathExempt(c.path)
		if got != c.exempt {
			t.Errorf("path %q: expected exempt=%v, got %v", c.path, c.exempt, got)
		}
	}
}

// TestCSRFMiddleware_GETNeverChecked: GET requests pass through even
// without a header. Otherwise every page load would 403.
func TestCSRFMiddleware_GETNeverChecked(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "csrf-get-test")

	srv := &Server{logger: zap.NewNop()}
	called := false
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/console/collaborators", nil)
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
		"session_id": uuid.NewString(),
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Fatalf("GET should pass through CSRF middleware")
	}
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("GET status: expected 200, got %d", w.Result().StatusCode)
	}
}

// TestCSRFMiddleware_POSTMissingTokenEnforce: enforce-mode rejects a
// missing X-CSRF-Token with 403 + Problem+JSON.
func TestCSRFMiddleware_POSTMissingTokenEnforce(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "csrf-missing-enforce")

	srv := &Server{logger: zap.NewNop()}
	called := false
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/console/integration-instances", strings.NewReader(`{}`))
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
		"session_id": uuid.NewString(),
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Fatalf("handler should NOT be called when CSRF rejects in enforce mode")
	}
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("missing token in enforce: expected 403, got %d", w.Result().StatusCode)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("missing token: expected problem+json, got %q", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if code, _ := body["code"].(string); code != "csrf.missing_token" {
		t.Fatalf("expected code=csrf.missing_token, got %q", code)
	}
}

// TestCSRFMiddleware_POSTBadTokenEnforce: enforce-mode rejects a
// mismatched X-CSRF-Token with 403 + token_mismatch code.
func TestCSRFMiddleware_POSTBadTokenEnforce(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "csrf-bad-enforce")

	srv := &Server{logger: zap.NewNop()}
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called when CSRF rejects")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/preferences", strings.NewReader(`{}`))
	req.Header.Set(csrfHeaderName, "not-the-real-token")
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
		"session_id": uuid.NewString(),
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("bad token in enforce: expected 403, got %d", w.Result().StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if code, _ := body["code"].(string); code != "csrf.token_mismatch" {
		t.Fatalf("expected code=csrf.token_mismatch, got %q", code)
	}
}

// TestCSRFMiddleware_POSTValidTokenAllowed: a correctly computed token
// passes through, the handler runs, and no metric is bumped.
func TestCSRFMiddleware_POSTValidTokenAllowed(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "csrf-valid")

	srv := &Server{logger: zap.NewNop()}
	called := false
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	sessionID := uuid.New()
	token := computeCSRFToken(sessionID)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/console/teams", strings.NewReader(`{}`))
	req.Header.Set(csrfHeaderName, token)
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
		"session_id": sessionID.String(),
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Fatalf("handler should be called on valid token")
	}
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("valid token: expected 200, got %d", w.Result().StatusCode)
	}

	snap := metrics.CSRFRejectedSnapshot()
	for k, v := range snap {
		if v != 0 {
			t.Errorf("metric %s should be 0 on a valid request, got %d", k, v)
		}
	}
}

// TestCSRFMiddleware_POSTMissingTokenWarn: warn-mode logs + bumps the
// metric but still passes the request through. This is the rollout
// window during which surface-console catches up.
func TestCSRFMiddleware_POSTMissingTokenWarn(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "warn")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "csrf-warn")

	srv := &Server{logger: zap.NewNop()}
	called := false
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/preferences", strings.NewReader(`{}`))
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
		"session_id": uuid.NewString(),
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Fatalf("warn mode must let the request through even without a token")
	}
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("warn mode passthrough: expected 200, got %d", w.Result().StatusCode)
	}

	snap := metrics.CSRFRejectedSnapshot()
	if got := snap[metrics.CSRFRejectedMissingToken+"|"+metrics.CSRFModeWarn]; got != 1 {
		t.Errorf("warn-mode missing_token counter: expected 1, got %d", got)
	}
}

// TestCSRFMiddleware_ExemptPathPassesEnforce covers only genuinely public or
// cross-site endpoints. Machine callers bypass by authenticated identity.
func TestCSRFMiddleware_ExemptPathPassesEnforce(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")
	t.Setenv("YGGDRASIL_CSRF_HMAC_SECRET", "csrf-exempt")

	srv := &Server{logger: zap.NewNop()}
	called := false
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	for _, path := range []string{
		"/api/v1/auth/login",
		"/api/v1/github/webhook",
		"/saml/sso",
	} {
		called = false
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req = req.WithContext(contextWithClaims(req.Context(), map[string]any{
			"session_id": uuid.NewString(),
		}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if !called {
			t.Errorf("exempt path %q should pass through CSRF middleware in enforce mode", path)
		}
	}
}

func TestCSRFMiddleware_SessionWorkflowRunRequiresToken(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")

	srv := &Server{logger: zap.NewNop()}
	handler := srv.csrfMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("session-authenticated workflow dispatch must not bypass CSRF by URL")
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", strings.NewReader(`{}`))
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{"session_id": uuid.NewString()}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("session workflow run without CSRF token: expected 403, got %d", w.Code)
	}
}

func TestCSRFMiddleware_VerifiedBearerPassesWithoutSessionToken(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")

	srv := &Server{logger: zap.NewNop()}
	called := false
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", strings.NewReader(`{}`))
	ctx := contextWithClaims(req.Context(), map[string]any{"collaborator_id": uuid.NewString()})
	req = req.WithContext(contextWithCSRFBearerAuth(ctx))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("verified bearer should bypass cookie CSRF; called=%v status=%d", called, w.Code)
	}
}

func TestCSRFMiddleware_InvalidSessionFailsClosed(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")

	srv := &Server{logger: zap.NewNop()}
	handler := srv.csrfMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid session identity must fail closed")
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/preferences", strings.NewReader(`{}`))
	req = req.WithContext(contextWithClaims(req.Context(), map[string]any{"session_id": "not-a-uuid"}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("invalid session: expected 403, got %d", w.Code)
	}
	if got := metrics.CSRFRejectedSnapshot()[metrics.CSRFRejectedInvalidSession+"|"+metrics.CSRFModeEnforce]; got != 1 {
		t.Fatalf("invalid_session metric: expected 1, got %d", got)
	}
}

// TestCSRFMiddleware_NoSessionPasses: requests without a session in the
// context (workflow_run_token paths) are passed through. The CSRF defense
// is for session-cookie-authenticated browser flows; bearer-token callers
// have their own auth surface.
func TestCSRFMiddleware_NoSessionPasses(t *testing.T) {
	metrics.ResetForTest()
	t.Setenv("YGGDRASIL_CSRF_ENFORCE", "enforce")

	srv := &Server{logger: zap.NewNop()}
	called := false
	handler := srv.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/preferences", strings.NewReader(`{}`))
	// No claims attached.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Fatalf("no-session request should pass through (bearer auth lives elsewhere)")
	}
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("no-session passthrough: expected 200, got %d", w.Result().StatusCode)
	}
}

// TestCSRFCookie_Default attributes — keys to lock down: Path=/,
// HttpOnly=false (the SPA must read it), Secure tracks the session
// cookie's Secure flag.
func TestCSRFCookie_Default(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SECURE", "true")
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "Strict")
	w := httptest.NewRecorder()
	writeCSRFCookie(w, "abc", time.Now().Add(time.Hour))
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != csrfTokenCookieName {
		t.Errorf("cookie name: expected %q, got %q", csrfTokenCookieName, c.Name)
	}
	if c.HttpOnly {
		t.Errorf("CSRF cookie must NOT be HttpOnly (SPA reads it)")
	}
	if c.Path != "/" {
		t.Errorf("CSRF cookie path: expected /, got %q", c.Path)
	}
	if !c.Secure {
		t.Errorf("CSRF cookie should track session cookie Secure flag; expected Secure=true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("CSRF cookie SameSite: expected Strict, got %v", c.SameSite)
	}
}
