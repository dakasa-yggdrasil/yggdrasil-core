package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeJWTVerifier returns a fixed claims map when token matches
// validForToken; otherwise returns errInvalid. Suitable for stubbing the
// JWT verifier in middleware unit tests.
type fakeJWTVerifier struct {
	validForToken string
	claims        map[string]any
}

var errInvalidFakeToken = errors.New("invalid token")

func (f fakeJWTVerifier) Verify(_ context.Context, token string) (map[string]any, error) {
	if token != f.validForToken {
		return nil, errInvalidFakeToken
	}
	if f.claims != nil {
		return f.claims, nil
	}
	return map[string]any{"sub": "test-subject"}, nil
}

func TestBearerOrSession_AcceptsBearer(t *testing.T) {
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "valid-jwt"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	r.Header.Set("Authorization", "Bearer valid-jwt")
	w := httptest.NewRecorder()

	called := false
	var receivedClaims map[string]any
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		receivedClaims, _ = claimsFromContext(r.Context())
	}))
	handler.ServeHTTP(w, r)

	if !called {
		t.Errorf("expected next handler invoked for valid bearer (status=%d)", w.Code)
	}
	if receivedClaims == nil || receivedClaims["sub"] != "test-subject" {
		t.Errorf("claims not attached to context: %v", receivedClaims)
	}
}

func TestBearerOrSession_AcceptsSessionCookie(t *testing.T) {
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "cookie-jwt"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "cookie-jwt"})
	w := httptest.NewRecorder()

	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	handler.ServeHTTP(w, r)

	if !called {
		t.Errorf("expected next handler invoked for valid cookie (status=%d)", w.Code)
	}
}

func TestBearerOrSession_RejectsInvalidBearer(t *testing.T) {
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "valid"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()

	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	handler.ServeHTTP(w, r)

	if called {
		t.Error("next handler should not be invoked for invalid bearer")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestBearerOrSession_RejectsMissingCredentials(t *testing.T) {
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "valid"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	w := httptest.NewRecorder()

	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	handler.ServeHTTP(w, r)

	if called {
		t.Error("next handler should not be invoked without credentials")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestBearerOrSession_BearerTakesPrecedenceOverCookie(t *testing.T) {
	// Bearer is checked first; if it succeeds, the cookie is not consulted.
	// We verify by giving a valid bearer + an invalid cookie token: the
	// request should still succeed (proving cookie path was not taken).
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "bearer-good"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	r.Header.Set("Authorization", "Bearer bearer-good")
	r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "cookie-bad"})
	w := httptest.NewRecorder()

	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	handler.ServeHTTP(w, r)

	if !called {
		t.Errorf("bearer path should have authenticated; status=%d", w.Code)
	}
}

func TestBearerOrSession_FallsBackToCookieWhenBearerInvalid(t *testing.T) {
	// Invalid bearer + valid cookie → cookie path should authenticate.
	mw := bearerOrSession(fakeJWTVerifier{validForToken: "cookie-good"})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "cookie-good"})
	w := httptest.NewRecorder()

	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	handler.ServeHTTP(w, r)

	if !called {
		t.Errorf("cookie fallback should have authenticated; status=%d", w.Code)
	}
}

func TestRequireAuthenticatedConsoleAPIs_RejectsAnonymousConsoleAndOps(t *testing.T) {
	s := &Server{}
	handler := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler should not be called without a session")
	}))

	for _, path := range []string{
		"/api/v1/console/collaborators",
		"/api/v1/ops/workflows",
		"/api/v1/collaborators",
		"/api/v1/teams",
		"/api/v1/team-memberships",
	} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestRequireAuthenticatedConsoleAPIs_AllowsPublicAuthRoutes(t *testing.T) {
	s := &Server{}
	called := false
	handler := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if !called {
		t.Fatal("public auth route should pass through")
	}
}

func TestRequiresAuthenticatedConsoleRequestSeparatesPublicAndAdminAuthRoutes(t *testing.T) {
	for _, test := range []struct {
		method string
		path   string
		want   bool
	}{
		{method: http.MethodPost, path: "/api/v1/auth/login"},
		{method: http.MethodGet, path: "/api/v1/auth/providers"},
		{method: http.MethodPost, path: "/api/v1/auth/providers", want: true},
		{method: http.MethodDelete, path: "/api/v1/auth/providers/google", want: true},
		{method: http.MethodPost, path: "/api/v1/auth/third-party-identities", want: true},
		{method: http.MethodDelete, path: "/api/v1/auth/third-party-identities/google/sub", want: true},
		{method: http.MethodPost, path: "/api/v1/auth/scim/clients", want: true},
		{method: http.MethodPost, path: "/api/v1/auth/saml/service-providers", want: true},
		{method: http.MethodPost, path: "/api/v1/auth/saml/rotate-signing-cert", want: true},
	} {
		if got := requiresAuthenticatedConsoleRequest(test.method, test.path); got != test.want {
			t.Fatalf("%s %s protected=%v, want %v", test.method, test.path, got, test.want)
		}
	}
}
