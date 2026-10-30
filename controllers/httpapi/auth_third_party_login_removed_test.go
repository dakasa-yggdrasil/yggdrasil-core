package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"go.uber.org/zap"
)

// bootThirdPartyRouteServer boots the real router (every middleware and the
// full mux) over sqlmock, so a request that reaches the database without a
// matching expectation fails loudly.
func bootThirdPartyRouteServer(t *testing.T) (http.Handler, sqlmock.Sqlmock) {
	t.Helper()
	clearMachineCredentialEnv(t)
	t.Setenv("YGGDRASIL_ENV", "test")
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")
	t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("boot real server: %v", err)
	}
	return handler, mock
}

// ADR-0088: POST /api/v1/auth/third-party/login opened a session from a
// provider, subject and email taken from the request body, and with
// auto_link_by_email it linked any active collaborator by e-mail. The route
// is gone: every method and spelling falls through to the mux, which answers
// 404 or 405 without reading the database or setting a cookie.
func TestThirdPartyIdentityExchangeRouteIsRemoved(t *testing.T) {
	handler, mock := bootThirdPartyRouteServer(t)
	autoLinkBody := `{"provider":"google","subject":"100000000000000000001","email":"someone@example.test","auto_link_by_email":true}`
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodPut} {
		for _, target := range []string{
			"/api/v1/auth/third-party/login",
			"/api/v1/auth/third-party/login/",
			"/api/v1/auth/third-party/login?provider=google",
			"/api/v1/auth/third-party%2Flogin",
		} {
			t.Run(method+" "+target, func(t *testing.T) {
				req := httptest.NewRequest(method, target, strings.NewReader(autoLinkBody))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
					t.Fatalf("status=%d body=%s, want 404 or 405", rec.Code, rec.Body.String())
				}
				if cookies := rec.Result().Cookies(); len(cookies) != 0 {
					t.Fatalf("removed route set cookies: %v", cookies)
				}
				if strings.Contains(rec.Body.String(), `"token"`) {
					t.Fatalf("removed route answered a token: %s", rec.Body.String())
				}
			})
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The browser flow stays mounted: start and callback still reach their
// handlers, which resolve the provider from the database before anything
// else, and start keeps refusing unknown query parameters before any
// database work.
func TestThirdPartyBrowserLoginRoutesStayMounted(t *testing.T) {
	t.Run("start_rejects_unknown_query_before_the_database", func(t *testing.T) {
		handler, mock := bootThirdPartyRouteServer(t)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/third-party/start/google?bypass_state=1", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "input.unknown_fields") {
			t.Fatalf("status=%d body=%s, want 400 input.unknown_fields", rec.Code, rec.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	for _, target := range []string{
		"/api/v1/auth/third-party/start/google",
		"/api/v1/auth/third-party/callback/google?code=abc&state=xyz",
	} {
		t.Run("resolves_provider "+target, func(t *testing.T) {
			handler, mock := bootThirdPartyRouteServer(t)
			mock.ExpectQuery(`FROM public\.auth_third_party_providers`).
				WillReturnError(errors.New("provider store unavailable"))
			req := httptest.NewRequest(http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
				t.Fatalf("browser route is not mounted: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("handler did not resolve the provider first: %v", err)
			}
			for _, cookie := range rec.Result().Cookies() {
				if cookie.Name == authSessionCookieName() && cookie.Value != "" {
					t.Fatalf("failed provider resolution set a session cookie")
				}
			}
		})
	}
}
