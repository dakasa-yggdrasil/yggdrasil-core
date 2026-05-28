package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
)

// TestHandleAdminOIDCClientPatch_RequiresAuth: no admin token → 401.
// Defense in depth — same trust boundary as the other /api/v1/admin/*
// endpoints.
func TestHandleAdminOIDCClientPatch_RequiresAuth(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "admin-token-value")

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	srv := &Server{db: db, logger: zap.NewNop()}
	req := httptest.NewRequest("PATCH", "/api/v1/admin/oidc-clients/test-client", strings.NewReader(`{"access_token_lifetime_seconds":120}`))
	req.SetPathValue("id", "test-client")
	w := httptest.NewRecorder()
	srv.handleAdminOIDCClientPatch(w, req)

	if w.Result().StatusCode != 401 {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

// TestHandleAdminOIDCClientPatch_RejectsEmptyClientID — the path
// matcher would normally guarantee a non-empty id, but the handler
// defends anyway.
func TestHandleAdminOIDCClientPatch_RejectsEmptyClientID(t *testing.T) {
	t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "admin-token-value")

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	srv := &Server{db: db, logger: zap.NewNop()}
	req := httptest.NewRequest("PATCH", "/api/v1/admin/oidc-clients/", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer admin-token-value")
	w := httptest.NewRecorder()
	srv.handleAdminOIDCClientPatch(w, req)

	if w.Result().StatusCode == 200 {
		t.Fatalf("empty client id should NOT return 200, got %d body=%s", w.Result().StatusCode, w.Body.String())
	}
}
