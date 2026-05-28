package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
)

// TestTenantBrandPatch_RejectsAnonymous locks in the security-review
// fix from 2026-05-28: PATCH /api/v1/tenant/brand intentionally lives
// outside the requireAuthenticatedConsoleAPIs allowlist (the GET is
// public, fed by the pre-session LoginPage), so the handler MUST
// self-gate. A request that carries neither a session token nor the
// workflow-run-token has to receive 401 — not silently fall through
// with updatedBy=nil.
func TestTenantBrandPatch_RejectsAnonymous(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "test-workflow-token")

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	srv := &Server{db: db, logger: zap.NewNop()}

	r := httptest.NewRequest(http.MethodPatch, "/api/v1/tenant/brand",
		bytes.NewBufferString(`{"name":"Hacker","short_name":"H","product_label":"Y","locale":"pt-BR"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.handleTenantBrandPatch(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous PATCH must return 401, got %d (body=%s)",
			w.Code, w.Body.String())
	}
}

// TestTenantBrandPatch_AcceptsWorkflowRunToken proves the
// machine-credential path works when the request carries a verified
// X-Yggdrasil-Workflow-Token header that matches the configured value.
// updated_by is expected to stay nil (no human actor); the row write
// itself is intercepted by sqlmock so the test only exercises the auth
// gate, not the SQL contract.
func TestTenantBrandPatch_AcceptsWorkflowRunToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "test-workflow-token")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery(`INSERT INTO public\.tenant_brand_settings`).
		WillReturnRows(sqlmock.NewRows([]string{
			"name", "short_name", "product_label", "locale",
			"accent_override", "logo_url", "support_email",
			"integration_domain_catalog", "updated_by",
			"created_at", "updated_at",
		}).AddRow(
			"DaKasa", "DK", "Yggdrasil", "pt-BR",
			nil, nil, nil, []byte("[]"), nil,
			time.Now(), time.Now(),
		))

	srv := &Server{db: db, logger: zap.NewNop()}

	r := httptest.NewRequest(http.MethodPatch, "/api/v1/tenant/brand",
		bytes.NewBufferString(`{"name":"DaKasa","short_name":"DK","product_label":"Yggdrasil","locale":"pt-BR"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Yggdrasil-Workflow-Token", "test-workflow-token")
	w := httptest.NewRecorder()

	srv.handleTenantBrandPatch(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("workflow-token PATCH must return 200, got %d (body=%s)",
			w.Code, w.Body.String())
	}
}

// TestTenantBrandPatch_RejectsWrongWorkflowRunToken makes sure a
// non-matching token is treated the same as no token.
func TestTenantBrandPatch_RejectsWrongWorkflowRunToken(t *testing.T) {
	_ = os.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "expected-token")
	t.Cleanup(func() { _ = os.Unsetenv("YGGDRASIL_WORKFLOW_RUN_TOKEN") })

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	srv := &Server{db: db, logger: zap.NewNop()}

	r := httptest.NewRequest(http.MethodPatch, "/api/v1/tenant/brand",
		bytes.NewBufferString(`{"name":"Hacker","short_name":"H","product_label":"Y","locale":"pt-BR"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Yggdrasil-Workflow-Token", "wrong-token")
	w := httptest.NewRecorder()

	srv.handleTenantBrandPatch(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong workflow-token must return 401, got %d (body=%s)",
			w.Code, w.Body.String())
	}
}
