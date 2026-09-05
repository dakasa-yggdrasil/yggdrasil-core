package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"go.uber.org/zap"
)

// TestTenantBrandPatch_RejectsAnonymous locks in the security-review
// fix from 2026-05-28: PATCH /api/v1/tenant/brand intentionally lives
// outside the requireAuthenticatedConsoleAPIs allowlist (the GET is
// public, fed by the pre-session LoginPage), so the handler MUST
// self-gate. A request without a valid session has to receive 401 — not
// silently fall through with updatedBy=nil.
func TestTenantBrandPatch_RejectsAnonymous(t *testing.T) {
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

// Workflow credentials are dispatch-only and cannot mutate tenant settings.
func TestTenantBrandPatch_RejectsValidLegacyWorkflowRunToken(t *testing.T) {
	setTestLegacyWorkflowCredential(t, "test-workflow-token")

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	srv := &Server{db: db, logger: zap.NewNop()}

	r := httptest.NewRequest(http.MethodPatch, "/api/v1/tenant/brand",
		bytes.NewBufferString(`{"name":"DaKasa","short_name":"DK","product_label":"Yggdrasil","locale":"pt-BR"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Yggdrasil-Workflow-Token", "test-workflow-token")
	w := httptest.NewRecorder()

	srv.handleTenantBrandPatch(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("workflow-token PATCH must return 401, got %d (body=%s)",
			w.Code, w.Body.String())
	}
}

// TestTenantBrandPatch_RejectsWrongWorkflowRunToken makes sure an unrelated
// static bearer is treated the same as no session.
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
