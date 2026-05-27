package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleManifestCreate_AuthRequired guards the audited critical hole:
// POST /api/v1/manifests must refuse anonymous writes when the workflow
// run token is configured (the canonical production posture).
//
// Audit ref: reference_yggdrasil_dakasa_me_deep_audit_2026_05_27.md A1
// — "POST /api/v1/manifests is unauthenticated".
func TestHandleManifestCreateGeneric_AuthRequired(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "secret-token")
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/manifests", server.handleManifestCreateGeneric)

	body := bytes.NewBufferString(`{"name":"x","namespace":"y","spec":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=workflow", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST status: got %d, want %d (body=%s)", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}

// TestHandleManifestCreateGeneric_RejectsWrongToken: a bearer token that
// doesn't match the configured value is rejected with 401.
func TestHandleManifestCreateGeneric_RejectsWrongToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "secret-token")
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/manifests", server.handleManifestCreateGeneric)

	body := bytes.NewBufferString(`{"name":"x","namespace":"y","spec":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=workflow", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Yggdrasil-Workflow-Token", "wrong")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token POST status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// TestHandleManifestCreateGeneric_AcceptsValidToken: a matching workflow
// run token gets PAST the auth gate. We submit a body that fails at the
// payload-validation stage (empty spec) so the response is 400 with
// "spec is required" — proving the auth check let it through without
// triggering the audit goroutine (s.db is nil in these tests).
func TestHandleManifestCreateGeneric_AcceptsValidToken(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "secret-token")
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/manifests", server.handleManifestCreateGeneric)

	// Empty spec → manifestDocumentFromPayload returns "spec is required"
	// before recordAudit runs (which would panic with nil db).
	body := bytes.NewBufferString(`{"name":"x","namespace":"y"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=workflow", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Yggdrasil-Workflow-Token", "secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Fatalf("valid token still got 401, expected pass-through: body=%s", w.Body.String())
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid payload after auth, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestHandleManifestCreateGeneric_AllowsOpenWhenTokenUnset preserves the
// developer/test convention: when YGGDRASIL_WORKFLOW_RUN_TOKEN is unset,
// the endpoint stays open. This matches the existing manifest DELETE
// + workflow-run + events handlers.
func TestHandleManifestCreateGeneric_AllowsOpenWhenTokenUnset(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/manifests", server.handleManifestCreateGeneric)

	body := bytes.NewBufferString(`{"name":"x","namespace":"y"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=workflow", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Fatalf("open-when-unset broken: got 401, expected pass-through (body=%s)", w.Body.String())
	}
}

// TestHandleManifestCreate_KindSpecific_AuthRequired: the kind-specific
// wrappers (handleProductCreate, handleSurfaceCreate, …) all funnel into
// handleManifestCreate. Auth-gating handleManifestCreate centrally MUST
// protect every kind-specific POST too. We pick handleProductCreate as a
// representative.
func TestHandleProductCreate_AuthRequired(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "secret-token")
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/products", server.handleProductCreate)

	body := bytes.NewBufferString(`{"name":"x","namespace":"y","spec":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/products", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous product POST status: got %d, want %d (body=%s)", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}
