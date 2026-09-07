package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleManifestCreate_AuthRequired guards the audited critical hole:
// POST /api/v1/manifests must refuse anonymous writes when machine auth is
// configured (the canonical production posture).
//
// Audit ref: reference_yggdrasil_dakasa_me_deep_audit_2026_05_27.md A1
// — "POST /api/v1/manifests is unauthenticated".
func TestHandleManifestCreateGeneric_AuthRequired(t *testing.T) {
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "machine-token", "ci",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))
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

// TestHandleManifestCreateGeneric_RejectsWrongToken: a bearer token that does
// not match any console session or route credential is rejected with 401.
func TestHandleManifestCreateGeneric_RejectsWrongToken(t *testing.T) {
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "machine-token", "ci",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))
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

// A workflow credential is never a manifest writer, even while the legacy
// workflow bridge is explicitly enabled and unexpired.
func TestHandleManifestCreateGeneric_RejectsValidLegacyWorkflowToken(t *testing.T) {
	setTestLegacyWorkflowCredential(t, "secret-token")
	server := &Server{serviceName: "yggdrasil-core-test", db: nil}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/manifests", server.handleManifestCreateGeneric)

	body := bytes.NewBufferString(`{"name":"x","namespace":"y"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/manifests?kind=workflow", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Yggdrasil-Workflow-Token", "secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("legacy workflow token escaped to manifest writes: status=%d body=%s", w.Code, w.Body.String())
	}
}

// TestHandleManifestCreateGeneric_AllowsOpenWhenTokenUnset preserves the
// direct-handler developer/test convention when every machine credential is
// unset. Server.New still places the real route behind console authentication.
func TestHandleManifestCreateGeneric_AllowsOpenWhenTokenUnset(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	t.Setenv(workflowMachinePrincipalsEnv, "")
	t.Setenv(legacyScopedWorkflowTokensEnv, "")
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
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "machine-token", "ci",
		machineWorkflowRef{Namespace: "dakasa", Name: "deploy"}))
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
