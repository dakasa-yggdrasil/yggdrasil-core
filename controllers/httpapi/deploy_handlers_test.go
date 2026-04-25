package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestHandleDeployProductReturns410(t *testing.T) {
	server := &Server{logger: zap.NewNop()}
	r := httptest.NewRequest("POST", "/api/v1/products/dakasa/dakasa-app/deploy", nil)
	w := httptest.NewRecorder()
	server.handleDeployProduct(w, r)
	if w.Code != 410 {
		t.Fatalf("status: got %d want 410", w.Code)
	}
	if !strings.Contains(w.Body.String(), "deprecated in yggdrasil v2.0.0") {
		t.Fatalf("body should mention deprecation, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "repository_binding") {
		t.Fatalf("body should point at repository_binding replacement, got %s", w.Body.String())
	}
}

func TestHandleDeployAllReturns410(t *testing.T) {
	server := &Server{logger: zap.NewNop()}
	r := httptest.NewRequest("POST", "/api/v1/products/deploy-all", nil)
	w := httptest.NewRecorder()
	server.handleDeployAll(w, r)
	if w.Code != 410 {
		t.Fatalf("status: got %d want 410", w.Code)
	}
}

func TestHandleBootstrapReturns410(t *testing.T) {
	server := &Server{logger: zap.NewNop()}
	r := httptest.NewRequest("POST", "/api/v1/bootstrap", nil)
	w := httptest.NewRecorder()
	server.handleBootstrap(w, r)
	if w.Code != 410 {
		t.Fatalf("status: got %d want 410", w.Code)
	}
}
