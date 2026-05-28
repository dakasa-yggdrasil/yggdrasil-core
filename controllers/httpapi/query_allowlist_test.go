package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Audit 2026-05-27 A15: sensitive endpoints MUST reject unknown query
// params with 400 input.unknown_fields so the surface humanizer can
// localize. Allowed params pass through cleanly.

func TestRejectUnknownQueryParams_AllowedPasses(t *testing.T) {
	r := httptest.NewRequest("GET", "/test?collaborator_id=abc&provider=google", nil)
	w := httptest.NewRecorder()
	ok := rejectUnknownQueryParams(w, r, "collaborator_id", "provider", "status")
	if !ok {
		t.Fatalf("expected true (passes), got false (rejected). Response: %s", w.Body.String())
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 (default OK from recorder), got %d", w.Code)
	}
}

func TestRejectUnknownQueryParams_UnknownRejected(t *testing.T) {
	r := httptest.NewRequest("GET", "/test?debug=true", nil)
	w := httptest.NewRecorder()
	ok := rejectUnknownQueryParams(w, r, "collaborator_id", "provider", "status")
	if ok {
		t.Fatal("expected false (rejected), got true")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("expected Content-Type application/problem+json, got %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body must be JSON: %v", err)
	}
	if body["code"] != "input.unknown_fields" {
		t.Fatalf("expected code=input.unknown_fields, got %v", body["code"])
	}
	// Important: the attacker MUST NOT learn which param name was rejected.
	if strings.Contains(w.Body.String(), "debug") {
		t.Fatal("response must NOT echo the rejected param name (probe-resistance)")
	}
}

func TestRejectUnknownQueryParams_EmptyQueryPasses(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	ok := rejectUnknownQueryParams(w, r, "collaborator_id")
	if !ok {
		t.Fatal("empty query string must pass even with strict allowlist")
	}
}

func TestRejectUnknownQueryParams_MixedAllowedAndUnknownRejects(t *testing.T) {
	// One known param + one unknown — must reject (any unknown is unsafe).
	r := httptest.NewRequest("GET", "/test?provider=google&bypass_mfa=1", nil)
	w := httptest.NewRecorder()
	ok := rejectUnknownQueryParams(w, r, "provider")
	if ok {
		t.Fatal("any unknown param must reject the whole request")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRejectUnknownQueryParams_EmptyAllowlistRejectsAnyParam(t *testing.T) {
	r := httptest.NewRequest("GET", "/test?anything=x", nil)
	w := httptest.NewRecorder()
	ok := rejectUnknownQueryParams(w, r)
	if ok {
		t.Fatal("empty allowlist must reject any provided param")
	}
}
