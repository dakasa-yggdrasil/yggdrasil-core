package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// TestWriteMappedErrorEmitsProblemJSON asserts the §14 backward-compat
// invariant: writeMappedError produces an RFC 7807 envelope (Content-Type
// + `code` field) while ALSO preserving the legacy `error` field so
// existing surfaces don't break.
func TestWriteMappedErrorEmitsProblemJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMappedError(rec, repository.ErrAuthInvalidCredentials)

	if got, want := rec.Code, http.StatusUnauthorized; got != want {
		t.Errorf("status: got %d want %d", got, want)
	}
	if got, want := rec.Header().Get("Content-Type"), httperr.ContentType; got != want {
		t.Errorf("content-type: got %q want %q", got, want)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := body["code"]; got != httperr.CodeAuthInvalidCredentials {
		t.Errorf("code: got %v want %v", got, httperr.CodeAuthInvalidCredentials)
	}
	// Legacy `error` field MUST still be present for at least one
	// minor version per §14 migration note.
	if got, ok := body["error"].(string); !ok || got == "" {
		t.Errorf("legacy `error` key missing: got %v", body["error"])
	}
	if got := body["type"]; got == nil || !strings.HasPrefix(got.(string), httperr.TypePrefix) {
		t.Errorf("type: got %v want prefix %s", got, httperr.TypePrefix)
	}
	if got := body["title"]; got != "Unauthorized" {
		t.Errorf("title: got %v want Unauthorized", got)
	}
}

// TestWriteMappedErrorUnknownErrorDefaultsTo500 covers the fallback
// path: unknown errors still produce a §14 envelope with the internal
// code so frontends don't have to special-case anonymous failures.
func TestWriteMappedErrorUnknownErrorDefaultsTo500(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMappedError(rec, errors.New("boom"))

	if got, want := rec.Code, http.StatusInternalServerError; got != want {
		t.Errorf("status: got %d want %d", got, want)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := body["code"]; got != httperr.CodeInternal {
		t.Errorf("code: got %v want %v", got, httperr.CodeInternal)
	}
	if got := body["error"]; got != "boom" {
		t.Errorf("error: got %v want boom", got)
	}
}

// TestWriteMappedErrorAccountLockedMapsTo423 verifies the locked status
// keeps emitting 423 with the auth.account_locked code.
func TestWriteMappedErrorAccountLockedMapsTo423(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMappedError(rec, repository.ErrAuthAccountLocked)

	if rec.Code != http.StatusLocked {
		t.Errorf("status: got %d want 423", rec.Code)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != httperr.CodeAuthAccountLocked {
		t.Errorf("code: got %v want %v", body["code"], httperr.CodeAuthAccountLocked)
	}
}

// TestWriteJSONErrorEnvelope covers the str-only entry point used by
// many handlers — it should also emit the §14 shape.
func TestWriteJSONErrorEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONError(rec, http.StatusBadRequest, "missing field 'name'")

	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] == "" || body["code"] == nil {
		t.Errorf("code missing")
	}
	if body["error"] != "missing field 'name'" {
		t.Errorf("legacy error key missing: %v", body["error"])
	}
}
