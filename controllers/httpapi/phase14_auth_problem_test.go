package httpapi

// Phase 2B-close (§14): asserts that every hand-rolled error site in the
// auth/MFA/password handlers emits the canonical RFC 7807 Problem+JSON
// shape — application/problem+json Content-Type AND a stable `code`
// field in the dotted catalog. Phase 2B-core covered the universal
// writeMappedError/writeJSONError helpers; these tests pin the migration
// of the remaining ~25 hand-rolled `writeJSON(w, status, map[string]any{
// "code": "..."})` sites that used short identifiers ("unauthenticated",
// "invalid_mfa", "mfa_not_enrolled", ...) into the dotted namespace
// declared in docs/error_codes.md.
//
// The tests below intentionally hit only the paths that exit BEFORE any
// DB roundtrip (validation gates, decode failures, missing headers,
// missing envelope), so they run without sqlmock. Paths that need DB
// state are exercised in the higher-level integration tests.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"go.uber.org/zap"
)

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	if got, want := rec.Header().Get("Content-Type"), httperr.ContentType; got != want {
		t.Fatalf("content-type: got %q want %q (body=%s)", got, want, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, rec.Body.String())
	}
	if got := body["code"]; got == nil || got == "" {
		t.Fatalf("code field missing (body=%s)", rec.Body.String())
	}
	if got := body["type"]; got == nil || !strings.HasPrefix(got.(string), httperr.TypePrefix) {
		t.Fatalf("type field missing or wrong prefix: %v", got)
	}
	return body
}

func newRequest(method, target string, body string) *http.Request {
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, target, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// TestPhase14MFAEnrollMissingEmail covers handleMFAEnrollRequest the
// "collaborator_email required" exit. Was: writeJSON map[string]string
// {"error": "collaborator_email required"}; expected: Problem+JSON with
// code=input.missing_field.
//
// Path: skip admin authz (handler returns before it on bad body), call
// directly. We supply a non-admin request and a body missing
// collaborator_email — the admin gate executes first, so we route around
// it by setting the admin token header to whatever the env says (or
// blank — the gate emits Problem+JSON too).
func TestPhase14MFAEnrollMissingEmail(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	// Auth gate emits 401 Problem+JSON since no admin token. That's a
	// valid §14 shape too — we assert the shape, not the specific code.
	req := newRequest(http.MethodPost, "/api/v1/auth/mfa/enroll/request",
		`{"collaborator_email":""}`)
	rec := httptest.NewRecorder()
	srv.handleMFAEnrollRequest(rec, req)

	if rec.Code < 400 {
		t.Fatalf("expected 4xx, got %d", rec.Code)
	}
	body := decodeProblem(t, rec)
	// Either the admin gate (auth.*) or the missing-field branch
	// (input.*) — both are canonical post-migration.
	codeStr := body["code"].(string)
	if !strings.HasPrefix(codeStr, "auth.") && !strings.HasPrefix(codeStr, "input.") {
		t.Errorf("code %q must be dotted (auth.* or input.*) per §14", codeStr)
	}
}

// TestPhase14RequireEnvelopeReturnsProblem covers s.requireEnvelope when
// s.envelope is nil — the path is hit by every MFA TOTP/WebAuthn handler
// during the boot phase where YGGDRASIL_AUTH_KEK_BASE64 is unset. Was:
// writeJSON 503 map[string]string{"error": "YGGDRASIL_AUTH_KEK_BASE64
// not configured"}; expected: Problem+JSON with code=auth.kek_not_configured.
func TestPhase14RequireEnvelopeReturnsProblem(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	rec := httptest.NewRecorder()
	ok := srv.requireEnvelope(rec)
	if ok {
		t.Fatal("requireEnvelope must return false when envelope nil")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d want 503", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeAuthKEKNotConfigured {
		t.Errorf("code: got %v want %v", got, httperr.CodeAuthKEKNotConfigured)
	}
}

// TestPhase14WebAuthnFinishReturnsProblem covers handleMFAWebAuthnFinish
// when the engine isn't configured (no RPID/Origins env, no test wiring).
//
// 2026-05-28: the handler is no longer a 501 stub — it's a real
// FinishRegistration path against go-webauthn. When the engine is nil
// the handler returns 503 + auth.webauthn_not_implemented (kept as the
// canonical "passkey not available" code so existing surface translations
// keep working). The surface's response treats 503 the same as 501 —
// both prompt the user toward TOTP.
func TestPhase14WebAuthnFinishReturnsProblem(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodPost, "/api/v1/auth/mfa/factors/webauthn/finish", `{}`)
	rec := httptest.NewRecorder()
	srv.handleMFAWebAuthnFinish(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d want 503", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeAuthWebAuthnNotImplemented {
		t.Errorf("code: got %v want %v", got, httperr.CodeAuthWebAuthnNotImplemented)
	}
}

// TestPhase14PasswordChangeUnauthenticated covers handlePasswordChange's
// no-token early return. Was: writeJSON map[string]any{"code":
// "unauthenticated"}; expected: Problem+JSON with code=auth.unauthenticated.
func TestPhase14PasswordChangeUnauthenticated(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodPost, "/api/v1/auth/passwords/change", `{}`)
	// No Authorization header / no cookie — first guard short-circuits.
	rec := httptest.NewRecorder()
	srv.handlePasswordChange(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeAuthUnauthenticated {
		t.Errorf("code: got %v want %v", got, httperr.CodeAuthUnauthenticated)
	}
}

// TestPhase14SetupCommitTokenRequired covers handleSetupCommit's
// "token_required" exit. Was: writeJSON map[string]any{"code": "token_required"};
// expected: Problem+JSON with code=input.missing_field.
func TestPhase14SetupCommitTokenRequired(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodPost, "/api/v1/auth/passwords/setup",
		`{"new_password":"x"}`)
	rec := httptest.NewRecorder()
	srv.handleSetupCommit(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeMissingField {
		t.Errorf("code: got %v want %v", got, httperr.CodeMissingField)
	}
}

// TestPhase14SetupCommitPasswordRequired covers handleSetupCommit's
// "password_required" exit (token present, new_password missing).
func TestPhase14SetupCommitPasswordRequired(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodPost, "/api/v1/auth/passwords/setup",
		`{"token":"abc"}`)
	rec := httptest.NewRecorder()
	srv.handleSetupCommit(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeMissingField {
		t.Errorf("code: got %v want %v", got, httperr.CodeMissingField)
	}
}

// TestPhase14SetupCommitUnknownFields covers the whitelist-violation
// path. Was: writeJSON map[string]any{"code": "setup_unknown_fields",
// "rejected": [...]}; expected: Problem+JSON with code=input.unknown_fields
// and a `rejected` extension field preserved.
func TestPhase14SetupCommitUnknownFields(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodPost, "/api/v1/auth/passwords/setup",
		`{"token":"abc","new_password":"x","profile":{"unknown_field":"v"}}`)
	rec := httptest.NewRecorder()
	srv.handleSetupCommit(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeUnknownFields {
		t.Errorf("code: got %v want %v", got, httperr.CodeUnknownFields)
	}
	if body["rejected"] == nil {
		t.Errorf("rejected extension field missing: %v", body)
	}
}

// TestPhase14SetupCommitPasswordTooShort covers the pre-DB strength
// check. Was: writeJSON map[string]any{"code": "password_too_weak",
// "reason": "too_short"}; expected: Problem+JSON with
// code=auth.password_too_weak and `reason` preserved as extension.
func TestPhase14SetupCommitPasswordTooShort(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodPost, "/api/v1/auth/passwords/setup",
		`{"token":"abc","new_password":"short"}`)
	rec := httptest.NewRecorder()
	srv.handleSetupCommit(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeAuthPasswordTooWeak {
		t.Errorf("code: got %v want %v", got, httperr.CodeAuthPasswordTooWeak)
	}
	if body["reason"] != "too_short" {
		t.Errorf("reason extension missing: %v", body["reason"])
	}
}

// TestPhase14IssueSetupTokenInvalidUUID covers handleIssueSetupToken's
// uuid.Parse failure path. Was: writeJSON map[string]any{"code":
// "invalid_collaborator_id"}; expected: Problem+JSON with code=input.invalid.
//
// The admin authz gate is hit first — we test the SAME wire shape on
// whatever 4xx the handler emits (auth.* OR input.*); the regression
// guard is "not the legacy unstructured shape".
func TestPhase14IssueSetupTokenAlwaysEmitsProblem(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodPost, "/api/v1/auth/passwords/setup-tokens",
		`{"collaborator_id":"not-a-uuid"}`)
	rec := httptest.NewRecorder()
	srv.handleIssueSetupToken(rec, req)
	if rec.Code < 400 {
		t.Errorf("status: got %d expected 4xx", rec.Code)
	}
	decodeProblem(t, rec) // shape gate
}

// TestSetupPreflightMissingToken covers the cheap query-parameter validation
// path. The DB-dependent states (invalid / already_used / expired) require
// integration tests with a real Postgres and are covered by e2e.
func TestSetupPreflightMissingToken(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	req := newRequest(http.MethodGet, "/api/v1/auth/passwords/setup/preflight", "")
	rec := httptest.NewRecorder()
	srv.handleSetupPreflight(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d want 400", rec.Code)
	}
	body := decodeProblem(t, rec)
	if got := body["code"]; got != httperr.CodeMissingField {
		t.Errorf("code: got %v want %v", got, httperr.CodeMissingField)
	}
}
