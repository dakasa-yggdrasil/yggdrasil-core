package httperr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProblemMarshalFlattensExtra verifies the RFC 7807 wire shape:
// reserved fields appear at the top level alongside Extra entries,
// producing one flat JSON object.
func TestProblemMarshalFlattensExtra(t *testing.T) {
	p := &Problem{
		Status:   http.StatusUnauthorized,
		Code:     CodeAuthInvalidCredentials,
		Title:    "Invalid credentials",
		Detail:   "Email or password is incorrect.",
		Instance: "/api/v1/auth/login",
		Extra: map[string]interface{}{
			"correlation_id": "abc-123",
			"retry_after":    60,
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := map[string]interface{}{
		"type":           TypePrefix + CodeAuthInvalidCredentials,
		"title":          "Invalid credentials",
		"status":         float64(401),
		"code":           CodeAuthInvalidCredentials,
		"detail":         "Email or password is incorrect.",
		"instance":       "/api/v1/auth/login",
		"correlation_id": "abc-123",
		"retry_after":    float64(60),
	}
	for k, v := range want {
		if got := decoded[k]; got != v {
			t.Errorf("decoded[%q]: got %v want %v", k, got, v)
		}
	}
}

// TestProblemTypeDefaultsFromCode asserts that when Type is omitted the
// marshalled output synthesizes a default URI from the code namespace —
// the field must never be empty per RFC 7807 §3.1.
func TestProblemTypeDefaultsFromCode(t *testing.T) {
	p := &Problem{Status: 422, Code: CodeManifestValidationFailed, Title: "Validation failed"}
	raw, _ := json.Marshal(p)
	var decoded map[string]interface{}
	_ = json.Unmarshal(raw, &decoded)
	if got, want := decoded["type"], TypePrefix+CodeManifestValidationFailed; got != want {
		t.Errorf("type: got %v want %v", got, want)
	}
}

// TestReservedFieldsCannotBeShadowedByExtra is a guard against careless
// callers putting "code" or "status" in Extra. Reserved fields ALWAYS
// win — the marshaller writes them after Extra.
func TestReservedFieldsCannotBeShadowedByExtra(t *testing.T) {
	p := &Problem{
		Status: 500,
		Code:   CodeInternal,
		Title:  "Boom",
		Extra: map[string]interface{}{
			"code":   "ignored",
			"status": "ignored",
			"title":  "ignored",
		},
	}
	raw, _ := json.Marshal(p)
	var decoded map[string]interface{}
	_ = json.Unmarshal(raw, &decoded)
	if got := decoded["code"]; got != CodeInternal {
		t.Errorf("code shadowed: %v", got)
	}
	if got := decoded["status"]; got != float64(500) {
		t.Errorf("status shadowed: %v", got)
	}
	if got := decoded["title"]; got != "Boom" {
		t.Errorf("title shadowed: %v", got)
	}
}

// TestWriteProblemSetsContentType asserts the wire response carries the
// RFC 7807 §3 application/problem+json media type — caches and proxies
// rely on this.
func TestWriteProblemSetsContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, 401, CodeAuthInvalidCredentials, "Invalid credentials", "", WithInstance("/login"))
	if got, want := rec.Header().Get("Content-Type"), ContentType; got != want {
		t.Errorf("content-type: got %q want %q", got, want)
	}
	if rec.Code != 401 {
		t.Errorf("status: got %d want 401", rec.Code)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != CodeAuthInvalidCredentials {
		t.Errorf("code: got %v", body["code"])
	}
	if body["instance"] != "/login" {
		t.Errorf("instance: got %v", body["instance"])
	}
}

// TestWithFieldErrorAccumulates verifies multi-error validation
// responses (one POST with several invalid fields).
func TestWithFieldErrorAccumulates(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, 422, CodeInvalidInput, "Validation failed", "",
		WithFieldError("/spec/name", "input.missing_field", "name is required"),
		WithFieldError("/spec/replicas", "input.invalid", "replicas must be >= 0"),
	)
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	errs, ok := body["errors"].([]interface{})
	if !ok {
		t.Fatalf("expected errors array, got %T", body["errors"])
	}
	if len(errs) != 2 {
		t.Errorf("errors count: got %d want 2", len(errs))
	}
}
