package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type fakeDispatcher struct {
	gotReq model.ExecuteIntegrationRequest
	resp   any
	err    error
}

func (f *fakeDispatcher) Execute(_ context.Context, req model.ExecuteIntegrationRequest) (any, error) {
	f.gotReq = req
	return f.resp, f.err
}

func TestSurfaceQuery_PassesThrough(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{"a"}}}
	srv := &Server{surfaceQueryDispatcher: disp}
	body, _ := json.Marshal(map[string]any{"query_name": "list-channels", "params": map[string]any{"x": 1}})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if disp.gotReq.Operation != "on_surface_query" {
		t.Errorf("operation = %q", disp.gotReq.Operation)
	}
	if disp.gotReq.Integration.ManifestID != "i1" {
		t.Errorf("integration.manifest_id = %q", disp.gotReq.Integration.ManifestID)
	}
	if in, ok := disp.gotReq.Input["query_name"].(string); !ok || in != "list-channels" {
		t.Errorf("input.query_name = %v", disp.gotReq.Input["query_name"])
	}
}

// SECURITY: the verified caller stamped onto the outbound envelope comes from
// the session claims attached to the request context — never from the client
// body/params. A spoofed collaborator_id nested in params must NOT become the
// verified caller.
func TestSurfaceQuery_StampsVerifiedCallerFromSession(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{}}}
	srv := &Server{surfaceQueryDispatcher: disp}
	// Client tries to spoof a victim id inside params.
	body, _ := json.Marshal(map[string]any{
		"query_name": "my-employment",
		"params":     map[string]any{"collaborator_id": "VICTIM-SPOOFED-ID"},
	})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	// The auth middleware has validated the session and attached claims.
	ctx := contextWithClaims(req.Context(), map[string]any{
		"collaborator_id": "real-verified-collab",
		"session_id":      "sess-1",
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	got, ok := disp.gotReq.Input["verified_caller_id"].(string)
	if !ok {
		t.Fatalf("verified_caller_id not stamped onto Input: %#v", disp.gotReq.Input)
	}
	if got != "real-verified-collab" {
		t.Fatalf("verified_caller_id = %q, want the session collaborator (not the spoofed params id)", got)
	}
	// The client-supplied params must be preserved verbatim (adapter ignores its
	// collaborator_id for scoping, but params still flow through for limits etc.).
	params, _ := disp.gotReq.Input["params"].(map[string]any)
	if params["collaborator_id"] != "VICTIM-SPOOFED-ID" {
		t.Errorf("params should pass through unchanged, got %#v", params)
	}
}

// A machine/token caller authenticates WITHOUT collaborator claims; the handler
// must omit the verified caller rather than stamping an empty string.
func TestSurfaceQuery_NoClaims_OmitsVerifiedCaller(t *testing.T) {
	disp := &fakeDispatcher{resp: map[string]any{"items": []any{}}}
	srv := &Server{surfaceQueryDispatcher: disp}
	body, _ := json.Marshal(map[string]any{"query_name": "list-employees"})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if _, present := disp.gotReq.Input["verified_caller_id"]; present {
		t.Errorf("verified_caller_id must be OMITTED for a no-claims caller, got %#v", disp.gotReq.Input["verified_caller_id"])
	}
}

// A client cannot smuggle verified_caller_id via the top-level body — the body
// decoder disallows unknown fields, so such a request is a 400.
func TestSurfaceQuery_ClientCannotInjectVerifiedCaller(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{}}
	body, _ := json.Marshal(map[string]any{
		"query_name":         "my-employment",
		"verified_caller_id": "attacker-injected",
	})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 (unknown body field rejected)", w.Code)
	}
}

func TestSurfaceQuery_MissingQueryNameIs400(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{}}
	body, _ := json.Marshal(map[string]any{})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
}

func TestSurfaceQuery_DispatchErrorIs502(t *testing.T) {
	srv := &Server{surfaceQueryDispatcher: &fakeDispatcher{err: errors.New("amqp down")}}
	body, _ := json.Marshal(map[string]any{"query_name": "x"})
	req := httptest.NewRequest("POST", "/api/v1/integrations/i1/surface-query", bytes.NewReader(body))
	req.SetPathValue("instance_id", "i1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleIntegrationSurfaceQuery()(w, req)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", w.Code)
	}
}
