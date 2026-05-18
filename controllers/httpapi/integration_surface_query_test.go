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
