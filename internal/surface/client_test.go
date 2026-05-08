package surface

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchManifest_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/surface/manifest" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
			"surface":"heimdall","surface_version":"1.0.0","schema_version":1,
			"display_name":"Heimdall","icon":"shield-check",
			"pages":[{"id":"pulses","path":"/pulses","title":"Pulses","view":{"kind":"table"}}]
		}`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client())
	m, err := c.FetchManifest(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if m.Surface != "heimdall" {
		t.Errorf("Surface: %q", m.Surface)
	}
	if m.SchemaVersion != 1 {
		t.Errorf("SchemaVersion: %d", m.SchemaVersion)
	}
}

func TestFetchManifest_404IsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	c := NewClient(srv.Client())
	_, err := c.FetchManifest(context.Background(), srv.URL)
	if err != ErrNoSurface {
		t.Errorf("err: got %v want ErrNoSurface", err)
	}
}

func TestFetchData_PassesQuery(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.RawQuery
		_, _ = w.Write([]byte(`[{"id":"p1"}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client())
	body, err := c.FetchData(context.Background(), srv.URL, "pulses", "status=active")
	if err != nil {
		t.Fatalf("FetchData: %v", err)
	}
	if seen != "status=active" {
		t.Errorf("query: %q", seen)
	}
	var rows []map[string]any
	_ = json.Unmarshal(body, &rows)
	if len(rows) != 1 {
		t.Errorf("rows: %d", len(rows))
	}
}

func TestExecuteAction_PostsBody(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := bytes.Buffer{}
		_, _ = io.Copy(&buf, r.Body)
		got = buf.Bytes()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := NewClient(srv.Client())
	body, err := c.ExecuteAction(context.Background(), srv.URL, "trigger", strings.NewReader(`{"id":"p1"}`))
	if err != nil {
		t.Fatalf("ExecuteAction: %v", err)
	}
	if string(got) != `{"id":"p1"}` {
		t.Errorf("body sent: %q", string(got))
	}
	if !strings.Contains(string(body), "ok") {
		t.Errorf("resp: %s", body)
	}
}
