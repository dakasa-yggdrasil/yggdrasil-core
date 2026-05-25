package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// TestIsAsyncWorkflowRunRequest_QueryParam verifies the route that selects
// the async dispatcher accepts the documented query forms (true/1/yes,
// case-insensitive) and rejects everything else. This guards against a
// silent fallback to sync execution for callers that opted-in to async.
func TestIsAsyncWorkflowRunRequest_QueryParam(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{"async=true", true},
		{"async=1", true},
		{"async=yes", true},
		{"async=TRUE", true},
		{"async=YES", true},
		{"async=false", false},
		{"async=", false},
		{"", false},
		{"other=true", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "http://x/api/v1/workflow-runs?"+c.query, nil)
		if got := isAsyncWorkflowRunRequest(req); got != c.want {
			t.Errorf("query=%q got=%v want=%v", c.query, got, c.want)
		}
	}
}

func TestIsAsyncWorkflowRunRequest_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://x/api/v1/workflow-runs", nil)
	req.Header.Set("X-Yggdrasil-Workflow-Mode", "async")
	if !isAsyncWorkflowRunRequest(req) {
		t.Fatal("expected header to enable async mode")
	}
	req.Header.Set("X-Yggdrasil-Workflow-Mode", "ASYNC")
	if !isAsyncWorkflowRunRequest(req) {
		t.Fatal("header lookup must be case-insensitive")
	}
	req.Header.Set("X-Yggdrasil-Workflow-Mode", "sync")
	if isAsyncWorkflowRunRequest(req) {
		t.Fatal("header sync must NOT enable async")
	}
}

// TestExplicitWorkflowRunDispatchMode pins the tri-state contract that
// resolveWorkflowRunAsync layers on top of. The caller may explicitly opt
// IN to async (?async=true / header async) OR explicitly opt OUT (?async=
// false / header sync) — both must win over whatever the workflow manifest
// declares. When neither is set, the caller is implicit and the manifest
// becomes the source of truth.
func TestExplicitWorkflowRunDispatchMode(t *testing.T) {
	cases := []struct {
		name     string
		query    string
		header   string
		wantMode string
		wantOK   bool
	}{
		{name: "no signal", wantMode: "", wantOK: false},
		{name: "query async=true", query: "async=true", wantMode: "async", wantOK: true},
		{name: "query async=1", query: "async=1", wantMode: "async", wantOK: true},
		{name: "query async=yes", query: "async=yes", wantMode: "async", wantOK: true},
		{name: "query async=false (opt out)", query: "async=false", wantMode: "sync", wantOK: true},
		{name: "query async=0 (opt out)", query: "async=0", wantMode: "sync", wantOK: true},
		{name: "query async=no (opt out)", query: "async=no", wantMode: "sync", wantOK: true},
		{name: "query gibberish ignored", query: "async=maybe", wantMode: "", wantOK: false},
		{name: "header async", header: "async", wantMode: "async", wantOK: true},
		{name: "header sync", header: "sync", wantMode: "sync", wantOK: true},
		{name: "header gibberish ignored", header: "later", wantMode: "", wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			url := "http://x/api/v1/workflow-runs"
			if c.query != "" {
				url += "?" + c.query
			}
			req := httptest.NewRequest(http.MethodPost, url, nil)
			if c.header != "" {
				req.Header.Set("X-Yggdrasil-Workflow-Mode", c.header)
			}
			got, ok := explicitWorkflowRunDispatchMode(req)
			if got != c.wantMode || ok != c.wantOK {
				t.Fatalf("explicitWorkflowRunDispatchMode() = (%q, %v), want (%q, %v)", got, ok, c.wantMode, c.wantOK)
			}
		})
	}
}

// TestResolveWorkflowRunAsync_ExplicitWins guards the most surprising
// branch of the resolver: even when the workflow manifest declares
// `dispatch_mode: async` (and would normally route through the async
// dispatcher), a caller that passes `?async=false` MUST get the sync
// path. This is the documented ops-escape hatch — without it, an operator
// debugging a broken async workflow cannot force the sync path to see
// the per-step error on the wire instead of via the polling endpoint.
//
// We don't need a DB here because explicit-mode short-circuits before
// the manifest lookup. The server's db field stays nil — if any branch
// touches the DB this test will fail with a nil-pointer panic which is
// exactly the regression signal we want.
func TestResolveWorkflowRunAsync_ExplicitOptOutBeatsManifestAsync(t *testing.T) {
	s := &Server{}
	req := model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Name: "any-async-workflow", Namespace: "global"},
	}

	httpReq := httptest.NewRequest(http.MethodPost, "http://x/api/v1/workflow-runs?async=false", nil)
	if s.resolveWorkflowRunAsync(httpReq, req) {
		t.Fatal("explicit ?async=false must force sync even when the manifest would have chosen async")
	}
}

// TestResolveWorkflowRunAsync_ExplicitOptInBeatsManifestSync mirrors the
// symmetric case: a caller passing `?async=true` must reach the async
// dispatcher regardless of whether the manifest declared anything. This
// preserves the back-compat opt-in path documented at the top of
// handleWorkflowRun for callers that learned the flag before the
// per-workflow knob existed.
func TestResolveWorkflowRunAsync_ExplicitOptInBeatsManifestSync(t *testing.T) {
	s := &Server{}
	req := model.RunWorkflowRequest{
		Workflow: model.ManifestSelector{Name: "any-sync-workflow", Namespace: "global"},
	}

	httpReq := httptest.NewRequest(http.MethodPost, "http://x/api/v1/workflow-runs?async=true", nil)
	if !s.resolveWorkflowRunAsync(httpReq, req) {
		t.Fatal("explicit ?async=true must force async even when the manifest would have chosen sync")
	}
}
