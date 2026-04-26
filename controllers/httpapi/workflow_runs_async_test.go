package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
