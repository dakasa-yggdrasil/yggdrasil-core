package scim

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadOnlyGuard_BlocksMutationsButAllowsSearchPost(t *testing.T) {
	allowed := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":0}`))
	})
	guarded := ReadOnlyGuard()(allowed)

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"GET Users passes through", http.MethodGet, "/scim/v2/Users", http.StatusOK},
		{"POST Users blocked (create)", http.MethodPost, "/scim/v2/Users", http.StatusForbidden},
		{"POST /.search allowed (RFC 7644 §3.4.3)", http.MethodPost, "/scim/v2/Users/.search", http.StatusOK},
		{"POST /.search on Groups allowed", http.MethodPost, "/scim/v2/Groups/.search", http.StatusOK},
		{"PUT blocked", http.MethodPut, "/scim/v2/Users/abc", http.StatusForbidden},
		{"PATCH blocked", http.MethodPatch, "/scim/v2/Users/abc", http.StatusForbidden},
		{"DELETE blocked", http.MethodDelete, "/scim/v2/Users/abc", http.StatusForbidden},
		{"POST /.search trailing slash also allowed", http.MethodPost, "/scim/v2/Users/.search/", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(""))
			rr := httptest.NewRecorder()
			guarded.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d (body=%q)", rr.Code, tc.wantStatus, rr.Body.String())
			}
		})
	}
}
