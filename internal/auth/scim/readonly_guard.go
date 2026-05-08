package scim

import (
	"net/http"
	"strings"
)

// ReadOnlyGuard returns 403 + an RFC 7644 §3.12 error response for any
// mutating method (PUT, PATCH, DELETE, POST creates).
//
// Exception: SCIM 2.0 §3.4.3 defines `POST /<resource>/.search` as a query
// operation (not a mutation) — used for filter expressions too long for a
// query string. Those POSTs are allowed through to the downstream handler.
//
// Yggdrasil is source of truth: downstream clients pull, never push.
func ReadOnlyGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isMutating(r.Method, r.URL.Path) {
				writeReadOnlyError(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isMutating(method, path string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	case http.MethodPost:
		// RFC 7644 §3.4.3: POST /<resource>/.search is a query, not a mutation.
		return !isSCIMSearch(path)
	default:
		return false
	}
}

// isSCIMSearch reports whether the request path targets a SCIM search
// endpoint. Trailing slashes are normalized so `/Users/.search` and
// `/Users/.search/` both match.
func isSCIMSearch(path string) bool {
	trimmed := strings.TrimRight(path, "/")
	return trimmed == "/scim/v2/.search" || strings.HasSuffix(trimmed, "/.search")
}

func writeReadOnlyError(w http.ResponseWriter) {
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"403","scimType":"mutability","detail":"Yggdrasil is source of truth; modify upstream and wait for reconcile"}`
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(body))
}
