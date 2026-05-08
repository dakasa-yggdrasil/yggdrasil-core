package scim

import (
	"net/http"
	"strings"
)

// ReadOnlyGuard returns 403 + an RFC 7644 §3.12 error response for any
// mutating method (PUT, PATCH, DELETE, POST). The single allowed POST hits
// `/scim/v2/Schemas` etc. as a SCIM "search" — we do not implement that here,
// so all mutations are blocked.
//
// Yggdrasil is source of truth: downstream clients pull, never push.
func ReadOnlyGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isMutating(r.Method) {
				writeReadOnlyError(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isMutating(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodPost:
		return true
	default:
		return false
	}
}

func writeReadOnlyError(w http.ResponseWriter) {
	const body = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"403","scimType":"mutability","detail":"Yggdrasil is source of truth; modify upstream and wait for reconcile"}`
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(body))
}
