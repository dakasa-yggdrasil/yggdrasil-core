package reqcache

import "net/http"

// Middleware installs a fresh request-scoped cache on every inbound
// HTTP request before delegating to the next handler. Wire it as
// early as possible in the chain (above auth, above logging) so any
// downstream code that calls reqcache.Get / GetOrLoad benefits from
// the same memos.
//
// The cache is detached when the handler returns (context goes out
// of scope; GC reclaims the map).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := Install(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
