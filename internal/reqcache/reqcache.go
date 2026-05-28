// Package reqcache is a request-scoped memoization layer keyed by
// (kind, id). It exists to eliminate the F4 "same row fetched N times
// per request" pattern that appeared throughout the credentials /
// collaborator-lifecycle / middleware_credentials path:
//
//   handleSomething:
//     1. middleware_auth     GetCollaborator(id) -> Collaborator
//     2. middleware_creds    GetCollaborator(id) -> Collaborator  (same row)
//     3. handler body        GetCollaborator(id) -> Collaborator  (same row)
//     4. recordAuthAudit     GetCollaborator(id) -> Collaborator  (same row)
//
// Each call hits Postgres independently. With this package the first
// call goes to the DB and stores the row in r.Context(); the next three
// calls return the cached value without touching the pool.
//
// Scope: cache lifetime equals the request lifetime (Context is GC'd
// as soon as the handler returns). No TTL needed — context tear-down
// is the eviction. This is SAFE for sessions, permissions, anything:
// within a single request the data point is consistent by definition.
// (Caching across requests is what cache/ttl.go covers; that is a
// different problem with different safety rules.)
//
// Usage:
//
//	ctx := reqcache.Install(r.Context())
//	r = r.WithContext(ctx)
//	// later, in any handler / middleware:
//	collab, err := reqcache.GetOrLoad(r.Context(), "collaborator", id,
//	    func(ctx context.Context) (model.Collaborator, error) {
//	        return repository.GetCollaborator(ctx, db, id)
//	    })
//
// The cache is intentionally `map[string]any` — generics would force
// every call-site to pick the type parameter explicitly. The
// GetOrLoad[T] generic helper below recovers type safety at the
// boundary while leaving the storage flat.
//
// Audit ref: backlog F4 perf cycle 2026-05-28.
package reqcache

import (
	"context"
	"sync"
)

// contextKey is the unexported type that keys the cache in
// context.Context. The unexported type prevents accidental key
// collisions with other packages that put values into the same
// context.
type contextKey struct{}

// cache is the per-request store. sync.Mutex guards the map for the
// rare case where a handler dispatches goroutines that share the same
// request context (audit fire-and-forget pattern). The fast path is
// uncontended.
type cache struct {
	mu   sync.Mutex
	data map[string]any
}

// Install returns a child context with a fresh request-scoped cache
// attached. Call once per request (the middleware layer is the natural
// home — see InstallMiddleware below). Subsequent calls to
// reqcache.Get / GetOrLoad through this context (or its children)
// share the same cache.
//
// If the context already has a cache installed, Install returns it
// unchanged — re-installing would lose the existing memos.
func Install(ctx context.Context) context.Context {
	if _, ok := ctx.Value(contextKey{}).(*cache); ok {
		return ctx
	}
	c := &cache{data: map[string]any{}}
	return context.WithValue(ctx, contextKey{}, c)
}

// fromContext returns the cache installed by Install, or nil when none
// is attached.  All public helpers gracefully fall through to the
// loader on nil, so a handler that forgets to call Install gets correct
// behaviour at the cost of memoization — never wrong data.
func fromContext(ctx context.Context) *cache {
	c, _ := ctx.Value(contextKey{}).(*cache)
	return c
}

// keyOf composes the canonical (kind, id) key string. Both fields are
// concatenated with a separator that can't appear in valid identifiers.
func keyOf(kind, id string) string {
	return kind + "|" + id
}

// Set stores value under (kind, id). No-op when the context has no
// cache installed.
func Set(ctx context.Context, kind, id string, value any) {
	c := fromContext(ctx)
	if c == nil {
		return
	}
	c.mu.Lock()
	c.data[keyOf(kind, id)] = value
	c.mu.Unlock()
}

// Get returns the value previously stored under (kind, id) and a
// presence flag. Returns (nil, false) when the cache is missing OR the
// key is unknown.
func Get(ctx context.Context, kind, id string) (any, bool) {
	c := fromContext(ctx)
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	v, ok := c.data[keyOf(kind, id)]
	c.mu.Unlock()
	return v, ok
}

// Delete removes (kind, id) from the cache. Useful when a handler
// performs a mutation and wants downstream code in the SAME request
// to see the post-mutation row.
func Delete(ctx context.Context, kind, id string) {
	c := fromContext(ctx)
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.data, keyOf(kind, id))
	c.mu.Unlock()
}

// GetOrLoad is the typed convenience: returns the cached value when
// present, otherwise invokes loader, stores the result, and returns
// it. Errors from loader are NEVER cached — a subsequent call will
// retry the loader.
//
// Generic to recover type safety at the call site without forcing
// every consumer to type-assert.
func GetOrLoad[T any](
	ctx context.Context,
	kind, id string,
	loader func(context.Context) (T, error),
) (T, error) {
	var zero T
	if v, ok := Get(ctx, kind, id); ok {
		if typed, ok := v.(T); ok {
			return typed, nil
		}
		// Shadowed by a different concrete type — fall through to the
		// loader rather than panic on the assertion. This handles the
		// edge case of two callers using the same kind for different T.
	}
	val, err := loader(ctx)
	if err != nil {
		return zero, err
	}
	Set(ctx, kind, id, val)
	return val, nil
}

// Size returns the number of entries currently cached. Test-only;
// production callers don't introspect the cache.
func Size(ctx context.Context) int {
	c := fromContext(ctx)
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}
