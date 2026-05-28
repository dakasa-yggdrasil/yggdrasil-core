package httpapi

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/reqcache"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Request-scoped cache kinds. Centralized here so a typo at a call site
// becomes a compile error rather than a silent cache miss.
const (
	reqcacheKindCollaborator = "collaborator"
)

// getCollaboratorCached returns the collaborator with the given id,
// memoizing the result for the lifetime of the request context.
// Subsequent calls with the same id in the SAME request skip the DB
// round-trip and return the cached row.
//
// Safety: scoped to one request — the cache map is GC'd when the
// handler returns. There is no cross-request staleness possible.
//
// F4 audit: collaborator lookups previously fired 2–4 times per
// request (middleware_credentials, ops_rbac_middleware, the handler
// body, recordAuthAudit). Memoization collapses them to one.
func getCollaboratorCached(ctx context.Context, db *sql.DB, id string) (model.Collaborator, error) {
	return reqcache.GetOrLoad(ctx, reqcacheKindCollaborator, id,
		func(ctx context.Context) (model.Collaborator, error) {
			return repository.GetCollaborator(ctx, db, id)
		})
}

// setCollaboratorInCache primes the request-scoped cache from a row
// the caller already has in hand. The auth middleware uses this to
// stash the collaborator resolved from the session token so downstream
// handlers don't re-fetch.
func setCollaboratorInCache(ctx context.Context, collab model.Collaborator) {
	reqcache.Set(ctx, reqcacheKindCollaborator, collab.ID.String(), collab)
}

