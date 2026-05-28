// Package cache holds the canonical TTL constants every caching layer
// in yggdrasil-core MUST consult before picking an expiry. The intent
// is to keep cache lifetimes consistent across the codebase: there is
// ONE policy answer per resource kind, not a per-handler ad-hoc number.
//
// Rules:
//   - Never invent a new TTL inline. If the resource isn't covered here,
//     either reuse the closest constant or ADD a new one to this file
//     with a comment explaining the choice.
//   - Sessions are NEVER cached (security: cached sessions race revocation
//     and authz changes). SessionLookupTTL is intentionally 0 — handlers
//     reading session state MUST go to the source of truth every call.
//   - The Phase-3 surface PermissionCacheProvider already uses 30s; this
//     file mirrors that on the server side so any future server-side
//     permission cache lines up with the surface — no double-window
//     anomaly during permission edits.
//
// Audit ref: backlog F5 perf cycle 2026-05-28.
package cache

import "time"

const (
	// IntegrationManifestTTL bounds how stale a cached integration
	// manifest (kind=integration / integration_type / integration_instance)
	// may be served to a handler before re-fetching. 5 min lines up with
	// the manifest_sync addon's reconcile cadence — a cached entry
	// is guaranteed to be no older than one sync cycle.
	IntegrationManifestTTL = 5 * time.Minute

	// PermissionCheckTTL bounds how long an authorization decision can
	// be cached server-side. Mirrors the 30s window the
	// surface-console PermissionCacheProvider uses; matching the two
	// avoids a "user revoked but UI still shows enabled" window when
	// the server cache and surface cache miss-then-hit asymmetrically.
	PermissionCheckTTL = 30 * time.Second

	// DescribeOutputTTL bounds how long the JSON spec returned by an
	// adapter's describe handshake (`ensure_integration_type` /
	// `discover_*`) can be reused. 1 min is enough for a burst of
	// handlers reading the same spec without paying the RPC cost; not
	// so long that a Phase-2 hard-fail validator flip ever serves
	// stale shape across cycles.
	DescribeOutputTTL = 1 * time.Minute

	// SessionLookupTTL is 0 — sessions are NEVER cached.  The auth
	// session lookup is the authorization choke-point: caching it
	// makes revocation eventually-consistent in a way that violates
	// the §13 contract (mutation reactor + admin revoke must take
	// effect on the very next request).
	SessionLookupTTL = 0 * time.Second
)
