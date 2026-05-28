package httpapi

import (
	"net/http"
	"sort"
)

// rejectUnknownQueryParams enforces an allowlist of accepted query
// parameters on the supplied request. Any param not in the allowlist
// results in an immediate `400 Bad Request` (RFC 7807 Problem+JSON)
// with `code = input.unknown_fields` so the surface can humanize.
//
// Audit ref: 2026-05-27 A15 — deny unknown query params on sensitive
// endpoints (prevent param-smuggling). The pre-existing behavior was to
// silently ignore unknown params, which let attackers probe for hidden
// debug toggles (e.g. `?debug=true`, `?bypass_mfa=1`, `?include_secret=1`)
// without any signal in the logs.
//
// Returns true if the request passed (caller continues processing) and
// false if the response was already written (caller must return).
//
// The `rejected` slice is intentionally NOT exposed back to the caller
// in the response body — the attacker should not learn which arbitrary
// param names are "rejected" vs "ignored", only that their probe failed.
// Caller can log the names server-side for investigation.
func rejectUnknownQueryParams(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, k := range allowed {
		allowedSet[k] = struct{}{}
	}

	var rejected []string
	for key := range r.URL.Query() {
		if _, ok := allowedSet[key]; !ok {
			rejected = append(rejected, key)
		}
	}
	if len(rejected) == 0 {
		return true
	}

	// Deterministic order so the response body is stable for tests + logs.
	sort.Strings(rejected)
	writeProblemJSON(
		w,
		http.StatusBadRequest,
		"input.unknown_fields",
		"One or more query parameters are not recognized for this endpoint.",
	)
	return false
}
