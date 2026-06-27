// Package manifestsync auto-heals integration_type manifest drift against
// adapter live describe responses. See
// docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md.
package manifestsync

import (
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Diff is a compact summary of the structural change between two specs.
// Embedded in integration_type.synced event payloads for audit.
type Diff struct {
	AddedActions        []string
	RemovedActions      []string
	SchemaChanged       bool
	CapabilitiesChanged bool
}

// MergeSpec produces the new integration_type spec to persist when drift is
// detected: live as the base, with operator-managed fields taking
// precedence when the operator has already configured them.
//
// Operator-owned fields (preserved across sync if present in `current`):
//
//   - Reactors — UNION of adapter-declared and operator-declared
//     reactors (since 2026-06-27). The adapter's live-declared reactors
//     (`live.Reactors`) are ALWAYS present in the result; any
//     operator-declared reactor in `current.Reactors` that the adapter
//     does NOT declare is appended. Dedup is by the (EventType,
//     Capability) pair, with the adapter (live) entry winning on a
//     collision.
//
//     This replaces the old "operator override fully wins" semantics,
//     which had a sharp edge: an INCOMPLETE operator override (e.g. a
//     single stored reactor) dropped ALL the adapter's other declared
//     reactors. In prod, github had only `session.terminated` stored
//     while the adapter declared 10, so its membership/team reactors
//     never materialized after a manifest_sync tick. Unioning keeps the
//     adapter's full canonical subscription set intact while still
//     honoring operator-only additions on top.
//
//   - Domain (INTEGRATION_CONTRACT §17, since 2026-05-28). Adapters
//     declare their `spec.domain` slug via YAML/JSON manifest at
//     registration time, NOT via the adapter Describe() RPC (the
//     family/contract.AdapterDescribeResponse type does not carry
//     Domain). When manifest_sync re-syncs from the live adapter it
//     would otherwise blank the operator's declaration; we preserve
//     `current.Domain` whenever non-empty.
//
//   - Dashboard (§17 paired field). Same logic — adapters declare
//     `spec.dashboard` in their static manifest, not in Describe().
//     Preserve `current.Dashboard` whenever set.
//
//   - Display + Icon (§15 amplification, since 2026-05-28). Adapter
//     presentation hints (`spec.display` + `spec.icon`) ship in the
//     static manifest; the runtime AdapterDescribeResponse type does
//     not carry them. Preserve `current.Display` / `current.Icon`
//     whenever set so the cron sync does not blank operator-declared
//     branding on every tick.
//
// Other fields come from `live` verbatim. If new operator-owned fields
// are introduced, extend this function (and document it in the spec
// at docs/superpowers/specs/2026-05-16-sync-manifest-from-describe-design.md
// section 5.1).
func MergeSpec(current, live model.IntegrationTypeManifestSpec) (model.IntegrationTypeManifestSpec, Diff) {
	out := live
	// Reactors — UNION: the adapter's live-declared reactors are always
	// kept; operator-declared reactors not already present (by the
	// (event_type, capability) pair) are appended. An incomplete operator
	// override therefore no longer drops the adapter's other reactors.
	out.Reactors = unionReactors(live.Reactors, current.Reactors)

	// §17 — Domain and Dashboard live in the operator-managed manifest
	// (the YAML/JSON file POSTed at registration), not in the adapter's
	// runtime Describe() response. Preserve them across sync so the
	// manifest_sync addon does not silently blank the operator's
	// taxonomy declaration on every cron tick.
	if current.Domain != "" {
		out.Domain = current.Domain
	}
	if current.Dashboard != nil {
		out.Dashboard = current.Dashboard
	}

	// §15 amplification — Display + Icon are adapter presentation
	// hints declared in the static manifest, NOT in Describe(). Same
	// "preserve when non-empty, adopt when empty" pattern as Domain.
	if current.Display != nil {
		out.Display = current.Display
	}
	if current.Icon != nil {
		out.Icon = current.Icon
	}

	return out, computeDiff(current, out)
}

// unionReactors returns the union of the adapter-declared (`live`) and
// operator-declared (`current`) reactor sets, deduplicated by the
// (EventType, Capability) pair. The live entries come first and win on a
// collision; operator-only entries (those whose pair is not already in
// live) are appended in their original order. Returns nil when both
// inputs are empty so a manifest with no reactors anywhere stays nil
// rather than becoming an empty slice.
func unionReactors(live, current []model.IntegrationTypeReactor) []model.IntegrationTypeReactor {
	if len(live) == 0 && len(current) == 0 {
		return nil
	}
	type reactorKey struct {
		eventType  string
		capability string
	}
	seen := make(map[reactorKey]struct{}, len(live)+len(current))
	out := make([]model.IntegrationTypeReactor, 0, len(live)+len(current))
	for _, r := range live {
		k := reactorKey{eventType: r.EventType, capability: r.Capability}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	for _, r := range current {
		k := reactorKey{eventType: r.EventType, capability: r.Capability}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

func computeDiff(before, after model.IntegrationTypeManifestSpec) Diff {
	beforeOps := actionNames(before.ActionCatalog)
	afterOps := actionNames(after.ActionCatalog)

	return Diff{
		AddedActions:        diffStringMaps(afterOps, beforeOps),
		RemovedActions:      diffStringMaps(beforeOps, afterOps),
		SchemaChanged:       !reflect.DeepEqual(before.CredentialSchema, after.CredentialSchema) || !reflect.DeepEqual(before.InstanceSchema, after.InstanceSchema),
		CapabilitiesChanged: !reflect.DeepEqual(before.Capabilities, after.Capabilities),
	}
}

func actionNames(entries []model.IntegrationActionDefinition) map[string]struct{} {
	m := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		m[e.Name] = struct{}{}
	}
	return m
}

// diffStringMaps returns keys present in a but not in b. Caller does not
// depend on stable ordering; map iteration is fine here.
func diffStringMaps(a, b map[string]struct{}) []string {
	out := []string{}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}
