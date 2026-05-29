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
//   - Reactors (since the framework launched). If `current.Reactors` is
//     non-empty, the operator has explicitly configured reactors —
//     keep current.Reactors and ignore live.Reactors. This preserves
//     operator overrides across manifest_sync cycles. If empty, adopt
//     `live.Reactors` so adapters can seed their canonical reactor
//     subscriptions on a fresh install.
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
	if len(current.Reactors) > 0 {
		out.Reactors = current.Reactors // operator override wins
	}
	// else: keep live.Reactors (adapter-declared defaults seed the manifest)

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
