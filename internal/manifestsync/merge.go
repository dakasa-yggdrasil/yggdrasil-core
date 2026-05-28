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
// detected: live as the base, with operator-managed `Reactors` taking
// precedence when the operator has already configured them.
//
// Reactor precedence:
//
//  1. If `current.Reactors` is non-empty, the operator has explicitly
//     configured reactors — keep current.Reactors and ignore live.Reactors.
//     This preserves operator overrides across manifest_sync cycles.
//  2. If `current.Reactors` is empty (e.g. initial registration or first
//     sync after the adapter starts emitting reactor entries), adopt
//     `live.Reactors`. This lets adapters seed their canonical reactor
//     subscriptions (e.g. on_collaborator_session_terminated) without
//     requiring a manual catalog patch on every fresh install.
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
