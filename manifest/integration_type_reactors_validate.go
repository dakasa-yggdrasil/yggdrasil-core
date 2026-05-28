package manifest

import (
	"errors"
	"fmt"
)

var (
	ErrReactorEventTypeNotCanon      = errors.New("reactor event_type is not in canon catalog")
	ErrReactorCapabilityNotInCatalog = errors.New("reactor capability not in action_catalog")
	ErrReactorDuplicateEventType     = errors.New("duplicate reactor event_type in same integration_type")
)

// canonLifecycleEventTypes mirrors repository.CanonLifecycleEventTypes.
// It is duplicated here to avoid a manifest ↔ repository import cycle
// (repository/topology.go imports manifest).
// Invariant: keep in sync with repository/event_types_lifecycle.go.
var canonLifecycleEventTypes = map[string]struct{}{
	"collaborator.created":            {},
	"collaborator.offboarded":         {},
	"collaborator.session.terminated": {},
	"collaborator.absence_started":    {},
	"collaborator.absence_ended":      {},
	"collaborator.role_changed":       {},
	"collaborator.re_onboarded":       {},
	"team.created":                    {},
	"team.updated":                    {},
	"team.deleted":                    {},
	"team_membership.added":           {},
	"team_membership.removed":         {},
	"team_grant.added":                {},
	"team_grant.revoked":              {},
}

// ValidateReactors enforces:
//  1. reactors[].event_type ∈ canon catalog
//  2. reactors[].capability ∈ spec.action_catalog[].name
//  3. (integration_type, event_type) is unique
//
// Returns nil if the spec has no reactors block (optional field).
func ValidateReactors(spec map[string]any) error {
	rawReactors, ok := spec["reactors"]
	if !ok || rawReactors == nil {
		return nil
	}
	reactors, ok := rawReactors.([]any)
	if !ok {
		return fmt.Errorf("reactors must be an array")
	}

	catalogNames := map[string]struct{}{}
	if cat, ok := spec["action_catalog"].([]any); ok {
		for _, e := range cat {
			if m, ok := e.(map[string]any); ok {
				if n, ok := m["name"].(string); ok && n != "" {
					catalogNames[n] = struct{}{}
				}
			}
		}
	}

	seen := map[string]struct{}{}
	for i, r := range reactors {
		m, ok := r.(map[string]any)
		if !ok {
			return fmt.Errorf("reactors[%d] is not an object", i)
		}
		eventType, _ := m["event_type"].(string)
		capability, _ := m["capability"].(string)

		if _, canon := canonLifecycleEventTypes[eventType]; !canon {
			return fmt.Errorf("%w: %q (must be one of %v)", ErrReactorEventTypeNotCanon, eventType, canonList())
		}
		if _, ok := catalogNames[capability]; !ok {
			return fmt.Errorf("%w: %q (capabilities available: %v)", ErrReactorCapabilityNotInCatalog, capability, sortedKeys(catalogNames))
		}
		if _, dup := seen[eventType]; dup {
			return fmt.Errorf("%w: %q", ErrReactorDuplicateEventType, eventType)
		}
		seen[eventType] = struct{}{}
	}

	return nil
}

func canonList() []string {
	keys := make([]string, 0, len(canonLifecycleEventTypes))
	for k := range canonLifecycleEventTypes {
		keys = append(keys, k)
	}
	return keys
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
