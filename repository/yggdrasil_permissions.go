package repository

import (
	"context"
	"database/sql"
	"sort"

	"github.com/google/uuid"
)

// YggdrasilGodModeAction is the canonical wildcard returned to the FE when a
// collaborator has full admin powers (either via a "*" team_grant on a
// yggdrasil-self instance, or via traits.yggdrasil_admin=true). The FE's
// usePermission treats this as "matches every yggdrasil:* permission".
const YggdrasilGodModeAction = "yggdrasil:*"

// ResolveYggdrasilPermissions returns the sorted, deduplicated list of
// yggdrasil:* actions the collaborator has been granted, derived from
// team_grants on integration_instances of type=yggdrasil-self for every
// active team membership.
//
// Special cases:
//   - if any matched grant has action_name="*", the entire result is
//     collapsed to [YggdrasilGodModeAction] regardless of other entries.
//   - if collaborator.traits.yggdrasil_admin=true, also returns god mode
//     (this is the legacy flag set by team_membership reactor; we keep
//     accepting it so existing seed scripts don't need a migration).
//
// Empty slice = no permissions. The FE then hides anything gated.
func ResolveYggdrasilPermissions(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
	collaboratorTraits map[string]any,
) ([]string, error) {
	if collaboratorTraits != nil {
		if v, ok := collaboratorTraits["yggdrasil_admin"].(bool); ok && v {
			return []string{YggdrasilGodModeAction}, nil
		}
	}

	// Resolution mirrors the canonical manifest resolvers
	// (repository.MaterializeReactions, internal/teamreconcile.ListUnprovisionedPairs):
	// join by the real namespace/name COLUMNS (migration 00001, written by
	// InsertManifest), NOT the metadata annotations blob (migration 00045),
	// which InsertManifest never populates and therefore always resolves EMPTY.
	// The integration_type is matched by the instance spec type_ref
	// (namespace,name) - stored instances write type_ref as namespace/name with
	// no id - and restricted to the yggdrasil-self type. A manifest_id path is
	// COALESCEd in for selectors that serialize the id key (model.ManifestSelector
	// emits "manifest_id"). Both sides require active=true so tombstoned
	// versions never leak a grant.
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT tg.action_name
		FROM public.team_grants tg
		JOIN public.team_memberships tm
		  ON tm.team_id = tg.team_id
		 AND tm.active = true
		JOIN public.manifests mi
		  ON mi.kind = 'integration_instance'
		 AND mi.active = true
		 AND mi.namespace = tg.integration_instance_namespace
		 AND mi.name      = tg.integration_instance_name
		JOIN public.manifests mt
		  ON mt.kind = 'integration_type'
		 AND mt.active = true
		 AND mt.name = 'yggdrasil-self'
		 AND (
		       (mt.namespace = (mi.spec->'type_ref'->>'namespace')
		         AND mt.name = (mi.spec->'type_ref'->>'name'))
		    OR mt.id = NULLIF(mi.spec->'type_ref'->>'manifest_id', '')::uuid
		 )
		WHERE tm.collaborator_id = $1
	`, collaboratorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	hasWildcard := false
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			return nil, err
		}
		if action == "*" {
			hasWildcard = true
			continue
		}
		seen[action] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if hasWildcard {
		return []string{YggdrasilGodModeAction}, nil
	}

	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}
