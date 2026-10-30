package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// IntegrationActionCategoryPermission is the action_catalog category of a
// product-level permission: granted through team_grants and authorized by the
// downstream application, never dispatched by Yggdrasil.
const IntegrationActionCategoryPermission = "permission"

// integrationInstancePermissionCatalogQuery loads, in one read-only statement,
// the type_ref of the active version of a literal namespace/name instance and
// the identity and action_catalog of every active integration_type that
// type_ref may name. The candidate predicate is the one
// integrationTypeCandidatesJoin uses for ADR-0021, and the exact selection is
// made in Go by selectIntegrationTypeCandidate, so this resolver and
// ResolveIntegrationInstanceByName always pick the same active type.
const integrationInstancePermissionCatalogQuery = `
	SELECT a.spec -> 'type_ref', COALESCE(t.candidates, '[]'::jsonb)
	FROM public.manifests a
	LEFT JOIN LATERAL (
		SELECT jsonb_agg(jsonb_build_object(
			'id', ty.id,
			'namespace', ty.namespace,
			'name', ty.name,
			'version', ty.version,
			'action_catalog', COALESCE(ty.spec -> 'action_catalog', '[]'::jsonb)
		)) AS candidates
		FROM public.manifests ty
		WHERE ty.kind = 'integration_type'
			AND ty.active = TRUE
			AND (
				ty.id::text = lower(btrim(a.spec -> 'type_ref' ->> 'manifest_id'))
				OR ty.name = lower(btrim(a.spec -> 'type_ref' ->> 'name'))
			)
	) t ON TRUE
	WHERE a.kind = 'integration_instance'
		AND a.namespace = $1
		AND a.name = $2
		AND a.active = TRUE
`

// integrationTypeCatalogCandidate is one active integration_type row returned
// by integrationInstancePermissionCatalogQuery.
type integrationTypeCatalogCandidate struct {
	ID            uuid.UUID                           `json:"id"`
	Namespace     string                              `json:"namespace"`
	Name          string                              `json:"name"`
	Version       int                                 `json:"version"`
	ActionCatalog []model.IntegrationActionDefinition `json:"action_catalog"`
}

// ListIntegrationInstancePermissionActions returns the sorted, deduplicated
// names of the action_catalog entries whose category is exactly "permission"
// in the active integration_type that the active version of the literal
// namespace/name instance resolves to. The wildcard name "*" and blank names
// are never returned. An instance without an active version, a type_ref that
// selects no active integration_type, or an unreadable type_ref answers
// ErrIntegrationInstanceNotResolvable; a database or decoding failure is
// returned as is. Both parts must already be in the normalized form manifests
// are stored in.
func ListIntegrationInstancePermissionActions(ctx context.Context, db *sql.DB, namespace, name string) ([]string, error) {
	var (
		rawTypeRef    []byte
		rawCandidates []byte
	)
	err := db.QueryRowContext(ctx, integrationInstancePermissionCatalogQuery, namespace, name).Scan(&rawTypeRef, &rawCandidates)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIntegrationInstanceNotResolvable
	}
	if err != nil {
		return nil, err
	}

	var typeRef model.ManifestSelector
	if len(rawTypeRef) == 0 || json.Unmarshal(rawTypeRef, &typeRef) != nil {
		return nil, ErrIntegrationInstanceNotResolvable
	}
	var candidates []integrationTypeCatalogCandidate
	if len(rawCandidates) > 0 {
		if err := json.Unmarshal(rawCandidates, &candidates); err != nil {
			return nil, err
		}
	}
	identities := make([]integrationTypeCandidate, len(candidates))
	for index, candidate := range candidates {
		identities[index] = integrationTypeCandidate{
			ID:        candidate.ID,
			Namespace: candidate.Namespace,
			Name:      candidate.Name,
			Version:   candidate.Version,
		}
	}
	selected := selectIntegrationTypeCandidate(typeRef, identities)
	if selected < 0 {
		return nil, ErrIntegrationInstanceNotResolvable
	}

	seen := map[string]struct{}{}
	for _, action := range candidates[selected].ActionCatalog {
		if action.Category != IntegrationActionCategoryPermission {
			continue
		}
		actionName := strings.TrimSpace(action.Name)
		if actionName == "" || actionName == "*" {
			continue
		}
		seen[actionName] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for actionName := range seen {
		out = append(out, actionName)
	}
	sort.Strings(out)
	return out, nil
}
