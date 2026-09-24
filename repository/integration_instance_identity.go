package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ErrIntegrationInstanceNotResolvable is returned when an instance reference
// does not name a logical integration_instance with an active version whose
// type_ref resolves to an active integration_type with a provider. Callers on
// an authorization path must not distinguish its causes to the client.
var ErrIntegrationInstanceNotResolvable = errors.New("integration instance not resolvable")

// IntegrationInstanceIdentity is the logical identity an integration instance
// reference resolves to: the (namespace, name) of the instance, its current
// active version, and the provider of the integration_type that active
// version's type_ref resolves to.
type IntegrationInstanceIdentity struct {
	Namespace        string
	Name             string
	ActiveManifestID uuid.UUID
	ActiveVersion    int
	TypeProvider     string
}

// integrationTypeCandidatesJoin finds, in the same statement as the instance,
// the active integration_type rows its type_ref may name: by id, or by name in
// any namespace. The exact selection (manifest_id first, else namespace
// defaulting to "global", name and optional version) is made in Go by
// selectIntegrationTypeProvider, so the SQL only has to be a superset.
// Resolving instance and type in one statement keeps "not found" and "found"
// to the same single round trip (ADR-0021).
const integrationTypeCandidatesJoin = `
	LEFT JOIN LATERAL (
		SELECT jsonb_agg(jsonb_build_object(
			'id', ty.id,
			'namespace', ty.namespace,
			'name', ty.name,
			'version', ty.version,
			'provider', COALESCE(ty.spec ->> 'provider', '')
		)) AS candidates
		FROM public.manifests ty
		WHERE ty.kind = 'integration_type'
			AND ty.active = TRUE
			AND (
				ty.id::text = lower(btrim(a.spec -> 'type_ref' ->> 'manifest_id'))
				OR ty.name = lower(btrim(a.spec -> 'type_ref' ->> 'name'))
			)
	) t ON TRUE
`

// Resolves any version (active or inactive, until purged) of an
// integration_instance to that logical instance's active version. Uses the
// primary key for v and manifests_single_active_uidx for a.
const resolveIntegrationInstanceByManifestIDQuery = `
	SELECT a.id, a.namespace, a.name, a.version, a.spec -> 'type_ref', COALESCE(t.candidates, '[]'::jsonb)
	FROM public.manifests v
	JOIN public.manifests a
		ON a.kind = v.kind
		AND a.namespace = v.namespace
		AND a.name = v.name
		AND a.active = TRUE
` + integrationTypeCandidatesJoin + `
	WHERE v.id = $1
		AND v.kind = 'integration_instance'
`

const resolveIntegrationInstanceByNameQuery = `
	SELECT a.id, a.namespace, a.name, a.version, a.spec -> 'type_ref', COALESCE(t.candidates, '[]'::jsonb)
	FROM public.manifests a
` + integrationTypeCandidatesJoin + `
	WHERE a.kind = 'integration_instance'
		AND a.namespace = $1
		AND a.name = $2
		AND a.active = TRUE
`

// integrationTypeCandidate is one active integration_type row returned by
// integrationTypeCandidatesJoin.
type integrationTypeCandidate struct {
	ID        uuid.UUID `json:"id"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	Provider  string    `json:"provider"`
}

// ResolveIntegrationInstanceByManifestID resolves the per-version manifest id
// of any not-yet-purged integration_instance version to its logical identity,
// in one statement.
func ResolveIntegrationInstanceByManifestID(ctx context.Context, db *sql.DB, manifestID uuid.UUID) (IntegrationInstanceIdentity, error) {
	return resolveIntegrationInstance(ctx, db, resolveIntegrationInstanceByManifestIDQuery, manifestID)
}

// ResolveIntegrationInstanceByName resolves a literal namespace/name to the
// logical integration_instance identity, in one statement. Both parts must
// already be in the normalized (trimmed, lowercase) form manifests are stored
// in.
func ResolveIntegrationInstanceByName(ctx context.Context, db *sql.DB, namespace, name string) (IntegrationInstanceIdentity, error) {
	return resolveIntegrationInstance(ctx, db, resolveIntegrationInstanceByNameQuery, namespace, name)
}

func resolveIntegrationInstance(ctx context.Context, db *sql.DB, query string, args ...any) (IntegrationInstanceIdentity, error) {
	var (
		identity      IntegrationInstanceIdentity
		rawTypeRef    []byte
		rawCandidates []byte
	)
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&identity.ActiveManifestID,
		&identity.Namespace,
		&identity.Name,
		&identity.ActiveVersion,
		&rawTypeRef,
		&rawCandidates,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return IntegrationInstanceIdentity{}, ErrIntegrationInstanceNotResolvable
	}
	if err != nil {
		return IntegrationInstanceIdentity{}, err
	}

	var typeRef model.ManifestSelector
	if len(rawTypeRef) == 0 || json.Unmarshal(rawTypeRef, &typeRef) != nil {
		return IntegrationInstanceIdentity{}, ErrIntegrationInstanceNotResolvable
	}
	var candidates []integrationTypeCandidate
	if len(rawCandidates) > 0 {
		if err := json.Unmarshal(rawCandidates, &candidates); err != nil {
			return IntegrationInstanceIdentity{}, err
		}
	}
	provider, ok := selectIntegrationTypeProvider(typeRef, candidates)
	if !ok {
		return IntegrationInstanceIdentity{}, ErrIntegrationInstanceNotResolvable
	}
	identity.TypeProvider = provider
	return identity, nil
}

// selectIntegrationTypeProvider mirrors the execution-time type_ref
// resolution (manifest_id, else namespace defaulting to "global" plus name and
// optional version) over the active integration_type candidates, so the
// resolved type is always the active one. A type without a provider does not
// resolve.
func selectIntegrationTypeProvider(typeRef model.ManifestSelector, candidates []integrationTypeCandidate) (string, bool) {
	var match *integrationTypeCandidate
	if manifestID := strings.TrimSpace(typeRef.ManifestID); manifestID != "" {
		parsed, err := uuid.Parse(manifestID)
		if err != nil {
			return "", false
		}
		for index := range candidates {
			if candidates[index].ID == parsed {
				match = &candidates[index]
				break
			}
		}
	} else {
		name := strings.ToLower(strings.TrimSpace(typeRef.Name))
		if name == "" {
			return "", false
		}
		namespace := strings.ToLower(strings.TrimSpace(typeRef.Namespace))
		if namespace == "" {
			namespace = "global"
		}
		for index := range candidates {
			candidate := &candidates[index]
			if candidate.Namespace != namespace || candidate.Name != name {
				continue
			}
			if typeRef.Version != nil && candidate.Version != *typeRef.Version {
				continue
			}
			match = candidate
			break
		}
	}
	if match == nil {
		return "", false
	}
	provider := strings.TrimSpace(match.Provider)
	if provider == "" {
		return "", false
	}
	return provider, true
}
