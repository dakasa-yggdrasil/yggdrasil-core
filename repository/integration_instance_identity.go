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
// type_ref resolves to an active integration_type. Callers on an authorization
// path must not distinguish its causes to the client.
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

// Resolves any version (active or inactive, until purged) of an
// integration_instance to that logical instance's active version. Uses the
// primary key for v and manifests_single_active_uidx for a.
const resolveIntegrationInstanceByManifestIDQuery = `
	SELECT a.id, a.namespace, a.name, a.version, a.spec -> 'type_ref'
	FROM public.manifests v
	JOIN public.manifests a
		ON a.kind = v.kind
		AND a.namespace = v.namespace
		AND a.name = v.name
		AND a.active = TRUE
	WHERE v.id = $1
		AND v.kind = 'integration_instance'
`

const resolveIntegrationInstanceByNameQuery = `
	SELECT a.id, a.namespace, a.name, a.version, a.spec -> 'type_ref'
	FROM public.manifests a
	WHERE a.kind = 'integration_instance'
		AND a.namespace = $1
		AND a.name = $2
		AND a.active = TRUE
`

const resolveIntegrationTypeProviderByIDQuery = `
	SELECT COALESCE(spec ->> 'provider', '')
	FROM public.manifests
	WHERE id = $1
		AND kind = 'integration_type'
		AND active = TRUE
`

const resolveIntegrationTypeProviderByNameQuery = `
	SELECT COALESCE(spec ->> 'provider', '')
	FROM public.manifests
	WHERE kind = 'integration_type'
		AND namespace = $1
		AND name = $2
		AND active = TRUE
`

const resolveIntegrationTypeProviderByNameVersionQuery = `
	SELECT COALESCE(spec ->> 'provider', '')
	FROM public.manifests
	WHERE kind = 'integration_type'
		AND namespace = $1
		AND name = $2
		AND version = $3
		AND active = TRUE
`

// ResolveIntegrationInstanceByManifestID resolves the per-version manifest id
// of any not-yet-purged integration_instance version to its logical identity.
func ResolveIntegrationInstanceByManifestID(ctx context.Context, db *sql.DB, manifestID uuid.UUID) (IntegrationInstanceIdentity, error) {
	return resolveIntegrationInstance(ctx, db, resolveIntegrationInstanceByManifestIDQuery, manifestID)
}

// ResolveIntegrationInstanceByName resolves a literal namespace/name to the
// logical integration_instance identity. Both parts must already be in the
// normalized (trimmed, lowercase) form manifests are stored in.
func ResolveIntegrationInstanceByName(ctx context.Context, db *sql.DB, namespace, name string) (IntegrationInstanceIdentity, error) {
	return resolveIntegrationInstance(ctx, db, resolveIntegrationInstanceByNameQuery, namespace, name)
}

func resolveIntegrationInstance(ctx context.Context, db *sql.DB, query string, args ...any) (IntegrationInstanceIdentity, error) {
	var (
		identity   IntegrationInstanceIdentity
		rawTypeRef []byte
	)
	err := db.QueryRowContext(ctx, query, args...).Scan(
		&identity.ActiveManifestID,
		&identity.Namespace,
		&identity.Name,
		&identity.ActiveVersion,
		&rawTypeRef,
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
	provider, err := resolveActiveIntegrationTypeProvider(ctx, db, typeRef)
	if err != nil {
		return IntegrationInstanceIdentity{}, err
	}
	identity.TypeProvider = provider
	return identity, nil
}

// resolveActiveIntegrationTypeProvider mirrors the execution-time type_ref
// resolution (manifest_id, else namespace defaulting to "global" plus name and
// optional version) but always requires the resolved integration_type row to
// be the active one.
func resolveActiveIntegrationTypeProvider(ctx context.Context, db *sql.DB, typeRef model.ManifestSelector) (string, error) {
	var row *sql.Row
	if manifestID := strings.TrimSpace(typeRef.ManifestID); manifestID != "" {
		parsed, err := uuid.Parse(manifestID)
		if err != nil {
			return "", ErrIntegrationInstanceNotResolvable
		}
		row = db.QueryRowContext(ctx, resolveIntegrationTypeProviderByIDQuery, parsed)
	} else {
		name := strings.ToLower(strings.TrimSpace(typeRef.Name))
		if name == "" {
			return "", ErrIntegrationInstanceNotResolvable
		}
		namespace := strings.ToLower(strings.TrimSpace(typeRef.Namespace))
		if namespace == "" {
			namespace = "global"
		}
		if typeRef.Version != nil {
			row = db.QueryRowContext(ctx, resolveIntegrationTypeProviderByNameVersionQuery, namespace, name, *typeRef.Version)
		} else {
			row = db.QueryRowContext(ctx, resolveIntegrationTypeProviderByNameQuery, namespace, name)
		}
	}
	var provider string
	if err := row.Scan(&provider); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrIntegrationInstanceNotResolvable
		}
		return "", err
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "", ErrIntegrationInstanceNotResolvable
	}
	return provider, nil
}
