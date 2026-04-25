package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// ErrBindingNotFound is returned by FindBindingByRepository when no
// repository_binding manifest matches the requested repository slug.
var ErrBindingNotFound = errors.New("repository_binding not found")

// FindBindingByRepository looks up the active repository_binding manifest whose
// spec.repository matches the given owner/name slug. Returns ErrBindingNotFound
// when no matching active binding exists.
//
// The query relies on the partial index manifests_repository_binding_lookup
// (added in migration 00016). At most one active binding per repository is
// permitted by the partial unique index manifests_repository_binding_unique_repo.
func FindBindingByRepository(ctx context.Context, db *sql.DB, repository string) (*model.RepositoryBindingManifest, error) {
	const q = `
		SELECT namespace, name, COALESCE(description, ''), spec
		FROM public.manifests
		WHERE kind = 'repository_binding'
		  AND active = TRUE
		  AND spec->>'repository' = $1
		LIMIT 1
	`
	var (
		namespace   string
		name        string
		description string
		rawSpec     []byte
	)
	err := db.QueryRowContext(ctx, q, repository).Scan(&namespace, &name, &description, &rawSpec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrBindingNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository_binding lookup: %w", err)
	}
	var spec model.RepositoryBindingManifestSpec
	if err := json.Unmarshal(rawSpec, &spec); err != nil {
		return nil, fmt.Errorf("decode repository_binding spec: %w", err)
	}
	return &model.RepositoryBindingManifest{
		Metadata: model.ManifestMetadata{
			Namespace:   namespace,
			Name:        name,
			Description: description,
			Active:      true,
		},
		Spec: spec,
	}, nil
}
