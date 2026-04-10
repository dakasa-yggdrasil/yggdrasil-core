package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrManifestNotFound = errors.New("manifest not found")

// CreateManifestVersion stores a new manifest version.
func CreateManifestVersion(ctx context.Context, db *sql.DB, doc model.ManifestDocument, checksum string) (model.Manifest, error) {
	labels, err := marshalLabels(doc.Metadata.Labels)
	if err != nil {
		return model.Manifest{}, err
	}

	spec := []byte(doc.Spec)
	if len(spec) == 0 {
		spec = []byte("{}")
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.Manifest{}, err
	}
	defer tx.Rollback()

	var nextVersion int
	err = tx.QueryRowContext(
		ctx,
		`SELECT COALESCE(MAX(version), 0) + 1 FROM public.manifests WHERE kind = $1 AND namespace = $2 AND name = $3`,
		doc.Kind,
		doc.Metadata.Namespace,
		doc.Metadata.Name,
	).Scan(&nextVersion)
	if err != nil {
		return model.Manifest{}, err
	}

	active := documentActive(doc)
	if active {
		_, err = tx.ExecContext(
			ctx,
			`UPDATE public.manifests SET active = FALSE WHERE kind = $1 AND namespace = $2 AND name = $3 AND active = TRUE`,
			doc.Kind,
			doc.Metadata.Namespace,
			doc.Metadata.Name,
		)
		if err != nil {
			return model.Manifest{}, err
		}
	}

	q := `
		INSERT INTO public.manifests (
			api_version,
			kind,
			namespace,
			name,
			version,
			active,
			description,
			labels,
			spec,
			checksum
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8::jsonb,
			$9::jsonb,
			$10
		)
		RETURNING
			id,
			api_version,
			kind,
			namespace,
			name,
			version,
			active,
			description,
			labels,
			spec,
			checksum,
			created_at,
			updated_at
	`

	manifest, err := scanManifest(tx.QueryRowContext(
		ctx,
		q,
		doc.APIVersion,
		doc.Kind,
		doc.Metadata.Namespace,
		doc.Metadata.Name,
		nextVersion,
		active,
		strings.TrimSpace(doc.Metadata.Description),
		labels,
		spec,
		checksum,
	))
	if err != nil {
		return model.Manifest{}, err
	}

	if err := tx.Commit(); err != nil {
		return model.Manifest{}, err
	}

	return manifest, nil
}

// ListManifests returns manifests matching the provided filters.
func ListManifests(ctx context.Context, db *sql.DB, filters model.ListManifestFilters) ([]model.Manifest, error) {
	q := `
		SELECT
			id,
			api_version,
			kind,
			namespace,
			name,
			version,
			active,
			description,
			labels,
			spec,
			checksum,
			created_at,
			updated_at
		FROM public.manifests
	`

	var (
		clauses []string
		args    []any
	)

	if value := strings.TrimSpace(filters.Kind); value != "" {
		args = append(args, strings.ToLower(value))
		clauses = append(clauses, fmt.Sprintf("kind = $%d", len(args)))
	}

	if value := strings.TrimSpace(filters.Namespace); value != "" {
		args = append(args, strings.ToLower(value))
		clauses = append(clauses, fmt.Sprintf("namespace = $%d", len(args)))
	}

	if value := strings.TrimSpace(filters.Name); value != "" {
		args = append(args, strings.ToLower(value))
		clauses = append(clauses, fmt.Sprintf("name = $%d", len(args)))
	}

	if len(filters.Labels) > 0 {
		labels, err := marshalLabels(filters.Labels)
		if err != nil {
			return nil, err
		}
		args = append(args, labels)
		clauses = append(clauses, fmt.Sprintf("labels @> $%d::jsonb", len(args)))
	}

	if filters.ActiveOnly {
		clauses = append(clauses, "active = TRUE")
	}

	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}

	q += " ORDER BY kind, namespace, name, version DESC"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var manifests []model.Manifest
	for rows.Next() {
		manifest, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		manifests = append(manifests, manifest)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return manifests, nil
}

// GetManifestByID returns a manifest by its UUID.
func GetManifestByID(ctx context.Context, db *sql.DB, manifestID uuid.UUID) (model.Manifest, error) {
	q := `
		SELECT
			id,
			api_version,
			kind,
			namespace,
			name,
			version,
			active,
			description,
			labels,
			spec,
			checksum,
			created_at,
			updated_at
		FROM public.manifests
		WHERE id = $1
	`

	manifest, err := scanManifest(db.QueryRowContext(ctx, q, manifestID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Manifest{}, ErrManifestNotFound
		}
		return model.Manifest{}, err
	}

	return manifest, nil
}

// ResolveManifest returns a manifest by logical reference.
func ResolveManifest(ctx context.Context, db *sql.DB, kind, namespace, name string, version *int, activeOnly bool) (model.Manifest, error) {
	q := `
		SELECT
			id,
			api_version,
			kind,
			namespace,
			name,
			version,
			active,
			description,
			labels,
			spec,
			checksum,
			created_at,
			updated_at
		FROM public.manifests
		WHERE kind = $1 AND namespace = $2 AND name = $3
	`

	args := []any{strings.ToLower(strings.TrimSpace(kind)), strings.ToLower(strings.TrimSpace(namespace)), strings.ToLower(strings.TrimSpace(name))}
	if version != nil {
		args = append(args, *version)
		q += fmt.Sprintf(" AND version = $%d", len(args))
	}

	if activeOnly {
		q += " AND active = TRUE"
	}

	q += " ORDER BY version DESC LIMIT 1"

	manifest, err := scanManifest(db.QueryRowContext(ctx, q, args...))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Manifest{}, ErrManifestNotFound
		}
		return model.Manifest{}, err
	}

	return manifest, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanManifest(row scanner) (model.Manifest, error) {
	var manifest model.Manifest
	var namespace string
	var name string
	var active bool
	var description string
	var labels []byte
	var spec []byte

	err := row.Scan(
		&manifest.ID,
		&manifest.APIVersion,
		&manifest.Kind,
		&namespace,
		&name,
		&manifest.Version,
		&active,
		&description,
		&labels,
		&spec,
		&manifest.Checksum,
		&manifest.CreatedAt,
		&manifest.UpdatedAt,
	)
	if err != nil {
		return model.Manifest{}, err
	}

	manifest.Metadata = model.ManifestMetadata{
		Name:        name,
		Namespace:   namespace,
		Description: description,
		Active:      active,
		Labels:      map[string]string{},
	}

	if len(labels) > 0 {
		if err := json.Unmarshal(labels, &manifest.Metadata.Labels); err != nil {
			return model.Manifest{}, err
		}
	}

	manifest.Spec = json.RawMessage(spec)
	return manifest, nil
}

func marshalLabels(labels map[string]string) ([]byte, error) {
	if labels == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(labels)
}

func documentActive(doc model.ManifestDocument) bool {
	if doc.Metadata.Active == nil {
		return true
	}
	return *doc.Metadata.Active
}
