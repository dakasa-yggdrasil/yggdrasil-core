package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrManifestNotFound = errors.New("manifest not found")

// CreateManifestVersion stores a new manifest version.
// CreateManifestVersion creates a new manifest version in its own transaction.
// Use this when the caller has no other state mutations to combine with.
// For atomic mutations (e.g., emitting events alongside the create),
// prefer CreateManifestVersionTx with a caller-managed transaction.
func CreateManifestVersion(ctx context.Context, db *sql.DB, doc model.ManifestDocument, checksum string) (model.Manifest, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.Manifest{}, err
	}
	defer tx.Rollback()

	manifest, err := CreateManifestVersionTx(ctx, tx, doc, checksum)
	if err != nil {
		return model.Manifest{}, err
	}

	if err := tx.Commit(); err != nil {
		return model.Manifest{}, err
	}

	return manifest, nil
}

// CreateManifestVersionTx creates a new manifest version using a caller-provided
// transaction. The caller is responsible for committing or rolling back the tx.
// Use this when the caller needs to combine the manifest creation with other
// state mutations (e.g., emitting an event in the same tx for atomicity).
func CreateManifestVersionTx(ctx context.Context, tx *sql.Tx, doc model.ManifestDocument, checksum string) (model.Manifest, error) {
	labels, err := marshalLabels(doc.Metadata.Labels)
	if err != nil {
		return model.Manifest{}, err
	}

	spec := []byte(doc.Spec)
	if len(spec) == 0 {
		spec = []byte("{}")
	}

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
	// Either branch deactivates previously-active versions:
	//   - active=true: the new version becomes the active one (standard flow).
	//   - active=false: the new version is a tombstone — nothing is active
	//     for this (kind, namespace, name) afterwards. Without this branch,
	//     posting metadata.active=false would leave the previous version
	//     still active and the tombstone dangling at the end of the table.
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

	return manifest, nil
}

// ListManifests returns manifests matching the provided filters.
// ListManifests returns all manifests matching the given filters, without
// pagination. Intended for internal callers with bounded result sets
// (e.g., catalog discovery, heimdall observers). For external RPC-facing
// lists where result sets can grow large, prefer ListManifestsPaginated.
func ListManifests(ctx context.Context, db *sql.DB, filters model.ListManifestFilters) ([]model.Manifest, error) {
	q, args := buildListManifestsQuery(filters)
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

// ListManifestsPaginated returns a single page of manifests matching the
// filters, using cursor-based pagination. The caller passes an opaque cursor
// from a prior response (empty string for the first call) and a limit.
//
// Sort keys supported (via pagination.Sort field):
//   - "" (default): by (updated_at DESC, id DESC)
//   - "updated_at_desc": same as default
//   - "created_at_desc": by (created_at DESC, id DESC)
//   - "name_asc": by (name ASC, id ASC)
//
// Unrecognized sort keys fall back to the default.
func ListManifestsPaginated(
	ctx context.Context,
	db *sql.DB,
	filters model.ListManifestFilters,
	pagination model.PaginationRequest,
) ([]model.Manifest, model.PaginationResponse, error) {
	pagination = NormalizePagination(pagination)

	cursor, err := DecodeCursor(pagination.Cursor)
	if err != nil {
		return nil, model.PaginationResponse{}, fmt.Errorf("invalid cursor: %w", err)
	}

	sortKey := normalizeManifestSortKey(pagination.Sort)

	q, args := buildListManifestsQuery(filters)

	// Append cursor condition + ORDER BY + LIMIT.
	orderBy, cursorClause, cursorArgs := manifestCursorSQL(sortKey, cursor, len(args))
	args = append(args, cursorArgs...)
	if cursorClause != "" {
		if containsWhere(q) {
			q += " AND " + cursorClause
		} else {
			q += " WHERE " + cursorClause
		}
	}
	q += " " + orderBy

	args = append(args, pagination.Limit+1)
	q += fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, model.PaginationResponse{}, err
	}
	defer rows.Close()

	manifests := make([]model.Manifest, 0, pagination.Limit)
	for rows.Next() {
		manifest, err := scanManifest(rows)
		if err != nil {
			return nil, model.PaginationResponse{}, err
		}
		manifests = append(manifests, manifest)
	}
	if err := rows.Err(); err != nil {
		return nil, model.PaginationResponse{}, err
	}

	hasMore := len(manifests) > pagination.Limit
	if hasMore {
		manifests = manifests[:pagination.Limit]
	}

	nextCursor := ""
	if len(manifests) > 0 {
		last := manifests[len(manifests)-1]
		nextCursor = EncodeCursor(Cursor{
			LastID:        last.ID.String(),
			LastSortValue: extractManifestSortValue(last, sortKey),
			SortKey:       sortKey,
		})
	}

	return manifests, model.PaginationResponse{
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

// buildListManifestsQuery returns the base SELECT + WHERE clauses for
// the ListManifests queries (without ORDER BY or LIMIT). Shared by the
// paginated and non-paginated variants.
func buildListManifestsQuery(filters model.ListManifestFilters) (string, []any) {
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
		if err == nil {
			args = append(args, labels)
			clauses = append(clauses, fmt.Sprintf("labels @> $%d::jsonb", len(args)))
		}
	}

	if filters.ActiveOnly {
		clauses = append(clauses, "active = TRUE")
	}

	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}

	return q, args
}

// containsWhere reports whether the accumulated query already has a WHERE
// clause, so callers can know whether to start with WHERE or AND.
func containsWhere(q string) bool {
	return strings.Contains(q, " WHERE ")
}

// normalizeManifestSortKey maps a user-provided sort key to one of the
// supported values. Unrecognized or empty keys fall back to the default.
func normalizeManifestSortKey(sortKey string) string {
	sortKey = strings.ToLower(strings.TrimSpace(sortKey))
	switch sortKey {
	case "", "updated_at_desc":
		return "updated_at_desc"
	case "created_at_desc":
		return "created_at_desc"
	case "name_asc":
		return "name_asc"
	default:
		return "updated_at_desc"
	}
}

// manifestCursorSQL returns (ORDER BY clause, WHERE clause, args) to
// append to a manifest query so it continues from the given cursor.
// startArgIdx is the current length of the args slice before these
// cursor args are appended.
func manifestCursorSQL(sortKey string, cursor Cursor, startArgIdx int) (string, string, []any) {
	cursorHasValue := cursor.LastID != "" && cursor.LastSortValue != nil

	switch sortKey {
	case "created_at_desc":
		orderBy := "ORDER BY created_at DESC, id DESC"
		if !cursorHasValue {
			return orderBy, "", nil
		}
		// Tuple comparison: (created_at, id) < ($n, $n+1)
		clause := fmt.Sprintf("(created_at, id) < ($%d, $%d)", startArgIdx+1, startArgIdx+2)
		return orderBy, clause, []any{cursor.LastSortValue, cursor.LastID}

	case "name_asc":
		orderBy := "ORDER BY name ASC, id ASC"
		if !cursorHasValue {
			return orderBy, "", nil
		}
		clause := fmt.Sprintf("(name, id) > ($%d, $%d)", startArgIdx+1, startArgIdx+2)
		return orderBy, clause, []any{cursor.LastSortValue, cursor.LastID}

	default: // updated_at_desc
		orderBy := "ORDER BY updated_at DESC, id DESC"
		if !cursorHasValue {
			return orderBy, "", nil
		}
		clause := fmt.Sprintf("(updated_at, id) < ($%d, $%d)", startArgIdx+1, startArgIdx+2)
		return orderBy, clause, []any{cursor.LastSortValue, cursor.LastID}
	}
}

// extractManifestSortValue returns the field of the manifest that matches
// the active sort key. Used to build the next cursor.
func extractManifestSortValue(m model.Manifest, sortKey string) interface{} {
	switch sortKey {
	case "created_at_desc":
		return m.CreatedAt.Format("2006-01-02T15:04:05.999999999Z07:00")
	case "name_asc":
		return m.Metadata.Name
	default: // updated_at_desc
		return m.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00")
	}
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

// HardDeleteManifestByID removes every row sharing the logical
// (kind, namespace, name) of the manifest version pointed to by id. This
// matches what operators reach for after a soft-delete pass: when a
// manifest is conceptually gone, all of its historical rows go too.
//
// Returns ErrManifestNotFound if no version row exists for the given id.
// On success returns the number of rows removed (>=1 for the deleted
// version plus any sibling versions of the same logical record).
//
// Wrapped in a tx so the lookup + delete cannot race a concurrent
// CreateManifestVersion writing a new version with the same logical
// triple between SELECT and DELETE.
func HardDeleteManifestByID(ctx context.Context, db *sql.DB, manifestID uuid.UUID) (int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var kind, namespace, name string
	err = tx.QueryRowContext(
		ctx,
		`SELECT kind, namespace, name FROM public.manifests WHERE id = $1`,
		manifestID,
	).Scan(&kind, &namespace, &name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrManifestNotFound
		}
		return 0, err
	}

	res, err := tx.ExecContext(
		ctx,
		`DELETE FROM public.manifests WHERE kind = $1 AND namespace = $2 AND name = $3`,
		kind, namespace, name,
	)
	if err != nil {
		return 0, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return rows, nil
}

// MarkManifestInactiveByID flips active=FALSE for every row sharing the
// logical (kind, namespace, name) of the manifest version pointed to by
// id. It is the soft-delete cousin of HardDeleteManifestByID: history is
// preserved, but the logical manifest is no longer surfaced by
// active_only=true list calls and reconcilers treat it as absent.
//
// Returns ErrManifestNotFound if no version row exists for the given id.
// Returns the count of rows touched (>=0; can be 0 if all versions were
// already inactive — still a non-error idempotent outcome).
func MarkManifestInactiveByID(ctx context.Context, db *sql.DB, manifestID uuid.UUID) (int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var kind, namespace, name string
	err = tx.QueryRowContext(
		ctx,
		`SELECT kind, namespace, name FROM public.manifests WHERE id = $1`,
		manifestID,
	).Scan(&kind, &namespace, &name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrManifestNotFound
		}
		return 0, err
	}

	res, err := tx.ExecContext(
		ctx,
		`UPDATE public.manifests SET active = FALSE, updated_at = NOW() WHERE kind = $1 AND namespace = $2 AND name = $3 AND active = TRUE`,
		kind, namespace, name,
	)
	if err != nil {
		return 0, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return rows, nil
}

// PurgeInactiveManifestsOlderThan removes manifest rows where active=FALSE
// AND updated_at is older than the supplied cutoff. Used by the periodic
// purge runner to bound the size of the manifests table after a wave of
// soft-deletes.
//
// Returns the number of rows removed. Safe to call concurrently with
// writes: the DELETE uses a single statement and only touches rows whose
// active=FALSE state is durable (any concurrent CreateManifestVersion
// for the same logical triple would set the new row's active to TRUE,
// which is outside this DELETE's predicate).
func PurgeInactiveManifestsOlderThan(ctx context.Context, db *sql.DB, cutoff time.Time) (int64, error) {
	res, err := db.ExecContext(
		ctx,
		`DELETE FROM public.manifests WHERE active = FALSE AND updated_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func documentActive(doc model.ManifestDocument) bool {
	if doc.Metadata.Active == nil {
		return true
	}
	return *doc.Metadata.Active
}
