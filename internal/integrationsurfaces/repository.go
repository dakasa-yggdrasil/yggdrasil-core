package integrationsurfaces

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrNotFound = errors.New("integration surface not found")

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Upsert(ctx context.Context, m *Manifest) error {
	specJSON, err := json.Marshal(m.Spec)
	if err != nil {
		return fmt.Errorf("marshal spec: %w", err)
	}
	const q = `
INSERT INTO integration_surfaces (name, integration_type, category, spec, active)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (name) DO UPDATE
SET integration_type = EXCLUDED.integration_type,
    category = EXCLUDED.category,
    spec = EXCLUDED.spec,
    active = EXCLUDED.active
RETURNING id, registered_at, updated_at`

	row := r.db.QueryRowContext(ctx, q, m.Name, m.IntegrationType, string(m.Category), specJSON, m.Active)
	return row.Scan(&m.ID, &m.RegisteredAt, &m.UpdatedAt)
}

func (r *Repository) GetByName(ctx context.Context, name string) (*Manifest, error) {
	const q = `
SELECT id, name, integration_type, category, spec, active, registered_at, updated_at
FROM integration_surfaces
WHERE name = $1`
	var (
		m       Manifest
		specRaw []byte
		intType sql.NullString
		cat     string
	)
	err := r.db.QueryRowContext(ctx, q, name).Scan(
		&m.ID, &m.Name, &intType, &cat, &specRaw, &m.Active, &m.RegisteredAt, &m.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	if intType.Valid {
		s := intType.String
		m.IntegrationType = &s
	}
	m.Category = Category(cat)
	if err := json.Unmarshal(specRaw, &m.Spec); err != nil {
		return nil, fmt.Errorf("unmarshal spec: %w", err)
	}
	return &m, nil
}

type ListFilter struct {
	AppearsOn       string
	IntegrationType string
	Category        string
}

func (r *Repository) List(ctx context.Context, f ListFilter) ([]Manifest, error) {
	where := "active = true"
	args := []any{}
	i := 1
	if f.AppearsOn != "" {
		where += fmt.Sprintf(" AND spec->'display'->'appears_on' @> $%d::jsonb", i)
		args = append(args, fmt.Sprintf(`["%s"]`, f.AppearsOn))
		i++
	}
	if f.IntegrationType != "" {
		where += fmt.Sprintf(" AND integration_type = $%d", i)
		args = append(args, f.IntegrationType)
		i++
	}
	if f.Category != "" {
		where += fmt.Sprintf(" AND category = $%d", i)
		args = append(args, f.Category)
	}

	q := fmt.Sprintf(`
SELECT id, name, integration_type, category, spec, active, registered_at, updated_at
FROM integration_surfaces
WHERE %s
ORDER BY updated_at DESC`, where)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Manifest{}
	for rows.Next() {
		var (
			m       Manifest
			specRaw []byte
			intType sql.NullString
			cat     string
		)
		if err := rows.Scan(&m.ID, &m.Name, &intType, &cat, &specRaw, &m.Active, &m.RegisteredAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		if intType.Valid {
			s := intType.String
			m.IntegrationType = &s
		}
		m.Category = Category(cat)
		if err := json.Unmarshal(specRaw, &m.Spec); err != nil {
			return nil, fmt.Errorf("unmarshal spec for %s: %w", m.Name, err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Repository) Deactivate(ctx context.Context, name string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE integration_surfaces SET active = false WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) Touch(ctx context.Context, name string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE integration_surfaces SET updated_at = now() WHERE name = $1`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
