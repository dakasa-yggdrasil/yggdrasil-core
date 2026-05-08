package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrSCIMClientNotFound = errors.New("scim client not found")

// CreateSCIMClient persists a new SCIM bearer credential. The bearerHash is the
// SHA-256 of the raw token; only the hash is stored.
func CreateSCIMClient(ctx context.Context, db *sql.DB, slug, bearerHash string, permissions map[string]string, expiresAt *time.Time) (model.SCIMClient, error) {
	if slug == "" {
		return model.SCIMClient{}, fmt.Errorf("scim client slug required")
	}
	if bearerHash == "" {
		return model.SCIMClient{}, fmt.Errorf("bearer_token_hash required")
	}
	permsJSON, err := json.Marshal(permissions)
	if err != nil {
		return model.SCIMClient{}, fmt.Errorf("marshal permissions: %w", err)
	}
	if string(permsJSON) == "null" {
		permsJSON = []byte(`{"users":"read","groups":"read"}`)
	}
	row := db.QueryRowContext(ctx, `
		INSERT INTO public.scim_clients (slug, bearer_token_hash, permissions, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, slug, bearer_token_hash, permissions, last_used_at,
			expires_at, revoked_at, metadata, created_at, updated_at
	`, slug, bearerHash, permsJSON, expiresAt)
	return scanSCIMClient(row)
}

// GetSCIMClientByBearerHash resolves the client from a hashed token and
// validates it isn't revoked or expired. Side effect: bumps last_used_at.
func GetSCIMClientByBearerHash(ctx context.Context, db *sql.DB, bearerHash string) (model.SCIMClient, error) {
	row := db.QueryRowContext(ctx, `
		UPDATE public.scim_clients
		SET last_used_at = NOW()
		WHERE bearer_token_hash = $1
			AND revoked_at IS NULL
			AND (expires_at IS NULL OR expires_at > NOW())
		RETURNING id, slug, bearer_token_hash, permissions, last_used_at,
			expires_at, revoked_at, metadata, created_at, updated_at
	`, bearerHash)
	c, err := scanSCIMClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SCIMClient{}, ErrSCIMClientNotFound
	}
	return c, err
}

func GetSCIMClientBySlug(ctx context.Context, db *sql.DB, slug string) (model.SCIMClient, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, slug, bearer_token_hash, permissions, last_used_at,
			expires_at, revoked_at, metadata, created_at, updated_at
		FROM public.scim_clients WHERE slug = $1
	`, slug)
	c, err := scanSCIMClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.SCIMClient{}, ErrSCIMClientNotFound
	}
	return c, err
}

func ListSCIMClients(ctx context.Context, db *sql.DB, includeRevoked bool) ([]model.SCIMClient, error) {
	q := `
		SELECT id, slug, bearer_token_hash, permissions, last_used_at,
			expires_at, revoked_at, metadata, created_at, updated_at
		FROM public.scim_clients
	`
	if !includeRevoked {
		q += ` WHERE revoked_at IS NULL `
	}
	q += ` ORDER BY slug ASC `
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list scim clients: %w", err)
	}
	defer rows.Close()
	var out []model.SCIMClient
	for rows.Next() {
		c, err := scanSCIMClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func RevokeSCIMClient(ctx context.Context, db *sql.DB, slug string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE public.scim_clients
		SET revoked_at = NOW()
		WHERE slug = $1 AND revoked_at IS NULL
	`, slug)
	if err != nil {
		return fmt.Errorf("revoke scim client: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrSCIMClientNotFound
	}
	return nil
}

func scanSCIMClient(r rowScanner) (model.SCIMClient, error) {
	var c model.SCIMClient
	var permsJSON, metaJSON []byte
	if err := r.Scan(
		&c.ID, &c.Slug, &c.BearerTokenHash, &permsJSON, &c.LastUsedAt,
		&c.ExpiresAt, &c.RevokedAt, &metaJSON, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return model.SCIMClient{}, err
	}
	if len(permsJSON) > 0 {
		if err := json.Unmarshal(permsJSON, &c.Permissions); err != nil {
			return model.SCIMClient{}, fmt.Errorf("unmarshal permissions: %w", err)
		}
	}
	if c.Permissions == nil {
		c.Permissions = map[string]string{}
	}
	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &c.Metadata); err != nil {
			return model.SCIMClient{}, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	if c.Metadata == nil {
		c.Metadata = map[string]interface{}{}
	}
	return c, nil
}

// silence linter
var _ = uuid.Nil
