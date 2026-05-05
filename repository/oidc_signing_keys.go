package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrOIDCSigningKeyNotFound = errors.New("oidc signing key not found")

func CreateOIDCSigningKey(ctx context.Context, db *sql.DB, k model.OIDCSigningKey) (uuid.UUID, error) {
	jwkBytes, err := json.Marshal(k.PublicJWK)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal jwk: %w", err)
	}
	var id uuid.UUID
	err = db.QueryRowContext(ctx, `
		INSERT INTO oidc_signing_keys (algorithm, private_pem, public_jwk, active_at)
		VALUES ($1, $2, $3::jsonb, $4)
		RETURNING id
	`, k.Algorithm, k.PrivatePEM, string(jwkBytes), k.ActiveAt).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create signing key: %w", err)
	}
	return id, nil
}

// ListActiveOIDCSigningKeys returns all keys whose active_at is in the
// past and whose retire_at is either NULL or in the future. Ordered by
// active_at DESC (newest first) — caller's "current" is index 0.
func ListActiveOIDCSigningKeys(ctx context.Context, db *sql.DB, algorithm string) ([]model.OIDCSigningKey, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, algorithm, private_pem, public_jwk, created_at, active_at, retire_at
		FROM oidc_signing_keys
		WHERE algorithm = $1 AND active_at <= NOW() AND (retire_at IS NULL OR retire_at > NOW())
		ORDER BY active_at DESC
	`, algorithm)
	if err != nil {
		return nil, fmt.Errorf("list active keys: %w", err)
	}
	defer rows.Close()
	var keys []model.OIDCSigningKey
	for rows.Next() {
		var k model.OIDCSigningKey
		var jwkBytes []byte
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PrivatePEM, &jwkBytes, &k.CreatedAt, &k.ActiveAt, &k.RetireAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if err := json.Unmarshal(jwkBytes, &k.PublicJWK); err != nil {
			return nil, fmt.Errorf("unmarshal jwk: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// GetCurrentOIDCSigningKey returns the most recently activated key. Used
// when a single key is needed (e.g., for issuing a fresh JWT).
func GetCurrentOIDCSigningKey(ctx context.Context, db *sql.DB, algorithm string) (model.OIDCSigningKey, error) {
	keys, err := ListActiveOIDCSigningKeys(ctx, db, algorithm)
	if err != nil {
		return model.OIDCSigningKey{}, err
	}
	if len(keys) == 0 {
		return model.OIDCSigningKey{}, ErrOIDCSigningKeyNotFound
	}
	return keys[0], nil
}
