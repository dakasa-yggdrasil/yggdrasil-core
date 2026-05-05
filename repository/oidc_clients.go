package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
)

var ErrOIDCClientNotFound = errors.New("oidc client not found")

func GetOIDCClientByID(ctx context.Context, db *sql.DB, clientID string) (model.OIDCClient, error) {
	row := db.QueryRowContext(ctx, `
		SELECT client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
		       scopes, grant_types, pkce_required, created_at
		FROM oidc_clients
		WHERE client_id = $1
	`, clientID)
	var c model.OIDCClient
	err := row.Scan(
		&c.ClientID,
		&c.ClientSecretHash,
		pq.Array(&c.RedirectURIs),
		pq.Array(&c.PostLogoutRedirectURIs),
		pq.Array(&c.Scopes),
		pq.Array(&c.GrantTypes),
		&c.PKCERequired,
		&c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCClient{}, ErrOIDCClientNotFound
	}
	if err != nil {
		return model.OIDCClient{}, fmt.Errorf("get oidc client: %w", err)
	}
	return c, nil
}

func UpsertOIDCClient(ctx context.Context, db *sql.DB, c model.OIDCClient) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO oidc_clients (
			client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
			scopes, grant_types, pkce_required
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret_hash = EXCLUDED.client_secret_hash,
			redirect_uris = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			scopes = EXCLUDED.scopes,
			grant_types = EXCLUDED.grant_types,
			pkce_required = EXCLUDED.pkce_required
	`,
		c.ClientID,
		c.ClientSecretHash,
		pq.Array(c.RedirectURIs),
		pq.Array(c.PostLogoutRedirectURIs),
		pq.Array(c.Scopes),
		pq.Array(c.GrantTypes),
		c.PKCERequired,
	)
	if err != nil {
		return fmt.Errorf("upsert oidc client: %w", err)
	}
	return nil
}
