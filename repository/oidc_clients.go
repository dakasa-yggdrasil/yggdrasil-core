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
		       scopes, grant_types, pkce_required,
		       COALESCE(backchannel_logout_uri, ''),
		       access_token_lifetime_seconds,
		       created_at
		FROM oidc_clients
		WHERE client_id = $1
	`, clientID)
	var c model.OIDCClient
	var accessTokenTTL sql.NullInt64
	err := row.Scan(
		&c.ClientID,
		&c.ClientSecretHash,
		pq.Array(&c.RedirectURIs),
		pq.Array(&c.PostLogoutRedirectURIs),
		pq.Array(&c.Scopes),
		pq.Array(&c.GrantTypes),
		&c.PKCERequired,
		&c.BackchannelLogoutURI,
		&accessTokenTTL,
		&c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.OIDCClient{}, ErrOIDCClientNotFound
	}
	if err != nil {
		return model.OIDCClient{}, fmt.Errorf("get oidc client: %w", err)
	}
	if accessTokenTTL.Valid {
		v := int(accessTokenTTL.Int64)
		c.AccessTokenLifetimeSeconds = &v
	}
	return c, nil
}

func UpsertOIDCClient(ctx context.Context, db *sql.DB, c model.OIDCClient) error {
	// nullable text column: empty string → NULL keeps the column semantically
	// "opted out of back-channel logout" instead of "registered as empty".
	var bcl any
	if c.BackchannelLogoutURI != "" {
		bcl = c.BackchannelLogoutURI
	}
	// access_token_lifetime_seconds is NULL by default (use global TTL); a
	// positive int overrides per-client (audit 2026-05-27 A10).
	var accessTokenTTL any
	if c.AccessTokenLifetimeSeconds != nil {
		accessTokenTTL = *c.AccessTokenLifetimeSeconds
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO oidc_clients (
			client_id, client_secret_hash, redirect_uris, post_logout_redirect_uris,
			scopes, grant_types, pkce_required, backchannel_logout_uri,
			access_token_lifetime_seconds
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret_hash = EXCLUDED.client_secret_hash,
			redirect_uris = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			scopes = EXCLUDED.scopes,
			grant_types = EXCLUDED.grant_types,
			pkce_required = EXCLUDED.pkce_required,
			backchannel_logout_uri = EXCLUDED.backchannel_logout_uri,
			access_token_lifetime_seconds = EXCLUDED.access_token_lifetime_seconds
	`,
		c.ClientID,
		c.ClientSecretHash,
		pq.Array(c.RedirectURIs),
		pq.Array(c.PostLogoutRedirectURIs),
		pq.Array(c.Scopes),
		pq.Array(c.GrantTypes),
		c.PKCERequired,
		bcl,
		accessTokenTTL,
	)
	if err != nil {
		return fmt.Errorf("upsert oidc client: %w", err)
	}
	return nil
}

// UpdateOIDCClientAccessTokenLifetime patches just the per-client
// AccessTokenLifetime override (audit 2026-05-27 A10). Idempotent: a
// nil seconds value clears the override (revert to global default).
// Validation (bounds [60, 86400]) is enforced by the DB CHECK constraint
// — the caller doesn't have to duplicate it; misformatted requests
// return a 22023 (numeric_value_out_of_range) / 23514 (check_violation)
// surfaced as a wrapped error here.
//
// Returns ErrOIDCClientNotFound when the client doesn't exist so the
// admin handler can map cleanly to HTTP 404.
func UpdateOIDCClientAccessTokenLifetime(
	ctx context.Context,
	db *sql.DB,
	clientID string,
	seconds *int,
) error {
	var v any
	if seconds != nil {
		v = *seconds
	}
	res, err := db.ExecContext(ctx, `
		UPDATE oidc_clients
		SET access_token_lifetime_seconds = $2
		WHERE client_id = $1
	`, clientID, v)
	if err != nil {
		return fmt.Errorf("update oidc client access_token_lifetime: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrOIDCClientNotFound
	}
	return nil
}
