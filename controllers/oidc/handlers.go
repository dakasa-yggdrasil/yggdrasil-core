package oidc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// MountOIDC builds an op.Provider backed by our Storage and registers its
// HTTP routes on the given mux. The discovery document is served at the
// well-known absolute path; the rest of the OP routes (authorize, token,
// userinfo, etc.) are mounted under /oidc/ via http.StripPrefix so they
// don't collide with existing yggdrasil API routes.
//
// MountOIDC requires that an active signing key already exists in the DB —
// callers must invoke EnsureSigningKey before mounting (the active key's
// PrivatePEM is hashed to derive op.Config.CryptoKey, which is used by the
// OP to encrypt code-exchange artifacts in the URL fragment of the auth
// callback).
func MountOIDC(mux *http.ServeMux, db *sql.DB, issuerURL string) error {
	cryptoKey, err := deriveCryptoKey(context.Background(), db)
	if err != nil {
		return fmt.Errorf("derive oidc crypto key: %w", err)
	}

	storage := NewStorage(db, issuerURL)
	cfg := &op.Config{
		CryptoKey:               cryptoKey,
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  false,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   false,
	}
	provider, err := op.NewProvider(cfg, storage, op.StaticIssuer(issuerURL))
	if err != nil {
		return fmt.Errorf("oidc new provider: %w", err)
	}

	// Discovery is served at the absolute well-known path so existing
	// clients (RFC 8414) find it without prefix knowledge.
	mux.Handle("/.well-known/openid-configuration", provider)
	// Everything else (authorize, token, userinfo, jwks, etc.) lives
	// under /oidc/ to avoid colliding with the existing /api/v1 surface.
	mux.Handle("/oidc/", http.StripPrefix("/oidc", provider))

	return nil
}

// deriveCryptoKey returns a deterministic 32-byte key derived from the
// active OIDC signing key's PrivatePEM. We use sha256 of the PEM body so
// the value rotates whenever signing keys rotate (acceptable: the only
// short-lived state encrypted with this key is the auth-code window of
// ~10 minutes; refresh tokens are stored hashed and unaffected).
//
// Choosing this over a static env var keeps the deployment story simple —
// no extra secret to provision, and CryptoKey rotation is implicit in the
// existing key-rotation runbook.
func deriveCryptoKey(ctx context.Context, db *sql.DB) ([32]byte, error) {
	key, err := repository.GetCurrentOIDCSigningKey(ctx, db, SigningAlgorithm)
	if err != nil {
		return [32]byte{}, fmt.Errorf("fetch active signing key: %w", err)
	}
	if key.PrivatePEM == "" {
		return [32]byte{}, fmt.Errorf("active signing key has empty PrivatePEM")
	}
	return sha256.Sum256([]byte(key.PrivatePEM)), nil
}
