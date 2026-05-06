package oidc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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
// PrivatePEM is hashed to derive op.Config.CryptoKey).
//
// CryptoKey is used by zitadel/oidc to encrypt opaque artifacts the OP
// returns to clients: notably the auth-code value (which wraps the auth
// request ID encrypted with this key) and the opaque access-token wrapper
// (tokenID:subject). Rotating this key invalidates any outstanding artifact
// within its TTL window — auth codes are short-lived (~10 min), and access
// tokens issued before rotation can no longer be decrypted for userinfo /
// revocation / token exchange. Refresh tokens themselves are stored hashed
// in `oidc_refresh_tokens` and unaffected by CryptoKey rotation.
func MountOIDC(ctx context.Context, mux *http.ServeMux, db *sql.DB, issuerURL string) error {
	cryptoKey, err := deriveCryptoKey(ctx, db)
	if err != nil {
		return fmt.Errorf("derive oidc crypto key: %w", err)
	}

	// The issuer URL's path becomes the mount prefix so the routes the
	// discovery doc advertises actually exist on this mux. Example: an
	// issuer of "https://yggdrasil.example/oidc" makes
	// authorization_endpoint = "https://yggdrasil.example/oidc/authorize",
	// and we mount the provider at "/oidc/" (StripPrefix-aware) so that
	// path resolves. An issuer with an empty path mounts at root, which
	// is fine when the host is dedicated to OIDC but collides with
	// /api/v1 if anything else shares the mux — adopters who care should
	// give the issuer a path.
	parsed, err := url.Parse(strings.TrimRight(issuerURL, "/"))
	if err != nil {
		return fmt.Errorf("parse issuer url %q: %w", issuerURL, err)
	}
	prefix := strings.TrimRight(parsed.Path, "/") // "", "/oidc", "/auth/oidc", etc.

	storage := NewStorage(db, issuerURL)
	cfg := &op.Config{
		CryptoKey:                cryptoKey,
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

	// Mount strategy depends on whether the issuer URL has a path:
	//
	//   - Path-bearing issuer (e.g. https://host/oidc): a single
	//     /<path>/ StripPrefix mount handles everything — discovery
	//     at /<path>/.well-known/openid-configuration, plus authorize/
	//     token/userinfo/jwks under the same prefix. The strip lets
	//     the provider see the unprefixed paths it expects, and the
	//     issuer URL it advertises matches the routes that actually
	//     exist on this mux. This is the recommended deploy.
	//
	//   - Path-less issuer (e.g. https://host): keep the legacy split
	//     mount — discovery at root /.well-known/... (no strip) and
	//     other routes at /oidc/ (with strip) for backward compat
	//     with the existing test fixtures and pre-fix deploys. The
	//     discovery doc still advertises root URLs that won't
	//     resolve, so any client following it will 404 — adopters
	//     should migrate to a path-bearing issuer to avoid that.
	if prefix == "" {
		mux.Handle("/.well-known/openid-configuration", provider)
		mux.Handle("/oidc/", http.StripPrefix("/oidc", provider))
	} else {
		mux.Handle(prefix+"/", http.StripPrefix(prefix, provider))
	}

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
//
// Captured at server startup; key rotation requires a server restart for
// the in-memory CryptoKey to refresh. Auth-code signing tracks the DB on
// each request, so token signing rolls forward independently.
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
