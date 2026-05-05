package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const SigningAlgorithm = "RS256"

// EnsureSigningKey ensures at least one active RS256 signing key exists in
// the DB. If absent, generates a new RSA-2048 keypair, stores private PEM
// + public JWK, and returns the row. Idempotent across multi-pod startup
// races via SELECT … FOR UPDATE on the oidc_provider_settings singleton row
// inside a serializable transaction.
func EnsureSigningKey(ctx context.Context, db *sql.DB) (model.OIDCSigningKey, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock the singleton settings row to serialize bootstraps from
	// multiple pods. We don't read its content; we only need the lock.
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM oidc_provider_settings WHERE singleton=TRUE FOR UPDATE`); err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("acquire bootstrap lock: %w", err)
	}

	// Re-check inside the lock — another pod may have just created a key.
	keys, err := repository.ListActiveOIDCSigningKeys(ctx, db, SigningAlgorithm)
	if err != nil {
		return model.OIDCSigningKey{}, err
	}
	if len(keys) > 0 {
		_ = tx.Commit()
		return keys[0], nil
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("rsa keygen: %w", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}))

	kid := fmt.Sprintf("yggdrasil-%d", time.Now().UnixNano())
	jwk := publicJWKFromRSA(&priv.PublicKey, kid)

	rec := model.OIDCSigningKey{
		Algorithm:  SigningAlgorithm,
		PrivatePEM: privPEM,
		PublicJWK:  jwk,
		// Set slightly in the past to defeat client/DB clock skew —
		// the ListActive query filters by active_at <= NOW().
		ActiveAt: time.Now().Add(-1 * time.Second),
	}
	if _, err := repository.CreateOIDCSigningKey(ctx, db, rec); err != nil {
		return model.OIDCSigningKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("commit: %w", err)
	}

	// Re-fetch to get DB-assigned id/created_at.
	keys, err = repository.ListActiveOIDCSigningKeys(ctx, db, SigningAlgorithm)
	if err != nil {
		return model.OIDCSigningKey{}, fmt.Errorf("post-create fetch failed: %w", err)
	}
	if len(keys) == 0 {
		return model.OIDCSigningKey{}, fmt.Errorf("post-create fetch returned 0 keys (clock skew?)")
	}
	return keys[0], nil
}

func publicJWKFromRSA(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": kid,
		"n":   base64URLBigInt(pub.N),
		"e":   base64URLBigInt(big.NewInt(int64(pub.E))),
	}
}

func base64URLBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}
