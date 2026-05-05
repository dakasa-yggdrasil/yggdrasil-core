package repository

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestSigningKeyLifecycle(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_signing_keys WHERE algorithm='TEST_RS256'`)
	})
	// Pre-cleanup for rerun-safety
	_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_signing_keys WHERE algorithm='TEST_RS256'`)

	// Empty case
	keys, err := ListActiveOIDCSigningKeys(context.Background(), db, "TEST_RS256")
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 active keys initially, got %d", len(keys))
	}

	// GetCurrent on empty must return ErrOIDCSigningKeyNotFound
	if _, err := GetCurrentOIDCSigningKey(context.Background(), db, "TEST_RS256"); err != ErrOIDCSigningKeyNotFound {
		t.Errorf("expected ErrOIDCSigningKeyNotFound on empty, got %v", err)
	}

	// Insert
	k := model.OIDCSigningKey{
		Algorithm:  "TEST_RS256",
		PrivatePEM: "-----BEGIN FAKE-----\nx\n-----END FAKE-----",
		PublicJWK:  map[string]any{"kty": "RSA", "alg": "RS256", "kid": "test-1"},
		ActiveAt:   time.Now().Add(-1 * time.Hour),
	}
	id, err := CreateOIDCSigningKey(context.Background(), db, k)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id.String() == "" {
		t.Fatal("expected uuid id")
	}

	// List active — must return 1
	keys, err = ListActiveOIDCSigningKeys(context.Background(), db, "TEST_RS256")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1, got %d", len(keys))
	}
	if keys[0].PublicJWK["kid"] != "test-1" {
		t.Errorf("PublicJWK kid round-trip lost: %+v", keys[0].PublicJWK)
	}

	// GetCurrent on populated — must return the key
	current, err := GetCurrentOIDCSigningKey(context.Background(), db, "TEST_RS256")
	if err != nil {
		t.Fatalf("get current: %v", err)
	}
	if current.ID != keys[0].ID {
		t.Errorf("current key id mismatch")
	}
}
