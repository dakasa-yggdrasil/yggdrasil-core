package oidc

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	_ "github.com/lib/pq"
)

func dbForKeyringTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping OIDC keyring test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	return db
}

func TestEnsureSigningKey_CreatesIfAbsent(t *testing.T) {
	db := dbForKeyringTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_signing_keys WHERE algorithm='RS256'`)
	})
	// Pre-cleanup for rerun-safety
	_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_signing_keys WHERE algorithm='RS256'`)

	first, err := EnsureSigningKey(context.Background(), db)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if first.PrivatePEM == "" {
		t.Errorf("first.PrivatePEM is empty")
	}
	if kid, _ := first.PublicJWK["kid"].(string); kid == "" {
		t.Errorf("first.PublicJWK.kid is empty")
	}

	keys, err := repository.ListActiveOIDCSigningKeys(context.Background(), db, "RS256")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key after EnsureSigningKey, got %d", len(keys))
	}

	// Second call must NOT create another (idempotent)
	second, err := EnsureSigningKey(context.Background(), db)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("expected same key on second call, got different id")
	}

	keys, _ = repository.ListActiveOIDCSigningKeys(context.Background(), db, "RS256")
	if len(keys) != 1 {
		t.Errorf("expected idempotent — still 1 key, got %d", len(keys))
	}
}
