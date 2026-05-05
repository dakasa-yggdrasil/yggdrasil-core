package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

func dbForOIDCTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping OIDC repository integration test")
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

func TestOIDCSchemaTablesExist(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	tables := []string{
		"oidc_clients",
		"oidc_auth_requests",
		"oidc_auth_codes",
		"oidc_refresh_tokens",
		"oidc_signing_keys",
		"oidc_provider_settings",
	}
	for _, name := range tables {
		var exists bool
		err := db.QueryRowContext(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
			name,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("query %q: %v", name, err)
		}
		if !exists {
			t.Errorf("expected table %q to exist", name)
		}
	}
}
