package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
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

func TestGetOIDCClientByID_NotFound(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	_, err := GetOIDCClientByID(context.Background(), db, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent client, got nil")
	}
	if err != ErrOIDCClientNotFound {
		t.Errorf("want ErrOIDCClientNotFound, got %v", err)
	}
}

func TestUpsertAndGetOIDCClient(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_clients WHERE client_id='test-client'`)
	})
	c := model.OIDCClient{
		ClientID:               "test-client",
		ClientSecretHash:       "$2a$10$fakehash",
		RedirectURIs:           []string{"https://example.test/callback"},
		PostLogoutRedirectURIs: []string{"https://example.test/"},
		Scopes:                 []string{"openid", "email"},
		GrantTypes:             []string{"authorization_code"},
		PKCERequired:           true,
	}
	if err := UpsertOIDCClient(context.Background(), db, c); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := GetOIDCClientByID(context.Background(), db, "test-client")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientID != "test-client" || !got.PKCERequired || len(got.RedirectURIs) != 1 {
		t.Errorf("round-trip lost data: %+v", got)
	}
}
