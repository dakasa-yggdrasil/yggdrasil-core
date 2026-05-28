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

// TestUpdateOIDCClientAccessTokenLifetime covers the A10 helper: NULL by
// default, settable to a valid value, settable back to NULL, and the
// CHECK constraint rejects out-of-bounds. Integration test — requires DB_URL.
func TestUpdateOIDCClientAccessTokenLifetime(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_clients WHERE client_id='ttl-test-client'`)
	})

	if err := UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID:               "ttl-test-client",
		ClientSecretHash:       "$2a$10$fake",
		RedirectURIs:           []string{"https://example.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid"},
		GrantTypes:             []string{"authorization_code"},
		PKCERequired:           true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// 1. Fresh row has no override.
	got, err := GetOIDCClientByID(context.Background(), db, "ttl-test-client")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AccessTokenLifetimeSeconds != nil {
		t.Errorf("fresh row should have NULL override, got %v", *got.AccessTokenLifetimeSeconds)
	}

	// 2. Set a valid override.
	ttl := 120
	if err := UpdateOIDCClientAccessTokenLifetime(context.Background(), db, "ttl-test-client", &ttl); err != nil {
		t.Fatalf("update to 120: %v", err)
	}
	got, _ = GetOIDCClientByID(context.Background(), db, "ttl-test-client")
	if got.AccessTokenLifetimeSeconds == nil || *got.AccessTokenLifetimeSeconds != 120 {
		t.Errorf("after set: expected 120, got %v", got.AccessTokenLifetimeSeconds)
	}

	// 3. Clear the override.
	if err := UpdateOIDCClientAccessTokenLifetime(context.Background(), db, "ttl-test-client", nil); err != nil {
		t.Fatalf("update to nil: %v", err)
	}
	got, _ = GetOIDCClientByID(context.Background(), db, "ttl-test-client")
	if got.AccessTokenLifetimeSeconds != nil {
		t.Errorf("after clear: expected nil, got %v", *got.AccessTokenLifetimeSeconds)
	}

	// 4. CHECK constraint rejects out-of-bounds.
	for _, bad := range []int{0, 59, 86401, 100000} {
		v := bad
		err := UpdateOIDCClientAccessTokenLifetime(context.Background(), db, "ttl-test-client", &v)
		if err == nil {
			t.Errorf("CHECK should reject %d, got nil error", bad)
		}
	}

	// 5. Unknown client → ErrOIDCClientNotFound.
	v := 120
	if err := UpdateOIDCClientAccessTokenLifetime(context.Background(), db, "no-such-client", &v); err != ErrOIDCClientNotFound {
		t.Errorf("unknown client: expected ErrOIDCClientNotFound, got %v", err)
	}
}
