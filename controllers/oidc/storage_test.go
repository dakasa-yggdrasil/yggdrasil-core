package oidc

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	_ "github.com/lib/pq"
)

func dbForStorageTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping OIDC storage integration test")
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

func TestStorage_GetClientByClientID(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_clients WHERE client_id='storage-test-client'`)
	})
	_, _ = db.ExecContext(context.Background(),
		`DELETE FROM oidc_clients WHERE client_id='storage-test-client'`)

	if err := repository.UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID:               "storage-test-client",
		ClientSecretHash:       "$2a$10$irrelevant",
		RedirectURIs:           []string{"https://x.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid", "email"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		PKCERequired:           true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	s := NewStorage(db, "https://yggdrasil.test")
	c, err := s.GetClientByClientID(context.Background(), "storage-test-client")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.GetID() != "storage-test-client" {
		t.Errorf("client id: %q", c.GetID())
	}
	if len(c.RedirectURIs()) != 1 {
		t.Errorf("redirect uris len: %d", len(c.RedirectURIs()))
	}
	if !c.IsScopeAllowed("openid") {
		t.Errorf("openid scope should be allowed")
	}
	if c.IsScopeAllowed("admin") {
		t.Errorf("admin scope should not be allowed")
	}
}

func TestStorage_AuthorizeClientIDSecret_HappyAndInvalid(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_clients WHERE client_id='storage-test-client-bcrypt'`)
	})
	_, _ = db.ExecContext(context.Background(),
		`DELETE FROM oidc_clients WHERE client_id='storage-test-client-bcrypt'`)

	// bcrypt hash of "secret-pass" generated with cost=10. Tests that
	// bcryptCompare round-trips against a real hash.
	hash := "$2a$10$aLC10NVpx4ZKC8M8MoE/senuHYdbOt/MV9xDfr9UdzW.MVQ07T8wW"
	if err := repository.UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID:               "storage-test-client-bcrypt",
		ClientSecretHash:       hash,
		RedirectURIs:           []string{"https://x.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid"},
		GrantTypes:             []string{"authorization_code"},
		PKCERequired:           true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	s := NewStorage(db, "https://yggdrasil.test")
	if err := s.AuthorizeClientIDSecret(context.Background(),
		"storage-test-client-bcrypt", "secret-pass"); err != nil {
		t.Errorf("expected happy path success, got %v", err)
	}
	if err := s.AuthorizeClientIDSecret(context.Background(),
		"storage-test-client-bcrypt", "wrong"); err == nil {
		t.Errorf("expected error on wrong secret")
	}
}
