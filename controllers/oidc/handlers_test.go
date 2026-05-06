package oidc

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// dbForHandlersTest opens a *sql.DB pointing at the integration Postgres or
// skips. Mirrors the pattern used in repository.dbForOIDCTest /
// keyring_test.dbForKeyringTest so we don't need to export that helper.
func dbForHandlersTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping OIDC handlers integration test")
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

func TestDiscoveryEndpointReturns200(t *testing.T) {
	db := dbForHandlersTest(t)
	defer db.Close()

	// Ensure at least one signing key exists. MountOIDC needs the active
	// signing key to derive the CryptoKey, and the discovery handler will
	// publish the JWKS URL that points at it.
	if _, err := EnsureSigningKey(context.Background(), db); err != nil {
		t.Fatalf("ensure signing key: %v", err)
	}

	mux := http.NewServeMux()
	if err := MountOIDC(mux, db, "https://yggdrasil.test"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("discovery status: got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"issuer"`) {
		t.Errorf("discovery missing issuer claim, got: %s", string(body))
	}
}
