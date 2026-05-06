package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
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

	// Pre-cleanup + t.Cleanup so the test is order-independent under
	// `go test -shuffle on`. Mirrors the pattern in keyring_test.go.
	// Note: we deliberately don't touch oidc_provider_settings — its
	// singleton row is the FOR UPDATE lock the keyring uses; deleting it
	// would break subsequent tests that call EnsureSigningKey.
	cleanup := func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_signing_keys WHERE algorithm='RS256'`)
	}
	cleanup()
	t.Cleanup(cleanup)

	// Ensure at least one signing key exists. MountOIDC needs the active
	// signing key to derive the CryptoKey, and the discovery handler will
	// publish the JWKS URL that points at it.
	if _, err := EnsureSigningKey(context.Background(), db); err != nil {
		t.Fatalf("ensure signing key: %v", err)
	}

	mux := http.NewServeMux()
	if err := MountOIDC(context.Background(), mux, db, "https://yggdrasil.test"); err != nil {
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

	var disco struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &disco); err != nil {
		t.Fatalf("decode discovery: %v; body=%s", err, body)
	}
	if disco.Issuer != "https://yggdrasil.test" {
		t.Errorf("issuer: got %q, want %q", disco.Issuer, "https://yggdrasil.test")
	}
	if !strings.HasPrefix(disco.JWKSURI, "https://yggdrasil.test") {
		t.Errorf("jwks_uri: got %q, want prefix %q", disco.JWKSURI, "https://yggdrasil.test")
	}
}

// TestDiscoveryEndpoint_IssuerWithPathServesAtPathPrefix proves the fix
// for the original path-mismatch bug: when the issuer URL includes a
// path (e.g. /oidc), discovery is served at that path's well-known URL
// AND the URLs the discovery doc advertises (authorization_endpoint,
// token_endpoint, jwks_uri) point at routes that actually exist on the
// mux. Before the fix, discovery was hard-coded at root and the
// /oidc/ StripPrefix mount caused an issuer mismatch.
func TestDiscoveryEndpoint_IssuerWithPathServesAtPathPrefix(t *testing.T) {
	db := dbForHandlersTest(t)
	defer db.Close()
	cleanup := func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_signing_keys WHERE algorithm='RS256'`)
	}
	cleanup()
	t.Cleanup(cleanup)
	if _, err := EnsureSigningKey(context.Background(), db); err != nil {
		t.Fatalf("ensure signing key: %v", err)
	}

	mux := http.NewServeMux()
	const issuer = "https://yggdrasil.test/oidc"
	if err := MountOIDC(context.Background(), mux, db, issuer); err != nil {
		t.Fatalf("mount: %v", err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Discovery must be at /oidc/.well-known/... — that's literally
	// <issuer>/.well-known/openid-configuration once you strip the host.
	resp, err := http.Get(srv.URL + "/oidc/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery via path-prefix: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status at /oidc/.well-known/openid-configuration: got %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var disco struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &disco); err != nil {
		t.Fatalf("decode discovery: %v; body=%s", err, body)
	}
	if disco.Issuer != issuer {
		t.Errorf("issuer: got %q, want %q", disco.Issuer, issuer)
	}
	// Each advertised endpoint URL must include the /oidc path prefix
	// AND map to a route that actually responds (not 404).
	for _, pair := range []struct {
		name, url string
	}{
		{"authorization_endpoint", disco.AuthorizationEndpoint},
		{"token_endpoint", disco.TokenEndpoint},
		{"jwks_uri", disco.JWKSURI},
	} {
		if !strings.HasPrefix(pair.url, issuer+"/") {
			t.Errorf("%s = %q, expected to start with %q (path mismatch regression)", pair.name, pair.url, issuer+"/")
		}
	}

	// Sanity: the JWKS endpoint should resolve. Hit the relative path
	// (strip the issuer's scheme+host) on our test server.
	jwksPath := strings.TrimPrefix(disco.JWKSURI, issuer)
	jwksResp, err := http.Get(srv.URL + "/oidc" + jwksPath)
	if err != nil {
		t.Fatalf("jwks via advertised path: %v", err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Errorf("jwks status at %s: got %d, want 200", srv.URL+"/oidc"+jwksPath, jwksResp.StatusCode)
	}
}
