//go:build capacitytest

package main

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsolatedDSN(t *testing.T) {
	t.Setenv("CAPACITY_TEST_ALLOW", "isolated-postgresql-only")
	socket := filepath.Join(t.TempDir(), "socket")
	if err := os.Mkdir(socket, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPACITY_TEST_SOCKET_DIR", socket)
	local := "postgres://postgres@/ci_capacity_test?sslmode=disable&port=54383&host=" + url.QueryEscape(socket)
	tests := []struct {
		name, dsn string
		allowed   bool
	}{
		{"local socket", local, true},
		{"remote", "postgres://postgres@example.org:5432/ci_capacity_test?sslmode=disable", false},
		{"loopback", "postgres://postgres@127.0.0.1:5432/ci_capacity_test?sslmode=disable", false},
		{"password prohibited", strings.Replace(local, "postgres@", "postgres:secret@", 1), false},
		{"wrong database", strings.Replace(local, "ci_capacity_test", "production", 1), false},
		{"host override", local + "&host=example.org", false},
		{"duplicate ssl", local + "&sslmode=require", false},
		{"foreign socket", strings.Replace(local, url.QueryEscape(socket), "%2Ftmp%2Fother", 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := checkDSN(tt.dsn)
			if (err == nil) != tt.allowed {
				t.Fatalf("allowed=%t, err=%v", tt.allowed, err)
			}
		})
	}
	t.Setenv("CAPACITY_TEST_ALLOW", "")
	if _, err := checkDSN(local); err == nil {
		t.Fatal("missing explicit isolation acknowledgement")
	}
}

func TestClosedRequest(t *testing.T) {
	valid := `{"schema":"ci_original_grant_concurrency_v1","source_root":"/tmp/source","policy_id":"a5d69e99-774d-46c8-a9a7-5152f9835919","workflow_id":"a5d69e99-774d-46c8-a9a7-5152f983591a","generation":1,"fence":1,"lease_owner":"a5d69e99-774d-46c8-a9a7-5152f983591b","executor_id":"a5d69e99-774d-46c8-a9a7-5152f983591c","binding_name":"fixture","slot":1,"nonce_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	tests := []struct {
		name, input string
		allowed     bool
	}{
		{"valid", valid, true},
		{"unknown", strings.Replace(valid, `"slot":1`, `"slot":1,"extra":true`, 1), false},
		{"duplicate", strings.Replace(valid, `"slot":1`, `"slot":1,"slot":2`, 1), false},
		{"trailing object", valid + `{}`, false},
		{"invalid digest", strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("G", 64), 1), false},
		{"noncanonical owner", strings.Replace(valid, "a5d69e99-774d-46c8-a9a7-5152f983591b", "A5D69E99-774D-46C8-A9A7-5152F983591B", 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeRequest(strings.NewReader(tt.input))
			if (err == nil) != tt.allowed {
				t.Fatalf("allowed=%t, err=%v", tt.allowed, err)
			}
		})
	}
}

func TestOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("CAPACITY_TEST_OWNED_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_OWNED_POSTGRES") == "true" {
			t.Fatal("owned PostgreSQL fixture required")
		}
		t.Skip("owned PostgreSQL fixture not requested")
	}
	name, err := checkDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = checkOwnedPostgres(ctx, db, name, os.Getenv("CAPACITY_TEST_SOCKET_DIR")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPACITY_TEST_PG_SYSTEM_ID", "1")
	if err = checkOwnedPostgres(ctx, db, name, os.Getenv("CAPACITY_TEST_SOCKET_DIR")); err == nil {
		t.Fatal("foreign system identifier accepted")
	}
}
