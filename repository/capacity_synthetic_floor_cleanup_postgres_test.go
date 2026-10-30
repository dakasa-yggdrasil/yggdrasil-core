//go:build !recoveryfixture || nativequalification

package repository

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Exercise independent cleanup with a real open connection in a disposable,
// uniquely named local database. No provider or native process is involved.
func TestFloorFixtureDatabaseCleanupPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("DB_URL required")
		}
		t.Skip("local PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("local DSN required")
	}
	host, socket := u.Hostname(), u.Query().Get("host")
	if !pg16LocalDSN(host, socket) {
		t.Fatal("remote database refused")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal("admin unavailable")
	}
	t.Cleanup(func() { _ = admin.Close() })
	var addr string
	var major int
	if err = admin.QueryRow(`SELECT COALESCE(inet_server_addr()::text,'unix'), current_setting('server_version_num')::int / 10000`).Scan(&addr, &major); err != nil || major != 16 || !pg16LocalServer(host, addr) {
		t.Fatal("actual local PG16 required")
	}
	name := "recovery_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
		t.Fatal("database create failed")
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + pq.QuoteIdentifier(name) + " WITH (FORCE)") })
	u.Path = "/" + name
	active, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("database unavailable")
	}
	defer active.Close()
	if err = active.Ping(); err != nil {
		t.Fatal("fixture connection unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = floorFixtureCleanupAfterJoin(ctx, admin, name, errors.New("unjoined")); err == nil {
		t.Fatal("unjoined child was accepted")
	}
	if err = active.PingContext(ctx); err != nil {
		t.Fatal("unjoined child database was removed")
	}
	if err = floorFixtureCleanupAfterJoin(ctx, admin, name, nil); err != nil {
		t.Fatal("independent cleanup failed")
	}
	if err = active.PingContext(ctx); err == nil {
		t.Fatal("active fixture connection survived cleanup")
	}
	if err = floorFixtureReapDatabase(ctx, admin, "postgres"); err == nil {
		t.Fatal("unowned database name accepted")
	}
}
