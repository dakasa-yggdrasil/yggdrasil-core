//go:build linux && nativequalification

package main

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// This checks the exact export query against the migrated schema and exercises
// its join on transaction-local records. It grants no native authority.
func TestSnapshotReturnProjectionPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Fatal("owned PostgreSQL DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	const request = "00000000-0000-4000-8000-000000000001"
	rows, err := tx.QueryContext(ctx, snapshotReturnProjectionSQL, request)
	if err != nil {
		t.Fatalf("actual schema rejects original query: %v", err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `CREATE TEMP TABLE capacity_guest_runtime_snapshot_challenges(id uuid PRIMARY KEY, intent_id uuid NOT NULL, ordinal integer NOT NULL); CREATE TEMP TABLE capacity_guest_runtime_snapshot_returns(challenge_id uuid PRIMARY KEY, return_sha256 text NOT NULL, original_wire bytea NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pg_temp.capacity_guest_runtime_snapshot_challenges VALUES ('00000000-0000-4000-8000-000000000011',$1,1),('00000000-0000-4000-8000-000000000012',$1,2),('00000000-0000-4000-8000-000000000013','00000000-0000-4000-8000-000000000002',3)`, request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pg_temp.capacity_guest_runtime_snapshot_returns VALUES ('00000000-0000-4000-8000-000000000011','first',decode('01','hex')),('00000000-0000-4000-8000-000000000012','second',decode('02','hex')),('00000000-0000-4000-8000-000000000013','foreign',decode('03','hex'))`)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = tx.QueryContext(ctx, strings.ReplaceAll(snapshotReturnProjectionSQL, "public.", "pg_temp."), request)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var ordinal int
		var digest string
		var wire []byte
		if err = rows.Scan(&ordinal, &digest, &wire); err != nil {
			t.Fatal(err)
		}
		if ordinal != len(names)+1 || len(wire) != 1 || int(wire[0]) != ordinal {
			t.Fatal("original return identity/order lost")
		}
		names = append(names, digest)
	}
	if err = rows.Err(); err != nil || strings.Join(names, ",") != "first,second" {
		t.Fatal("snapshot join lost or admitted a foreign return", names, err)
	}
}
