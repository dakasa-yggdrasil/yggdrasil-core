package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

func dbForReactionsTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping reactions integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func TestMaterializeReactions_Skips(t *testing.T) {
	db := dbForReactionsTest(t)
	defer db.Close()
	// Basic skip-gracefully test
	_ = context.Background()
}
