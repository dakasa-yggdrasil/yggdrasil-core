package password

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func dbForRotationTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping rotation integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

func TestSelectRotationBatchExcludesNonActive(t *testing.T) {
	db := dbForRotationTest(t)
	defer db.Close()
	ctx := context.Background()

	_, _ = db.Exec(`DELETE FROM auth_identities WHERE collaborator_id IN (SELECT id FROM collaborators WHERE slug LIKE 'rot-test-%')`)
	_, _ = db.Exec(`DELETE FROM collaborators WHERE slug LIKE 'rot-test-%'`)

	for _, suffix := range []string{"active", "suspended"} {
		status := "active"
		if suffix == "suspended" {
			status = "suspended"
		}
		_, err := db.Exec(`
            INSERT INTO collaborators (slug, display_name, primary_email, status)
            VALUES ($1, $1, $1 || '@test.dakasa.co', $2)
        `, "rot-test-"+suffix, status)
		if err != nil {
			t.Fatalf("insert collaborator %s: %v", suffix, err)
		}
		_, err = db.Exec(`
            INSERT INTO auth_identities (collaborator_id, username, password_hash, password_scheme, password_updated_at, password_expires_at)
            SELECT id, slug, 'h', 'argon2id', NOW() - INTERVAL '120 days', NOW() - INTERVAL '30 days'
            FROM collaborators WHERE slug = $1
        `, "rot-test-"+suffix)
		if err != nil {
			t.Fatalf("insert auth_identity %s: %v", suffix, err)
		}
	}

	ids, err := SelectRotationBatch(ctx, db, 100)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 eligible, got %d", len(ids))
	}

	if err := MarkForRotation(ctx, db, ids); err != nil {
		t.Fatalf("mark: %v", err)
	}
	var mustChange bool
	if err := db.QueryRow(`SELECT password_must_change FROM auth_identities WHERE collaborator_id = $1`, ids[0]).Scan(&mustChange); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !mustChange {
		t.Fatalf("expected must_change=true after MarkForRotation")
	}
	again, _ := SelectRotationBatch(ctx, db, 100)
	for _, id := range again {
		if id == ids[0] {
			t.Fatalf("MarkForRotation not idempotent: id reappears")
		}
	}
	_ = time.Now()
}
