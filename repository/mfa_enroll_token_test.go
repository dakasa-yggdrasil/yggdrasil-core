package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

func dbForMFAEnrollTokenTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping mfa_enroll_token integration test")
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

func cleanMFAEnrollTokenFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.mfa_enroll_tokens WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'mfa-tok-test-%')`); err != nil {
		t.Fatalf("clean mfa_enroll_tokens: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'mfa-tok-test-%'`); err != nil {
		t.Fatalf("clean collaborators: %v", err)
	}
}

func TestMFAEnrollTokenLifecycle(t *testing.T) {
	db := dbForMFAEnrollTokenTest(t)
	defer db.Close()
	cleanMFAEnrollTokenFixtures(t, db)
	defer cleanMFAEnrollTokenFixtures(t, db)

	ctx := context.Background()
	collab, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:         "mfa-tok-test-alice",
		DisplayName:  "Alice",
		PrimaryEmail: "mfa-tok-test-alice@dakasa.me",
	})
	if err != nil {
		t.Fatalf("create collab: %v", err)
	}

	id, err := IssueMFAEnrollToken(ctx, db, collab.ID, "hash-1", time.Now().Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	tok, err := GetMFAEnrollTokenByHash(ctx, db, "hash-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if tok.ID != id {
		t.Fatalf("id mismatch: got %s want %s", tok.ID, id)
	}
	if err := ConsumeMFAEnrollToken(ctx, db, "hash-1"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := ConsumeMFAEnrollToken(ctx, db, "hash-1"); !errors.Is(err, ErrMFAEnrollTokenAlreadyConsumed) {
		t.Fatalf("expected ErrMFAEnrollTokenAlreadyConsumed, got %v", err)
	}

	// expired token
	_, err = IssueMFAEnrollToken(ctx, db, collab.ID, "hash-expired", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	if err := ConsumeMFAEnrollToken(ctx, db, "hash-expired"); !errors.Is(err, ErrMFAEnrollTokenExpired) {
		t.Fatalf("expected ErrMFAEnrollTokenExpired, got %v", err)
	}

	// not found
	if err := ConsumeMFAEnrollToken(ctx, db, "hash-missing"); !errors.Is(err, ErrMFAEnrollTokenNotFound) {
		t.Fatalf("expected ErrMFAEnrollTokenNotFound, got %v", err)
	}
}
