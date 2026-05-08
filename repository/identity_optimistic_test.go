package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	_ "github.com/lib/pq"
)

func dbForCollaboratorOptimisticTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping collaborator optimistic locking integration test")
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

func cleanOptimisticTestCollaborators(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.lifecycle_events WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'optlock-test-%')`); err != nil {
		t.Fatalf("clean lifecycle_events: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborator_provider_state WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'optlock-test-%')`); err != nil {
		// Non-fatal if migration absent in CI; ignore.
		_ = err
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'optlock-test-%'`); err != nil {
		t.Fatalf("clean collaborators: %v", err)
	}
}

func TestUpdateCollaborator_BumpsVersionOnSuccess(t *testing.T) {
	db := dbForCollaboratorOptimisticTest(t)
	defer db.Close()
	cleanOptimisticTestCollaborators(t, db)
	defer cleanOptimisticTestCollaborators(t, db)

	ctx := context.Background()
	created, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:         "optlock-test-bump",
		DisplayName:  "Optlock Bump",
		PrimaryEmail: "optlock-test-bump@example.test",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Version != 0 {
		t.Fatalf("initial version: got %d, want 0", created.Version)
	}

	display := "Optlock Bump v2"
	updated, err := UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{
		ID:          created.ID.String(),
		DisplayName: &display,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Version != created.Version+1 {
		t.Fatalf("version: got %d, want %d", updated.Version, created.Version+1)
	}
	if updated.DisplayName != display {
		t.Fatalf("display_name not updated: got %q", updated.DisplayName)
	}

	display3 := "Optlock Bump v3"
	updated2, err := UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{
		ID:          created.ID.String(),
		DisplayName: &display3,
	})
	if err != nil {
		t.Fatalf("second update: %v", err)
	}
	if updated2.Version != updated.Version+1 {
		t.Fatalf("second version: got %d, want %d", updated2.Version, updated.Version+1)
	}
}

func TestUpdateCollaborator_ReturnsErrConcurrentUpdateOnRace(t *testing.T) {
	db := dbForCollaboratorOptimisticTest(t)
	defer db.Close()
	cleanOptimisticTestCollaborators(t, db)
	defer cleanOptimisticTestCollaborators(t, db)

	ctx := context.Background()
	created, err := CreateCollaborator(ctx, db, model.CreateCollaboratorRequest{
		Slug:         "optlock-test-race",
		DisplayName:  "Optlock Race",
		PrimaryEmail: "optlock-test-race@example.test",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Simulate a concurrent updater that bumped version BETWEEN our load and
	// our write — bypass the repo and write straight to the table.
	if _, err := db.Exec(
		`UPDATE public.collaborators SET version = version + 1, display_name = $1 WHERE id = $2`,
		"Concurrent Mutator", created.ID,
	); err != nil {
		t.Fatalf("simulate race: %v", err)
	}

	// Stale caller asserts ExpectedVersion=0 (pre-mutator value). Row is now on
	// version=1 → WHERE version=0 matches 0 rows → ErrConcurrentUpdate.
	staleVersion := 0
	staleDisplay := "Stale Caller Wins (should not)"
	_, err = UpdateCollaborator(ctx, db, model.UpdateCollaboratorRequest{
		ID:              created.ID.String(),
		DisplayName:     &staleDisplay,
		ExpectedVersion: &staleVersion,
	})
	if !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("expected ErrConcurrentUpdate, got: %v", err)
	}

	// Verify the concurrent mutator's row survived (display still "Concurrent Mutator").
	survivor, err := GetCollaborator(ctx, db, created.ID.String())
	if err != nil {
		t.Fatalf("re-fetch: %v", err)
	}
	if survivor.DisplayName != "Concurrent Mutator" {
		t.Fatalf("lost-update detected: got %q, expected concurrent mutator's value", survivor.DisplayName)
	}
}
