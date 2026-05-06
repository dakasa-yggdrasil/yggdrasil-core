package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// dbForProvisionTest opens a *sql.DB pointing at the integration Postgres
// or skips. Mirrors dbForHandlersTest in controllers/oidc/handlers_test.go
// so we don't need to export repository.dbForOIDCTest.
func dbForProvisionTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping provision integration test")
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

// cleanupProvisionedCollaborator removes a provisioned collaborator and its
// memberships by primary_email. Used in pre-cleanup AND t.Cleanup so tests
// are order-independent under `go test -shuffle on`.
//
// Important: we deliberately DO NOT touch oidc_provider_settings — the
// singleton row is seeded by 00019_oidc.sql (allowed_email_domains=['dakasa.me'],
// default_team_slug='dakasa-internal', auto_provision=TRUE) and other tests
// depend on it.
func cleanupProvisionedCollaborator(ctx context.Context, db *sql.DB, email string) {
	_, _ = db.ExecContext(ctx,
		`DELETE FROM team_memberships WHERE collaborator_id IN (SELECT id FROM collaborators WHERE primary_email=$1)`,
		email)
	_, _ = db.ExecContext(ctx,
		`DELETE FROM collaborators WHERE primary_email=$1`, email)
}

func TestProvisionCollaboratorFromGoogleClaim_AcceptedDomain(t *testing.T) {
	db := dbForProvisionTest(t)
	defer db.Close()

	ctx := context.Background()
	cleanupProvisionedCollaborator(ctx, db, "alice@dakasa.me")
	t.Cleanup(func() { cleanupProvisionedCollaborator(ctx, db, "alice@dakasa.me") })

	collab, err := provisionCollaboratorFromClaim(ctx, db, "alice@dakasa.me", "Alice", true)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if collab.PrimaryEmail != "alice@dakasa.me" {
		t.Errorf("email: got %q, want %q", collab.PrimaryEmail, "alice@dakasa.me")
	}
	if collab.DisplayName != "Alice" {
		t.Errorf("display_name: got %q, want %q", collab.DisplayName, "Alice")
	}

	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM team_memberships tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.collaborator_id=$1 AND t.slug='dakasa-internal'
	`, collab.ID).Scan(&count); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 dakasa-internal membership, got %d", count)
	}
}

func TestProvisionCollaboratorFromGoogleClaim_RejectedDomain(t *testing.T) {
	db := dbForProvisionTest(t)
	defer db.Close()

	ctx := context.Background()
	cleanupProvisionedCollaborator(ctx, db, "bob@external.com")
	t.Cleanup(func() { cleanupProvisionedCollaborator(ctx, db, "bob@external.com") })

	_, err := provisionCollaboratorFromClaim(ctx, db, "bob@external.com", "Bob", true)
	if err == nil {
		t.Fatal("expected error for rejected domain, got nil")
	}
	if !strings.Contains(err.Error(), "domain not allowed") {
		t.Errorf("error wording: %v", err)
	}
}

func TestProvisionCollaboratorFromGoogleClaim_UnverifiedEmail(t *testing.T) {
	db := dbForProvisionTest(t)
	defer db.Close()

	ctx := context.Background()
	cleanupProvisionedCollaborator(ctx, db, "alice@dakasa.me")
	t.Cleanup(func() { cleanupProvisionedCollaborator(ctx, db, "alice@dakasa.me") })

	_, err := provisionCollaboratorFromClaim(ctx, db, "alice@dakasa.me", "Alice", false)
	if err == nil {
		t.Fatal("expected error for email_verified=false, got nil")
	}
	if !strings.Contains(err.Error(), "email not verified") {
		t.Errorf("error wording: %v", err)
	}
}

func TestProvisionCollaboratorFromGoogleClaim_ReturnsExisting(t *testing.T) {
	db := dbForProvisionTest(t)
	defer db.Close()

	ctx := context.Background()
	cleanupProvisionedCollaborator(ctx, db, "alice@dakasa.me")
	t.Cleanup(func() { cleanupProvisionedCollaborator(ctx, db, "alice@dakasa.me") })

	first, err := provisionCollaboratorFromClaim(ctx, db, "alice@dakasa.me", "Alice", true)
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}
	second, err := provisionCollaboratorFromClaim(ctx, db, "alice@dakasa.me", "Alice", true)
	if err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("expected same ID on second call, got first=%s second=%s", first.ID, second.ID)
	}

	// Sanity: the public exported helper should also resolve the same row.
	again, err := repository.GetCollaboratorByPrimaryEmail(ctx, db, "alice@dakasa.me")
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if again.ID != first.ID {
		t.Errorf("get-by-email mismatch: %s vs %s", again.ID, first.ID)
	}

	// And ErrCollaboratorNotFound should propagate for unknown emails.
	if _, err := repository.GetCollaboratorByPrimaryEmail(ctx, db, "nobody@dakasa.me"); !errors.Is(err, repository.ErrCollaboratorNotFound) {
		t.Errorf("unknown email: got %v, want ErrCollaboratorNotFound", err)
	}
}

func TestProvisionCollaboratorFromGoogleClaim_AutoProvisionDisabled(t *testing.T) {
	db := dbForProvisionTest(t)
	// Register Close FIRST so the restore-state cleanup (registered next)
	// runs while db is still open — t.Cleanup runs LIFO, deferred funcs run
	// BEFORE cleanups, so we must use t.Cleanup for Close instead of defer.
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	cleanupProvisionedCollaborator(ctx, db, "charlie@dakasa.me")
	t.Cleanup(func() { cleanupProvisionedCollaborator(ctx, db, "charlie@dakasa.me") })

	// Save and disable auto_provision; restore on cleanup so other tests
	// (and -shuffle on -count 2) don't flake.
	orig, err := repository.GetOIDCProviderSettings(ctx, db)
	if err != nil {
		t.Fatalf("get original settings: %v", err)
	}
	disabled := orig
	disabled.AutoProvision = false
	if err := repository.UpdateOIDCProviderSettings(ctx, db, disabled); err != nil {
		t.Fatalf("disable auto_provision: %v", err)
	}
	t.Cleanup(func() {
		if err := repository.UpdateOIDCProviderSettings(context.Background(), db, orig); err != nil {
			t.Errorf("restore auto_provision: %v", err)
		}
	})

	_, err = provisionCollaboratorFromClaim(ctx, db, "charlie@dakasa.me", "Charlie", true)
	if err == nil {
		t.Fatal("expected error for auto_provision=false, got nil")
	}
	if !strings.Contains(err.Error(), "auto_provision is disabled") {
		t.Errorf("error wording: %v", err)
	}
	if !errors.Is(err, errAutoProvisionRejected) {
		t.Errorf("expected errors.Is(err, errAutoProvisionRejected) to be true; got %v", err)
	}
}
