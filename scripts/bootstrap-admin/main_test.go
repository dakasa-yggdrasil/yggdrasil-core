package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func dbForBootstrapAdminTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping bootstrap-admin test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedAdminTestCollab inserts a throwaway collaborator and registers
// cleanup. Returns the row's UUID + email so the test can pass the
// email to promoteAdmin and verify by ID afterwards.
func seedAdminTestCollab(t *testing.T, db *sql.DB) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	slug := "bootstrap-admin-test-" + suffix
	email := slug + "@dakasa.me"

	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.ExecContext(ctx, `DELETE FROM team_memberships WHERE collaborator_id IN (SELECT id FROM collaborators WHERE primary_email=$1)`, email)
		_, _ = db.ExecContext(ctx, `DELETE FROM collaborators WHERE primary_email=$1`, email)
	})

	var id uuid.UUID
	if err := db.QueryRowContext(ctx, `
		INSERT INTO collaborators (slug, status, display_name, primary_email)
		VALUES ($1, 'active', 'Bootstrap Admin Test', $2)
		RETURNING id
	`, slug, email).Scan(&id); err != nil {
		t.Fatalf("seed collab: %v", err)
	}
	return id, email
}

func TestPromoteAdmin_AddsToYggdrasilAdmin(t *testing.T) {
	db := dbForBootstrapAdminTest(t)
	ctx := context.Background()
	collabID, email := seedAdminTestCollab(t, db)

	gotID, err := promoteAdmin(ctx, db, email, "yggdrasil-admin")
	if err != nil {
		t.Fatalf("promoteAdmin: %v", err)
	}
	if gotID != collabID.String() {
		t.Errorf("returned ID: got %s, want %s", gotID, collabID)
	}

	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM team_memberships tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.collaborator_id=$1 AND t.slug='yggdrasil-admin'
	`, collabID).Scan(&count); err != nil {
		t.Fatalf("count membership: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 yggdrasil-admin membership, got %d", count)
	}
}

func TestPromoteAdmin_Idempotent(t *testing.T) {
	db := dbForBootstrapAdminTest(t)
	ctx := context.Background()
	collabID, email := seedAdminTestCollab(t, db)

	for i := 0; i < 3; i++ {
		if _, err := promoteAdmin(ctx, db, email, "yggdrasil-admin"); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}

	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM team_memberships tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.collaborator_id=$1 AND t.slug='yggdrasil-admin'
	`, collabID).Scan(&count); err != nil {
		t.Fatalf("count membership: %v", err)
	}
	if count != 1 {
		t.Errorf("expected idempotent: got %d memberships after 3 calls, want 1", count)
	}
}

func TestPromoteAdmin_UnknownCollaborator_FriendlyError(t *testing.T) {
	db := dbForBootstrapAdminTest(t)
	ctx := context.Background()

	_, err := promoteAdmin(ctx, db, "nobody-"+uuid.NewString()[:8]+"@dakasa.me", "yggdrasil-admin")
	if err == nil {
		t.Fatal("expected error for unknown collaborator")
	}
	if !strings.Contains(err.Error(), "must log in once via OIDC") {
		t.Errorf("expected hint about logging in first; got: %v", err)
	}
	// Verify the underlying repo error is wrapped (so callers can still
	// errors.Is if they need to distinguish).
	if !errors.Is(err, repository.ErrCollaboratorNotFound) {
		t.Errorf("expected wrapped ErrCollaboratorNotFound; got: %v", err)
	}
}

func TestPromoteAdmin_UnknownTeam_PropagatesError(t *testing.T) {
	db := dbForBootstrapAdminTest(t)
	ctx := context.Background()
	_, email := seedAdminTestCollab(t, db)

	_, err := promoteAdmin(ctx, db, email, "team-that-does-not-exist-"+uuid.NewString()[:8])
	if err == nil {
		t.Fatal("expected error for unknown team")
	}
	if !strings.Contains(err.Error(), "add to team") {
		t.Errorf("expected error wrapped with 'add to team'; got: %v", err)
	}
}
