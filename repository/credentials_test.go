package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/password"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func dbForCredentialsTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping credentials integration test")
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

func cleanCredentialsFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.auth_identities WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'cred-test-%')`); err != nil {
		t.Fatalf("clean auth_identities: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'cred-test-%'`); err != nil {
		t.Fatalf("clean collaborators: %v", err)
	}
}

func seedCredentialsCollaborator(t *testing.T, db *sql.DB, suffix string) uuid.UUID {
	t.Helper()
	collab, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:         "cred-test-" + suffix,
		DisplayName:  "Cred Test " + suffix,
		PrimaryEmail: suffix + "@cred-test.me",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	return collab.ID
}

// TestSetPasswordHashRoundTrip verifies the full write→read cycle for
// password credentials via SetPasswordHash / GetPasswordCredentialState.
func TestSetPasswordHashRoundTrip(t *testing.T) {
	db := dbForCredentialsTest(t)
	defer db.Close()
	cleanCredentialsFixtures(t, db)
	defer cleanCredentialsFixtures(t, db)

	id := seedCredentialsCollaborator(t, db, "alice")

	// Create the auth_identity row (without a password yet).
	if err := UpsertAuthIdentity(context.Background(), db, id, "alice@cred-test.me"); err != nil {
		t.Fatalf("upsert auth_identity: %v", err)
	}

	// Hash a plaintext password using the real password package.
	const plaintext = "S3cur3P@ssw0rd!"
	scheme, encoded, err := password.Hash(plaintext)
	if err != nil {
		t.Fatalf("password.Hash: %v", err)
	}

	expiresAt := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)

	if err := SetPasswordHash(context.Background(), db, id, encoded, string(scheme), expiresAt); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}

	// Read back and assert fields.
	got, err := GetPasswordCredentialState(context.Background(), db, id)
	if err != nil {
		t.Fatalf("GetPasswordCredentialState: %v", err)
	}

	if got.PasswordHash == nil {
		t.Fatal("expected password_hash to be non-nil after SetPasswordHash")
	}
	if *got.PasswordHash != encoded {
		t.Errorf("password_hash mismatch: want %q, got %q", encoded, *got.PasswordHash)
	}
	if got.PasswordScheme == nil {
		t.Fatal("expected password_scheme to be non-nil after SetPasswordHash")
	}
	if *got.PasswordScheme != string(scheme) {
		t.Errorf("password_scheme mismatch: want %q, got %q", scheme, *got.PasswordScheme)
	}
	if got.PasswordUpdatedAt == nil {
		t.Fatal("expected password_updated_at to be set")
	}
	if got.PasswordMustChange {
		t.Error("expected password_must_change=false after SetPasswordHash")
	}
	if got.PasswordExpiresAt == nil {
		t.Fatal("expected password_expires_at to be set")
	}

	// Verify the bridge works end-to-end via VerifyPassword.
	if err := VerifyPassword(context.Background(), db, id, plaintext); err != nil {
		t.Errorf("VerifyPassword with correct plaintext: %v", err)
	}
	if err := VerifyPassword(context.Background(), db, id, "wrong-password"); err == nil {
		t.Error("VerifyPassword with wrong plaintext should return an error")
	}
}

// TestSetPasswordHashNotFound asserts ErrPasswordCredentialNotFound when there
// is no auth_identities row for the given collaborator ID.
func TestSetPasswordHashNotFound(t *testing.T) {
	db := dbForCredentialsTest(t)
	defer db.Close()

	nonexistent := uuid.New()
	err := SetPasswordHash(context.Background(), db, nonexistent, "hash", "argon2id", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("expected error for nonexistent collaborator")
	}
	if err != ErrPasswordCredentialNotFound {
		t.Errorf("expected ErrPasswordCredentialNotFound, got %v", err)
	}
}

// TestRevokeAllOtherSessions verifies that active sessions other than the
// exempted one are marked revoked.  Uses raw SQL inserts since there is no
// CreateSession repository helper yet.
func TestRevokeAllOtherSessions(t *testing.T) {
	db := dbForCredentialsTest(t)
	defer db.Close()
	cleanCredentialsFixtures(t, db)
	defer cleanCredentialsFixtures(t, db)

	id := seedCredentialsCollaborator(t, db, "bob")

	// Insert three sessions directly.
	insertSession := func(t *testing.T, collaboratorID uuid.UUID) uuid.UUID {
		t.Helper()
		var sessID uuid.UUID
		err := db.QueryRowContext(context.Background(), `
			INSERT INTO auth_sessions (collaborator_id, token_hash, expires_at)
			VALUES ($1, gen_random_uuid()::text, NOW() + INTERVAL '1 hour')
			RETURNING id
		`, collaboratorID).Scan(&sessID)
		if err != nil {
			t.Fatalf("insert session: %v", err)
		}
		return sessID
	}

	keepSession := insertSession(t, id)
	_ = insertSession(t, id)
	_ = insertSession(t, id)

	n, err := RevokeAllOtherSessions(context.Background(), db, id, keepSession)
	if err != nil {
		t.Fatalf("RevokeAllOtherSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 revoked sessions, got %d", n)
	}

	// The kept session must still be active (revoked_at IS NULL).
	var revokedAt sql.NullTime
	if err := db.QueryRowContext(context.Background(),
		`SELECT revoked_at FROM auth_sessions WHERE id = $1`, keepSession,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read kept session: %v", err)
	}
	if revokedAt.Valid {
		t.Error("kept session should not be revoked")
	}
}
