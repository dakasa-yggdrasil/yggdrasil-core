package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func dbForAuthIdentityTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping auth_identity integration test")
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

func cleanAuthIdentityFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM public.auth_identities WHERE collaborator_id IN (SELECT id FROM public.collaborators WHERE slug LIKE 'auth-id-test-%')`); err != nil {
		t.Fatalf("clean auth_identities: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.collaborators WHERE slug LIKE 'auth-id-test-%'`); err != nil {
		t.Fatalf("clean collaborators: %v", err)
	}
}

func seedAuthIdentityCollaborator(t *testing.T, db *sql.DB, suffix string) uuid.UUID {
	t.Helper()
	collab, err := CreateCollaborator(context.Background(), db, model.CreateCollaboratorRequest{
		Slug:         "auth-id-test-" + suffix,
		DisplayName:  "Auth Test " + suffix,
		PrimaryEmail: suffix + "@dakasa-test.me",
	})
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	return collab.ID
}

func make32Key() []byte {
	return []byte("0123456789ABCDEF0123456789ABCDEF")
}

func TestUpsertAndGetAuthIdentity(t *testing.T) {
	db := dbForAuthIdentityTest(t)
	defer db.Close()
	cleanAuthIdentityFixtures(t, db)
	defer cleanAuthIdentityFixtures(t, db)

	id := seedAuthIdentityCollaborator(t, db, "alice")

	if err := UpsertAuthIdentity(context.Background(), db, id, "alice@dakasa-test.me"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := GetAuthIdentityByCollaboratorID(context.Background(), db, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Username != "alice@dakasa-test.me" {
		t.Errorf("expected username alice@dakasa-test.me, got %q", got.Username)
	}
	if got.HasTOTP {
		t.Error("expected has_totp=false for fresh identity")
	}
	if got.MFAEnrolledAt != nil {
		t.Error("expected mfa_enrolled_at NULL for fresh identity")
	}
}

func TestSetAndGetTOTPSecretRoundtrip(t *testing.T) {
	db := dbForAuthIdentityTest(t)
	defer db.Close()
	cleanAuthIdentityFixtures(t, db)
	defer cleanAuthIdentityFixtures(t, db)

	id := seedAuthIdentityCollaborator(t, db, "bob")
	if err := UpsertAuthIdentity(context.Background(), db, id, "bob@dakasa-test.me"); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	env := cryptoenvelope.NewWithStaticKEK(make32Key())
	seed := []byte("JBSWY3DPEHPK3PXP")
	if err := SetTOTPSecret(context.Background(), db, env, id, seed); err != nil {
		t.Fatalf("set totp: %v", err)
	}

	got, err := GetTOTPSecret(context.Background(), db, env, id)
	if err != nil {
		t.Fatalf("get totp: %v", err)
	}
	if string(got) != string(seed) {
		t.Errorf("totp roundtrip mismatch: %q vs %q", got, seed)
	}

	// has_totp now reflects the change
	identity, err := GetAuthIdentityByCollaboratorID(context.Background(), db, id)
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if !identity.HasTOTP {
		t.Error("expected has_totp=true after SetTOTPSecret")
	}
}

func TestMarkMFAEnrolledAndIsMFAEnrolled(t *testing.T) {
	db := dbForAuthIdentityTest(t)
	defer db.Close()
	cleanAuthIdentityFixtures(t, db)
	defer cleanAuthIdentityFixtures(t, db)

	id := seedAuthIdentityCollaborator(t, db, "carol")
	if err := UpsertAuthIdentity(context.Background(), db, id, "carol@dakasa-test.me"); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	enrolled, err := IsMFAEnrolled(context.Background(), db, id)
	if err != nil {
		t.Fatalf("is_mfa_enrolled: %v", err)
	}
	if enrolled {
		t.Error("fresh identity must not be MFA enrolled")
	}

	if err := MarkMFAEnrolled(context.Background(), db, id, time.Now()); err != nil {
		t.Fatalf("mark enrolled: %v", err)
	}
	enrolled, err = IsMFAEnrolled(context.Background(), db, id)
	if err != nil {
		t.Fatalf("is_mfa_enrolled (post): %v", err)
	}
	if !enrolled {
		t.Error("expected MFA enrolled after MarkMFAEnrolled")
	}
}

func TestSetRecoveryCodesHashes(t *testing.T) {
	db := dbForAuthIdentityTest(t)
	defer db.Close()
	cleanAuthIdentityFixtures(t, db)
	defer cleanAuthIdentityFixtures(t, db)

	id := seedAuthIdentityCollaborator(t, db, "dave")
	if err := UpsertAuthIdentity(context.Background(), db, id, "dave@dakasa-test.me"); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	hashes := []string{"hash1", "hash2", "hash3"}
	if err := SetRecoveryCodesHashes(context.Background(), db, id, hashes); err != nil {
		t.Fatalf("set hashes: %v", err)
	}

	got, err := GetAuthIdentityByCollaboratorID(context.Background(), db, id)
	if err != nil {
		t.Fatalf("get identity: %v", err)
	}
	if !got.HasRecoveryCodes {
		t.Error("expected has_recovery_codes=true after SetRecoveryCodesHashes")
	}
}
