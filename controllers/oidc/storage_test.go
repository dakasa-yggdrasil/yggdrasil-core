package oidc

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func dbForStorageTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Skip("DB_URL not set; skipping OIDC storage integration test")
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

func TestStorage_GetClientByClientID(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_clients WHERE client_id='storage-test-client'`)
	})
	_, _ = db.ExecContext(context.Background(),
		`DELETE FROM oidc_clients WHERE client_id='storage-test-client'`)

	if err := repository.UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID:               "storage-test-client",
		ClientSecretHash:       "$2a$10$irrelevant",
		RedirectURIs:           []string{"https://x.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid", "email"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		PKCERequired:           true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	s := NewStorage(db, "https://yggdrasil.test")
	c, err := s.GetClientByClientID(context.Background(), "storage-test-client")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.GetID() != "storage-test-client" {
		t.Errorf("client id: %q", c.GetID())
	}
	if len(c.RedirectURIs()) != 1 {
		t.Errorf("redirect uris len: %d", len(c.RedirectURIs()))
	}
	if !c.IsScopeAllowed("openid") {
		t.Errorf("openid scope should be allowed")
	}
	if c.IsScopeAllowed("admin") {
		t.Errorf("admin scope should not be allowed")
	}
}

func TestStorage_AuthorizeClientIDSecret_HappyAndInvalid(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_clients WHERE client_id='storage-test-client-bcrypt'`)
	})
	_, _ = db.ExecContext(context.Background(),
		`DELETE FROM oidc_clients WHERE client_id='storage-test-client-bcrypt'`)

	// bcrypt hash of "secret-pass" generated with cost=10. Tests that
	// bcryptCompare round-trips against a real hash.
	hash := "$2a$10$aLC10NVpx4ZKC8M8MoE/senuHYdbOt/MV9xDfr9UdzW.MVQ07T8wW"
	if err := repository.UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID:               "storage-test-client-bcrypt",
		ClientSecretHash:       hash,
		RedirectURIs:           []string{"https://x.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid"},
		GrantTypes:             []string{"authorization_code"},
		PKCERequired:           true,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	s := NewStorage(db, "https://yggdrasil.test")
	if err := s.AuthorizeClientIDSecret(context.Background(),
		"storage-test-client-bcrypt", "secret-pass"); err != nil {
		t.Errorf("expected happy path success, got %v", err)
	}
	if err := s.AuthorizeClientIDSecret(context.Background(),
		"storage-test-client-bcrypt", "wrong"); err == nil {
		t.Errorf("expected error on wrong secret")
	}
}

// seedStorageTestClient creates a confidential client used by the auth
// request tests. The client's redirect URI and grant set are wide enough
// to satisfy any of the storage flows we exercise.
func seedStorageTestClient(t *testing.T, db *sql.DB, clientID string) {
	t.Helper()
	if err := repository.UpsertOIDCClient(context.Background(), db, model.OIDCClient{
		ClientID:               clientID,
		ClientSecretHash:       "$2a$10$irrelevant",
		RedirectURIs:           []string{"https://x.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid", "email", "profile"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		PKCERequired:           true,
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
}

// seedStorageTestCollaborator creates (or updates) a collaborator row
// keyed by slug; returns its UUID. Idempotent across test runs.
func seedStorageTestCollaborator(t *testing.T, db *sql.DB, slug, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO collaborators (slug, display_name, primary_email, status)
		VALUES ($1, $2, $3, 'active')
		ON CONFLICT (slug) DO UPDATE SET primary_email = EXCLUDED.primary_email
		RETURNING id
	`, slug, "Storage Test "+slug, email).Scan(&id)
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	return id
}

func TestStorage_CreateAndGetAuthRequestByID(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	seedStorageTestClient(t, db, "storage-test-client")
	collabID := seedStorageTestCollaborator(t, db, "storage-test-collab-6b1", "6b1@example.test")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_auth_requests WHERE collaborator_id=$1`, collabID)
	})

	s := NewStorage(db, "https://yggdrasil.test")
	ar, err := s.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "storage-test-client",
		RedirectURI:         "https://x.test/cb",
		Scopes:              oidc.SpaceDelimitedArray{"openid", "email"},
		ResponseType:        oidc.ResponseTypeCode,
		State:               "state-1",
		Nonce:               "nonce-1",
		CodeChallenge:       "challenge-abc",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, collabID.String())
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	if ar.GetID() == "" {
		t.Fatalf("ID empty after create")
	}
	if ar.GetClientID() != "storage-test-client" {
		t.Errorf("ClientID: %q", ar.GetClientID())
	}
	if ar.GetSubject() != collabID.String() {
		t.Errorf("Subject: got %q want %q", ar.GetSubject(), collabID.String())
	}
	if !ar.Done() {
		t.Errorf("Done() should be true when subject set")
	}
	cc := ar.GetCodeChallenge()
	if cc == nil || cc.Challenge != "challenge-abc" || cc.Method != oidc.CodeChallengeMethodS256 {
		t.Errorf("PKCE not surfaced: %+v", cc)
	}

	got, err := s.AuthRequestByID(context.Background(), ar.GetID())
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if got.GetID() != ar.GetID() || got.GetState() != "state-1" || got.GetNonce() != "nonce-1" {
		t.Errorf("round-trip mismatch: id=%q state=%q nonce=%q",
			got.GetID(), got.GetState(), got.GetNonce())
	}
}

func TestStorage_SaveAuthCode_AndAuthRequestByCode(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	seedStorageTestClient(t, db, "storage-test-client")
	collabID := seedStorageTestCollaborator(t, db, "storage-test-collab-6b2", "6b2@example.test")
	code := "test-code-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_auth_codes WHERE code=$1`, code)
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_auth_requests WHERE collaborator_id=$1`, collabID)
	})

	s := NewStorage(db, "https://yggdrasil.test")
	ar, err := s.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:    "storage-test-client",
		RedirectURI: "https://x.test/cb",
		Scopes:      oidc.SpaceDelimitedArray{"openid"},
		State:       "code-state",
	}, collabID.String())
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}

	if err := s.SaveAuthCode(context.Background(), ar.GetID(), code); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	got, err := s.AuthRequestByCode(context.Background(), code)
	if err != nil {
		t.Fatalf("AuthRequestByCode: %v", err)
	}
	if got.GetID() != ar.GetID() {
		t.Errorf("AuthRequestByCode resolved wrong request: got %q want %q",
			got.GetID(), ar.GetID())
	}
	if got.GetState() != "code-state" {
		t.Errorf("State lost in by-code lookup: %q", got.GetState())
	}
}

func TestStorage_DeleteAuthRequest_MarksConsumed(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	seedStorageTestClient(t, db, "storage-test-client")
	collabID := seedStorageTestCollaborator(t, db, "storage-test-collab-6b3", "6b3@example.test")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_auth_requests WHERE collaborator_id=$1`, collabID)
	})

	s := NewStorage(db, "https://yggdrasil.test")
	ar, err := s.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:    "storage-test-client",
		RedirectURI: "https://x.test/cb",
		Scopes:      oidc.SpaceDelimitedArray{"openid"},
	}, collabID.String())
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}

	if err := s.DeleteAuthRequest(context.Background(), ar.GetID()); err != nil {
		t.Fatalf("DeleteAuthRequest: %v", err)
	}

	// Verify consumed_at is now set on the underlying row.
	var consumedAt *time.Time
	parsed, err := uuid.Parse(ar.GetID())
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	if err := db.QueryRowContext(context.Background(),
		`SELECT consumed_at FROM oidc_auth_requests WHERE id=$1`, parsed,
	).Scan(&consumedAt); err != nil {
		t.Fatalf("query consumed_at: %v", err)
	}
	if consumedAt == nil {
		t.Errorf("expected consumed_at to be set after DeleteAuthRequest")
	}
}
