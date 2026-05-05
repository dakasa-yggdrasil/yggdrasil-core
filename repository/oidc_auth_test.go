package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func ensureTestClient(t *testing.T, db *sql.DB) {
	t.Helper()
	c := model.OIDCClient{
		ClientID: "auth-test-client", ClientSecretHash: "x",
		RedirectURIs:           []string{"https://x.test/cb"},
		PostLogoutRedirectURIs: []string{},
		Scopes:                 []string{"openid"},
		GrantTypes:             []string{"authorization_code"}, PKCERequired: true,
	}
	if err := UpsertOIDCClient(context.Background(), db, c); err != nil {
		t.Fatalf("seed client: %v", err)
	}
}

func ensureTestCollaborator(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO collaborators (slug, display_name, primary_email, status)
		VALUES ('test-collab-task3', 'Test', 'test-task3@example.test', 'active')
		ON CONFLICT (slug) DO UPDATE SET primary_email = EXCLUDED.primary_email
		RETURNING id
	`).Scan(&id)
	if err != nil {
		t.Fatalf("seed collaborator: %v", err)
	}
	return id
}

func TestCreateAndGetOIDCAuthRequest(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	ensureTestClient(t, db)
	collabID := ensureTestCollaborator(t, db)
	ar := model.OIDCAuthRequest{
		ClientID:            "auth-test-client",
		CollaboratorID:      &collabID,
		RedirectURI:         "https://x.test/cb",
		Scopes:              []string{"openid", "email"},
		CodeChallenge:       "abc",
		CodeChallengeMethod: "S256",
		State:               "s",
		Nonce:               "n",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	id, err := CreateOIDCAuthRequest(context.Background(), db, ar)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := GetOIDCAuthRequestByID(context.Background(), db, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientID != ar.ClientID || got.State != "s" {
		t.Errorf("round-trip lost data: %+v", got)
	}
	if got.CodeChallenge != "abc" || got.CodeChallengeMethod != "S256" {
		t.Errorf("PKCE fields lost: challenge=%q method=%q", got.CodeChallenge, got.CodeChallengeMethod)
	}
}

func TestSaveAndConsumeOIDCAuthCode(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	// Pre-clean residue from prior runs (defer db.Close() preempts t.Cleanup).
	_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_auth_codes WHERE code='code-1'`)
	ensureTestClient(t, db)
	collabID := ensureTestCollaborator(t, db)
	ar := model.OIDCAuthRequest{
		ClientID: "auth-test-client", CollaboratorID: &collabID,
		RedirectURI: "https://x.test/cb", Scopes: []string{"openid"},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	arID, _ := CreateOIDCAuthRequest(context.Background(), db, ar)

	if err := SaveOIDCAuthCode(context.Background(), db, "code-1", arID, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("save code: %v", err)
	}
	got, err := ConsumeOIDCAuthCode(context.Background(), db, "code-1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.AuthRequestID != arID {
		t.Errorf("auth_request_id mismatch: %v vs %v", got.AuthRequestID, arID)
	}
	// Second consume must fail (single-use)
	if _, err := ConsumeOIDCAuthCode(context.Background(), db, "code-1"); err != ErrOIDCAuthCodeAlreadyUsed {
		t.Errorf("expected ErrOIDCAuthCodeAlreadyUsed on replay, got %v", err)
	}
}

func TestRefreshTokenRotationAndReplayChainRevoke(t *testing.T) {
	db := dbForOIDCTest(t)
	defer db.Close()
	// Pre-clean residue from prior runs (defer db.Close() preempts t.Cleanup).
	_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_refresh_tokens WHERE token IN ('r1','r2','r3')`)
	ensureTestClient(t, db)
	collabID := ensureTestCollaborator(t, db)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM oidc_refresh_tokens WHERE token IN ('r1','r2','r3')`)
	})

	r1 := model.OIDCRefreshToken{
		Token: "r1", CollaboratorID: collabID, ClientID: "auth-test-client",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	if err := CreateOIDCRefreshToken(context.Background(), db, r1); err != nil {
		t.Fatalf("create r1: %v", err)
	}

	// Rotate r1 → r2
	r1Ptr := "r1"
	if err := RotateOIDCRefreshToken(context.Background(), db, "r1", model.OIDCRefreshToken{
		Token: "r2", CollaboratorID: collabID, ClientID: "auth-test-client",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		RotatedFrom: &r1Ptr,
	}); err != nil {
		t.Fatalf("rotate r1->r2: %v", err)
	}

	// Rotate r2 → r3
	r2Ptr := "r2"
	if err := RotateOIDCRefreshToken(context.Background(), db, "r2", model.OIDCRefreshToken{
		Token: "r3", CollaboratorID: collabID, ClientID: "auth-test-client",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		RotatedFrom: &r2Ptr,
	}); err != nil {
		t.Fatalf("rotate r2->r3: %v", err)
	}

	// Replay r1: must revoke chain (r1, r2, r3) — actually r1 is already revoked,
	// so RevokeOIDCRefreshChainByRoot revokes r3 (r2 already revoked from rotation).
	revoked, err := RevokeOIDCRefreshChainByRoot(context.Background(), db, "r1")
	if err != nil {
		t.Fatalf("revoke chain: %v", err)
	}
	if revoked < 1 {
		t.Errorf("expected ≥1 token newly revoked in chain, got %d", revoked)
	}
	// All 3 tokens must now be revoked
	for _, tk := range []string{"r1", "r2", "r3"} {
		got, err := GetOIDCRefreshToken(context.Background(), db, tk)
		if err != nil {
			t.Errorf("get %s: %v", tk, err)
			continue
		}
		if got.RevokedAt == nil {
			t.Errorf("%s should be revoked, but RevokedAt is nil", tk)
		}
	}
}
