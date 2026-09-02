package oidc

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestValidateRequiredPKCEAppliesToConfidentialClients(t *testing.T) {
	client := model.OIDCClient{
		ClientID:         "confidential-client",
		ClientSecretHash: "$2b$12$hash-is-present-so-this-client-is-confidential",
		PKCERequired:     true,
	}
	verifier := "a-valid-length-code-verifier-with-at-least-43-characters"
	challenge := oidc.NewSHACodeChallenge(verifier)

	tests := []struct {
		name    string
		request *oidc.AuthRequest
		wantErr bool
	}{
		{name: "missing challenge", request: &oidc.AuthRequest{}, wantErr: true},
		{
			name: "plain challenge",
			request: &oidc.AuthRequest{
				CodeChallenge:       challenge,
				CodeChallengeMethod: oidc.CodeChallengeMethodPlain,
			},
			wantErr: true,
		},
		{
			name: "malformed S256 challenge",
			request: &oidc.AuthRequest{
				CodeChallenge:       "not-a-sha256-challenge",
				CodeChallengeMethod: oidc.CodeChallengeMethodS256,
			},
			wantErr: true,
		},
		{
			name: "valid S256 challenge",
			request: &oidc.AuthRequest{
				CodeChallenge:       challenge,
				CodeChallengeMethod: oidc.CodeChallengeMethodS256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRequiredPKCE(client, tc.request)
			if tc.wantErr && err == nil {
				t.Fatal("expected PKCE validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected PKCE validation error: %v", err)
			}
		})
	}

	if err := op.AuthorizeCodeChallenge(verifier, &oidc.CodeChallenge{
		Challenge: challenge,
		Method:    oidc.CodeChallengeMethodS256,
	}); err != nil {
		t.Fatalf("the upstream code exchange must verify a supplied confidential-client challenge: %v", err)
	}
	if err := op.AuthorizeCodeChallenge("wrong-verifier", &oidc.CodeChallenge{
		Challenge: challenge,
		Method:    oidc.CodeChallengeMethodS256,
	}); err == nil {
		t.Fatal("the upstream code exchange accepted the wrong verifier")
	}
}

func TestValidateRequiredPKCELeavesOptOutClientUnchanged(t *testing.T) {
	client := model.OIDCClient{ClientID: "legacy-client", PKCERequired: false}
	if err := validateRequiredPKCE(client, &oidc.AuthRequest{}); err != nil {
		t.Fatalf("PKCE opt-out client changed behavior: %v", err)
	}
}

func TestAuthorizeStorageRejectsConfidentialClientWithoutS256PKCEBeforeInsert(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		method    oidc.CodeChallengeMethod
		want      string
	}{
		{name: "missing", want: "code_challenge is required"},
		{
			name:      "plain",
			challenge: oidc.NewSHACodeChallenge("a-valid-length-code-verifier-with-at-least-43-characters"),
			method:    oidc.CodeChallengeMethodPlain,
			want:      "code_challenge_method must be S256",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("SELECT client_id, client_secret_hash").
				WithArgs("confidential-client").
				WillReturnRows(sqlmock.NewRows([]string{
					"client_id", "client_secret_hash", "redirect_uris", "post_logout_redirect_uris",
					"scopes", "grant_types", "pkce_required", "backchannel_logout_uri",
					"access_token_lifetime_seconds", "created_at",
				}).AddRow(
					"confidential-client",
					"$2b$12$hash-is-present-so-this-client-is-confidential",
					"{https://x.test/callback}",
					"{https://x.test/login}",
					"{openid}",
					"{authorization_code}",
					true,
					"",
					nil,
					time.Now().UTC(),
				))

			storage := NewStorage(db, "https://yggdrasil.test/oidc")
			_, err = storage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
				ClientID:            "confidential-client",
				RedirectURI:         "https://x.test/callback",
				Scopes:              oidc.SpaceDelimitedArray{"openid"},
				ResponseType:        oidc.ResponseTypeCode,
				CodeChallenge:       tc.challenge,
				CodeChallengeMethod: tc.method,
			}, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected authorize rejection containing %q, got %v", tc.want, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

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
	challenge := oidc.NewSHACodeChallenge("storage-test-code-verifier-6b1")
	ar, err := s.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "storage-test-client",
		RedirectURI:         "https://x.test/cb",
		Scopes:              oidc.SpaceDelimitedArray{"openid", "email"},
		ResponseType:        oidc.ResponseTypeCode,
		State:               "state-1",
		Nonce:               "nonce-1",
		CodeChallenge:       challenge,
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
	if cc == nil || cc.Challenge != challenge || cc.Method != oidc.CodeChallengeMethodS256 {
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
		ClientID:            "storage-test-client",
		RedirectURI:         "https://x.test/cb",
		Scopes:              oidc.SpaceDelimitedArray{"openid"},
		State:               "code-state",
		CodeChallenge:       oidc.NewSHACodeChallenge("storage-test-code-verifier-6b2"),
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
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

// minimalTokenRequest is a stand-in for op.TokenRequest used in tests
// where we don't need to round-trip through the full code/refresh flow.
// The OP would normally pass an authRequestView or refreshTokenRequestView.
type minimalTokenRequest struct {
	subject  string
	audience []string
	scopes   []string
	clientID string
}

func (m *minimalTokenRequest) GetSubject() string { return m.subject }
func (m *minimalTokenRequest) GetAudience() []string {
	if len(m.audience) > 0 {
		return m.audience
	}
	return []string{m.clientID}
}
func (m *minimalTokenRequest) GetScopes() []string { return m.scopes }
func (m *minimalTokenRequest) GetClientID() string { return m.clientID }

func TestStorage_CreateAccessAndRefreshTokens_FreshSession(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	seedStorageTestClient(t, db, "storage-test-client")
	collabID := seedStorageTestCollaborator(t, db, "storage-test-collab-6c1", "6c1@example.test")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_refresh_tokens WHERE collaborator_id=$1`, collabID)
	})

	s := NewStorage(db, "https://yggdrasil.test")
	req := &minimalTokenRequest{
		subject:  collabID.String(),
		clientID: "storage-test-client",
		scopes:   []string{"openid", "email"},
	}
	atID, rt, exp, err := s.CreateAccessAndRefreshTokens(context.Background(), req, "")
	if err != nil {
		t.Fatalf("CreateAccessAndRefreshTokens: %v", err)
	}
	if atID == "" || rt == "" {
		t.Errorf("empty token ids: at=%q rt=%q", atID, rt)
	}
	if !exp.After(time.Now()) {
		t.Errorf("expiration not in the future: %v", exp)
	}

	// The refresh token should be loadable from the DB.
	stored, err := repository.GetOIDCRefreshToken(context.Background(), db, rt)
	if err != nil {
		t.Fatalf("GetOIDCRefreshToken: %v", err)
	}
	if stored.RotatedFrom != nil {
		t.Errorf("fresh session should have RotatedFrom=nil, got %q", *stored.RotatedFrom)
	}
	if stored.RevokedAt != nil {
		t.Errorf("fresh refresh token should not be revoked")
	}
}

func TestStorage_CreateAccessAndRefreshTokens_Rotation(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	seedStorageTestClient(t, db, "storage-test-client")
	collabID := seedStorageTestCollaborator(t, db, "storage-test-collab-6c2", "6c2@example.test")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_refresh_tokens WHERE collaborator_id=$1`, collabID)
	})

	s := NewStorage(db, "https://yggdrasil.test")
	req := &minimalTokenRequest{
		subject:  collabID.String(),
		clientID: "storage-test-client",
		scopes:   []string{"openid"},
	}

	// Mint the initial refresh token (Code Flow).
	_, rt1, _, err := s.CreateAccessAndRefreshTokens(context.Background(), req, "")
	if err != nil {
		t.Fatalf("initial mint: %v", err)
	}
	// Rotate.
	_, rt2, _, err := s.CreateAccessAndRefreshTokens(context.Background(), req, rt1)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rt1 == rt2 {
		t.Errorf("rotated token equals previous: %q", rt2)
	}
	// Old token should be revoked.
	stored1, err := repository.GetOIDCRefreshToken(context.Background(), db, rt1)
	if err != nil {
		t.Fatalf("Get old: %v", err)
	}
	if stored1.RevokedAt == nil {
		t.Errorf("expected old refresh token to be revoked after rotation")
	}
	// New token should reference the old one as parent.
	stored2, err := repository.GetOIDCRefreshToken(context.Background(), db, rt2)
	if err != nil {
		t.Fatalf("Get new: %v", err)
	}
	if stored2.RotatedFrom == nil || *stored2.RotatedFrom != rt1 {
		got := "<nil>"
		if stored2.RotatedFrom != nil {
			got = *stored2.RotatedFrom
		}
		t.Errorf("RotatedFrom: got %q want %q", got, rt1)
	}
}

func TestStorage_TokenRequestByRefreshToken_RevokedReplayDetection(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	seedStorageTestClient(t, db, "storage-test-client")
	collabID := seedStorageTestCollaborator(t, db, "storage-test-collab-6c3", "6c3@example.test")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM oidc_refresh_tokens WHERE collaborator_id=$1`, collabID)
	})

	s := NewStorage(db, "https://yggdrasil.test")
	req := &minimalTokenRequest{
		subject:  collabID.String(),
		clientID: "storage-test-client",
		scopes:   []string{"openid"},
	}

	// Mint and rotate so we have a chain: rt1 -> rt2.
	_, rt1, _, err := s.CreateAccessAndRefreshTokens(context.Background(), req, "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	_, rt2, _, err := s.CreateAccessAndRefreshTokens(context.Background(), req, rt1)
	if err != nil {
		t.Fatalf("rotate 1: %v", err)
	}

	// Replay attempt: try to use rt1 again. Should fail with invalid
	// refresh token, AND the chain (including rt2) should be revoked.
	_, replayErr := s.TokenRequestByRefreshToken(context.Background(), rt1)
	if replayErr == nil {
		t.Fatalf("expected error on replay, got nil")
	}

	// rt2 should now be revoked too (chain revocation).
	stored2, err := repository.GetOIDCRefreshToken(context.Background(), db, rt2)
	if err != nil {
		t.Fatalf("Get rt2: %v", err)
	}
	if stored2.RevokedAt == nil {
		t.Errorf("rt2 should be revoked after replay defense triggered on rt1")
	}
}

func TestStorage_KeySet_ReturnsCurrentJWK(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	// EnsureSigningKey is idempotent; safe to call from any test that
	// needs a key.
	if _, err := EnsureSigningKey(context.Background(), db); err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	s := NewStorage(db, "https://yggdrasil.test")
	keys, err := s.KeySet(context.Background())
	if err != nil {
		t.Fatalf("KeySet: %v", err)
	}
	if len(keys) == 0 {
		t.Fatalf("expected at least one key")
	}
	k := keys[0]
	if k.ID() == "" {
		t.Errorf("key ID is empty")
	}
	if k.Use() != "sig" {
		t.Errorf("Use: %q want sig", k.Use())
	}
	if k.Algorithm() == "" {
		t.Errorf("Algorithm is empty")
	}
	if k.Key() == nil {
		t.Errorf("Key value is nil")
	}
}

func TestStorage_SigningKey_ParsesPrivateKey(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	if _, err := EnsureSigningKey(context.Background(), db); err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	s := NewStorage(db, "https://yggdrasil.test")
	sk, err := s.SigningKey(context.Background())
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}
	if sk.ID() == "" {
		t.Errorf("SigningKey ID empty")
	}
	if sk.Key() == nil {
		t.Errorf("SigningKey value nil")
	}
}

func TestStorage_Health_Pings(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	s := NewStorage(db, "https://yggdrasil.test")
	if err := s.Health(context.Background()); err != nil {
		t.Errorf("Health: %v", err)
	}
}

func TestStorage_SetUserinfoFromScopes_PopulatesEmailAndTeams(t *testing.T) {
	db := dbForStorageTest(t)
	defer db.Close()
	collabID := seedStorageTestCollaborator(t, db, "storage-test-collab-6c4", "6c4@example.test")

	// Attach the collaborator to the seed access group "dakasa-internal"
	// so the teams claim has something to surface.
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM team_memberships WHERE collaborator_id=$1`, collabID)
	})
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO team_memberships (team_id, collaborator_id, role, active, source)
		SELECT id, $1, 'member', TRUE, 'manual' FROM teams WHERE slug='dakasa-internal'
		ON CONFLICT (team_id, collaborator_id) DO UPDATE SET active=TRUE
	`, collabID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	s := NewStorage(db, "https://yggdrasil.test")
	ui := &oidc.UserInfo{}
	if err := s.SetUserinfoFromScopes(context.Background(), ui,
		collabID.String(), "storage-test-client",
		[]string{"openid", "email", "profile", "roles"},
	); err != nil {
		t.Fatalf("SetUserinfoFromScopes: %v", err)
	}
	if ui.Subject != collabID.String() {
		t.Errorf("Subject: got %q want %q", ui.Subject, collabID.String())
	}
	if ui.Email != "6c4@example.test" {
		t.Errorf("Email: got %q want %q", ui.Email, "6c4@example.test")
	}
	teams, _ := ui.Claims["teams"].([]string)
	if len(teams) == 0 {
		t.Errorf("expected at least one team in claims, got none. Claims: %v", ui.Claims)
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
		ClientID:            "storage-test-client",
		RedirectURI:         "https://x.test/cb",
		Scopes:              oidc.SpaceDelimitedArray{"openid"},
		CodeChallenge:       oidc.NewSHACodeChallenge("storage-test-code-verifier-6b3"),
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
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
