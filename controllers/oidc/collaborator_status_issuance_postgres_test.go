package oidc

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Real storage and migrated PostgreSQL prove the OIDC mint gate (ADR-0087):
// for every status that cannot sign in, no authorization request is honored,
// no code is saved or exchanged, no access or refresh token is minted and the
// refresh grant answers invalid_grant. Core tokens carry iat = mint time and
// no sid, so a relying party's iat-aware denylist cannot stop a token minted
// after a revocation; refusing to mint is the only safe answer. The status is
// flipped with raw SQL, so no termination runs: the gate alone is proven, and
// restoring active shows it reads the current row (the refused exchanges
// consumed nothing and revoked nothing). The provider introspection and
// userinfo refuse an access token of such a subject the same way.
func TestCollaboratorStatusNativeIssuancePostgres(t *testing.T) {
	if os.Getenv("DB_URL") == "" && os.Getenv("REQUIRE_SESSION_LIFECYCLE_POSTGRES") == "true" {
		t.Fatal("DB_URL is required by the session lifecycle PostgreSQL gate")
	}
	f := newNativeProtocolFixture(t)
	ctx := context.Background()
	s := NewStorage(f.db, f.issuer)

	// A request created with a userID is the pre-bound shape (id_token_hint):
	// the subject is attached at creation, before any login.
	newBoundRequest := func(t *testing.T) op.AuthRequest {
		t.Helper()
		ar, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
			ClientID: f.clientID, RedirectURI: f.redirectURI, Scopes: oidc.SpaceDelimitedArray{"openid"},
			ResponseType: oidc.ResponseTypeCode, CodeChallenge: oidc.NewSHACodeChallenge(strings.Repeat("s", 43)),
			CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		}, f.subject.String())
		if err != nil {
			t.Fatalf("bound request fixture failed: %v", err)
		}
		return ar
	}
	setStatus := func(t *testing.T, status string) {
		t.Helper()
		if _, err := f.db.ExecContext(ctx, `UPDATE collaborators SET status=$2 WHERE id=$1`, f.subject, status); err != nil {
			t.Fatalf("status fixture %q failed: %v", status, err)
		}
	}

	// Issued while active: a bound request with a saved code, and a refresh token.
	ar := newBoundRequest(t)
	requestID, err := uuid.Parse(ar.GetID())
	if err != nil {
		t.Fatal("request id fixture failed")
	}
	code := "status-old-" + uuid.NewString()
	if err := repository.SaveOIDCAuthCode(ctx, f.db, code, requestID, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("old code fixture failed: %v", err)
	}
	req := &minimalTokenRequest{subject: f.subject.String(), clientID: f.clientID, scopes: []string{"openid"}}
	_, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, req, "")
	if err != nil || refresh == "" {
		t.Fatalf("an active subject could not mint the refresh fixture: %v", err)
	}

	for _, status := range []string{"pending_start", "on_leave", "suspended", "offboarded"} {
		t.Run(status, func(t *testing.T) {
			setStatus(t, status)
			prebound := newBoundRequest(t)
			if _, err := s.AuthRequestByID(ctx, prebound.GetID()); !errors.Is(err, repository.ErrCollaboratorCannotSignIn) {
				t.Fatalf("a request created with the subject was honored: %v", err)
			}
			if _, err := s.AuthRequestByID(ctx, ar.GetID()); !errors.Is(err, repository.ErrCollaboratorCannotSignIn) {
				t.Fatalf("a request bound while active was honored: %v", err)
			}
			if err := s.SaveAuthCode(ctx, ar.GetID(), "refused-"+status+"-"+uuid.NewString()); !errors.Is(err, repository.ErrCollaboratorCannotSignIn) {
				t.Fatalf("a code was saved: %v", err)
			}
			if _, err := s.AuthRequestByCode(ctx, code); !errors.Is(err, repository.ErrCollaboratorCannotSignIn) {
				t.Fatalf("a code saved while active was exchanged: %v", err)
			}
			if token, _, err := s.CreateAccessToken(ctx, req); token != "" || !errors.Is(err, repository.ErrCollaboratorCannotSignIn) {
				t.Fatalf("an access token was minted: %v", err)
			}
			if token, rt, _, err := s.CreateAccessAndRefreshTokens(ctx, req, ""); token != "" || rt != "" || !errors.Is(err, repository.ErrCollaboratorCannotSignIn) {
				t.Fatalf("a refresh token was minted: %v", err)
			}
			if _, err := s.TokenRequestByRefreshToken(ctx, refresh); !errors.Is(err, op.ErrInvalidRefreshToken) {
				t.Fatalf("the refresh grant was not invalid_grant: %v", err)
			}
			// An access token minted while active outlives the change: the
			// provider introspection answers inactive (an error before any
			// field is set) and userinfo refuses it.
			introspection := new(oidc.IntrospectionResponse)
			if err := s.SetIntrospectionFromToken(ctx, introspection, "jti-"+status, f.subject.String(), f.clientID); !errors.Is(err, repository.ErrCollaboratorCannotSignIn) || introspection.Subject != "" || introspection.Email != "" {
				t.Fatalf("introspection described the token: err=%v subject=%q", err, introspection.Subject)
			}
			if err := s.SetUserinfoFromToken(ctx, new(oidc.UserInfo), "jti-"+status, f.subject.String(), ""); !errors.Is(err, repository.ErrCollaboratorCannotSignIn) {
				t.Fatalf("userinfo answered: %v", err)
			}
		})
	}

	setStatus(t, "active")
	// The refused exchanges did not consume the code: it exchanges once now,
	// and its single-use defense still holds.
	if _, err := s.AuthRequestByCode(ctx, code); err != nil {
		t.Fatalf("restoring active did not unlock the original code: %v", err)
	}
	if _, err := s.AuthRequestByCode(ctx, code); err == nil {
		t.Fatal("the status gate relaxed the code replay defense")
	}
	// The refused refresh grants revoked nothing; the gate reads the current row.
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh); err != nil {
		t.Fatalf("restoring active did not restore the refresh grant: %v", err)
	}
	introspection := new(oidc.IntrospectionResponse)
	if err := s.SetIntrospectionFromToken(ctx, introspection, "jti-active", f.subject.String(), f.clientID); err != nil || introspection.Subject != f.subject.String() {
		t.Fatalf("restoring active did not restore introspection: err=%v subject=%q", err, introspection.Subject)
	}
}
