package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Real storage and migrated PostgreSQL prove that provisional identity cannot
// mint native credentials, including a code saved before the requirement.
func TestPhoneProfileNativeIssuancePostgres(t *testing.T) {
	f := newNativeProtocolFixture(t)
	ctx := context.Background()
	if _, err := f.db.ExecContext(ctx, `UPDATE collaborators SET phone_profile_required=TRUE WHERE id=$1`, f.subject); err != nil {
		t.Fatal("profile fixture failed")
	}
	s := NewStorage(f.db, f.issuer)
	ar, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: f.clientID, RedirectURI: f.redirectURI, Scopes: oidc.SpaceDelimitedArray{"openid"},
		ResponseType: oidc.ResponseTypeCode, CodeChallenge: oidc.NewSHACodeChallenge(strings.Repeat("v", 43)),
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, f.subject.String())
	if err != nil {
		t.Fatal("native request fixture failed")
	}
	if _, err := s.AuthRequestByID(ctx, ar.GetID()); !errors.Is(err, repository.ErrPhoneProfileRequired) {
		t.Fatal("pending profile authorized native request")
	}
	if err := s.SaveAuthCode(ctx, ar.GetID(), "refused-code"); !errors.Is(err, repository.ErrPhoneProfileRequired) {
		t.Fatal("pending profile issued a code")
	}
	req := &minimalTokenRequest{subject: f.subject.String(), clientID: f.clientID, scopes: []string{"openid"}}
	if token, _, err := s.CreateAccessToken(ctx, req); token != "" || !errors.Is(err, repository.ErrPhoneProfileRequired) {
		t.Fatal("pending profile minted access token")
	}
	if token, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, req, ""); token != "" || refresh != "" || !errors.Is(err, repository.ErrPhoneProfileRequired) {
		t.Fatal("pending profile minted refresh token")
	}
	code := "profile-old-" + uuid.NewString()
	id, _ := uuid.Parse(ar.GetID())
	if err := repository.SaveOIDCAuthCode(ctx, f.db, code, id, time.Now().Add(time.Minute)); err != nil {
		t.Fatal("old code fixture failed")
	}
	if _, err := s.AuthRequestByCode(ctx, code); !errors.Is(err, repository.ErrPhoneProfileRequired) {
		t.Fatal("old code bypassed current completion state")
	}
	t.Setenv("YGGDRASIL_AUTH_KEK_BASE64", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	envelope, err := contactphone.EnvelopeFromEnv()
	if err != nil {
		t.Fatal("envelope fixture failed")
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("completion transaction failed")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := repository.SetPhoneContactTx(ctx, tx, envelope, f.subject, "+12025550104", "collaborator:"+f.subject.String(), "self_profile"); err != nil {
		t.Fatal("completion failed")
	}
	if tx.Commit() != nil {
		t.Fatal("completion did not commit")
	}
	// The refused exchange did not consume the old code. Its normal single-use
	// transition and issuance now work after actual profile completion.
	if _, err := s.AuthRequestByCode(ctx, code); err != nil {
		t.Fatal("completion failed to unlock original code")
	}
	if _, err := s.AuthRequestByCode(ctx, code); err == nil {
		t.Fatal("profile completion relaxed code replay defense")
	}
	if token, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, req, ""); err != nil || token == "" || refresh == "" {
		t.Fatal("completed profile cannot issue native credentials")
	}
}
