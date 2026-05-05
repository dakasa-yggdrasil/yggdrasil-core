// Package oidc implements the op.Storage interface required by the
// github.com/zitadel/oidc/v3 OpenID Provider. Each method delegates to
// repositories built in Phase 1 Tasks 1–5, with serializable transactions
// where atomicity is required (auth code consumption, refresh rotation).
package oidc

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Lifetime defaults shared across the provider.
const (
	IDTokenLifetime           = 15 * time.Minute
	AccessTokenLifetime       = 15 * time.Minute
	AuthorizationCodeLifetime = 10 * time.Minute
	RefreshTokenLifetime      = 30 * 24 * time.Hour
)

// Storage adapts repository helpers to the op.Storage interface.
type Storage struct {
	db        *sql.DB
	issuerURL string
}

// NewStorage builds a Storage rooted at the given issuer URL. The URL is
// used as the base for generated LoginURL values returned to the OP for
// redirecting the user agent into the third-party login flow.
func NewStorage(db *sql.DB, issuerURL string) *Storage {
	return &Storage{db: db, issuerURL: issuerURL}
}

// clientView wraps a model.OIDCClient and adapts it to op.Client. It is
// constructed per-request — never cached — so the underlying record is
// always fresh from the DB.
type clientView struct {
	c         model.OIDCClient
	issuerURL string
}

func newClientView(c model.OIDCClient, issuerURL string) *clientView {
	return &clientView{c: c, issuerURL: issuerURL}
}

func (v *clientView) GetID() string                    { return v.c.ClientID }
func (v *clientView) RedirectURIs() []string           { return v.c.RedirectURIs }
func (v *clientView) PostLogoutRedirectURIs() []string { return v.c.PostLogoutRedirectURIs }

// ApplicationType: confidential (has secret hash) → Web; otherwise UserAgent.
// Public clients aren't used in MVP but the path stays correct.
func (v *clientView) ApplicationType() op.ApplicationType {
	if v.c.ClientSecretHash != "" {
		return op.ApplicationTypeWeb
	}
	return op.ApplicationTypeUserAgent
}

// AuthMethod mirrors ApplicationType: Basic when there's a secret, None
// (PKCE-only) for public clients.
func (v *clientView) AuthMethod() oidc.AuthMethod {
	if v.c.ClientSecretHash != "" {
		return oidc.AuthMethodBasic
	}
	return oidc.AuthMethodNone
}

// ResponseTypes — MVP supports the authorization code flow only.
func (v *clientView) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

// GrantTypes — translate stored string grants into oidc.GrantType. Unknown
// values are skipped.
func (v *clientView) GrantTypes() []oidc.GrantType {
	out := make([]oidc.GrantType, 0, len(v.c.GrantTypes))
	for _, g := range v.c.GrantTypes {
		switch g {
		case "authorization_code":
			out = append(out, oidc.GrantTypeCode)
		case "refresh_token":
			out = append(out, oidc.GrantTypeRefreshToken)
		}
	}
	return out
}

// LoginURL bridges the OP's "login required" signal into our third-party
// (Google) flow. Task 8 wires the actual handler at /auth/third-party/start/google.
func (v *clientView) LoginURL(authReqID string) string {
	q := url.Values{}
	q.Set("auth_request_id", authReqID)
	return v.issuerURL + "/auth/third-party/start/google?" + q.Encode()
}

func (v *clientView) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (v *clientView) IDTokenLifetime() time.Duration      { return IDTokenLifetime }
func (v *clientView) AccessTokenLifetime() time.Duration  { return AccessTokenLifetime }
func (v *clientView) AuthorizationCodeLifetime() time.Duration {
	return AuthorizationCodeLifetime
}

// DevMode is false in production. Setting true allows ANY redirect URI to
// match — never desirable here.
func (v *clientView) DevMode() bool { return false }

// RestrictAdditionalIdTokenScopes / AccessTokenScopes — identity. We don't
// drop scopes from issued tokens beyond what the auth flow already approved.
func (v *clientView) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (v *clientView) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

// IsScopeAllowed checks membership in the registered scope list for this
// client. Scopes never registered fail closed.
func (v *clientView) IsScopeAllowed(scope string) bool {
	for _, allowed := range v.c.Scopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

// IDTokenUserinfoClaimsAssertion controls whether the ID token includes the
// full set of userinfo claims. We follow zitadel's recommendation and keep
// it false; clients that need them call /userinfo.
func (v *clientView) IDTokenUserinfoClaimsAssertion() bool { return false }

// ClockSkew gives the OP no extra leniency — server clocks should be in NTP.
func (v *clientView) ClockSkew() time.Duration { return 0 }

// GetClientByClientID loads a client record from the DB. The OP calls this
// on virtually every request that mentions a client_id.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := repository.GetOIDCClientByID(ctx, s.db, clientID)
	if err != nil {
		return nil, err
	}
	return newClientView(c, s.issuerURL), nil
}

// AuthorizeClientIDSecret is invoked by the OP to validate confidential
// client credentials at the token endpoint. The DB stores a bcrypt hash;
// we compare in constant time via the bcrypt helper.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	c, err := repository.GetOIDCClientByID(ctx, s.db, clientID)
	if err != nil {
		return err
	}
	if c.ClientSecretHash == "" {
		// Public client should never reach the secret-auth path; refuse.
		return errors.New("client has no secret configured")
	}
	return bcryptCompare(c.ClientSecretHash, clientSecret)
}
