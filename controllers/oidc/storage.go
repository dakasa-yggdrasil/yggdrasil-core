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
	"github.com/google/uuid"
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

// authRequestView adapts a model.OIDCAuthRequest to op.AuthRequest. The
// view also carries the userID set when the request was created (or
// promoted on login completion) so the OP can build subject claims.
type authRequestView struct {
	r      model.OIDCAuthRequest
	userID string
}

func newAuthRequestView(r model.OIDCAuthRequest) *authRequestView {
	uid := ""
	if r.CollaboratorID != nil {
		uid = r.CollaboratorID.String()
	}
	return &authRequestView{r: r, userID: uid}
}

func (v *authRequestView) GetID() string         { return v.r.ID.String() }
func (v *authRequestView) GetACR() string        { return "" }
func (v *authRequestView) GetAMR() []string      { return nil }
func (v *authRequestView) GetAudience() []string { return []string{v.r.ClientID} }

// GetAuthTime: we don't track auth_time separately, so report the request
// creation time. Once Task 8 wires login completion, this will be updated
// to the actual login moment.
func (v *authRequestView) GetAuthTime() time.Time { return v.r.CreatedAt }

func (v *authRequestView) GetClientID() string { return v.r.ClientID }

// GetCodeChallenge surfaces PKCE info to the OP. nil when the client
// didn't supply one (and PKCE is not required for that client).
func (v *authRequestView) GetCodeChallenge() *oidc.CodeChallenge {
	if v.r.CodeChallenge == "" {
		return nil
	}
	method := oidc.CodeChallengeMethodS256
	if v.r.CodeChallengeMethod == "plain" {
		method = oidc.CodeChallengeMethodPlain
	}
	return &oidc.CodeChallenge{
		Challenge: v.r.CodeChallenge,
		Method:    method,
	}
}

func (v *authRequestView) GetNonce() string                  { return v.r.Nonce }
func (v *authRequestView) GetRedirectURI() string            { return v.r.RedirectURI }
func (v *authRequestView) GetResponseType() oidc.ResponseType { return oidc.ResponseTypeCode }

// GetResponseMode — empty defers to OP defaults (form_post for code flow).
func (v *authRequestView) GetResponseMode() oidc.ResponseMode { return "" }

func (v *authRequestView) GetScopes() []string { return v.r.Scopes }
func (v *authRequestView) GetState() string    { return v.r.State }
func (v *authRequestView) GetSubject() string  { return v.userID }

// Done reports whether the user has completed authentication. We treat
// this as "user has been bound to the request": ID present and non-empty.
// Task 8 will update the request's collaborator_id at login completion.
func (v *authRequestView) Done() bool { return v.userID != "" }

// CreateAuthRequest persists a new auth request. The OP passes the parsed
// authorization request from the user agent; userID is the subject if the
// session is already authenticated (we receive empty string for fresh
// authorize calls and set collaborator_id later).
func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	ar := model.OIDCAuthRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scopes:              []string(req.Scopes),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
		State:               req.State,
		Nonce:               req.Nonce,
		ExpiresAt:           time.Now().Add(AuthorizationCodeLifetime),
	}
	if userID != "" {
		// Tolerate non-UUID values (zitadel example uses string IDs).
		// We only attach a collaborator_id when the value parses cleanly;
		// otherwise leave the column NULL so the FK constraint passes.
		if cid, err := uuid.Parse(userID); err == nil {
			ar.CollaboratorID = &cid
		}
	}
	id, err := repository.CreateOIDCAuthRequest(ctx, s.db, ar)
	if err != nil {
		return nil, err
	}
	ar.ID = id
	ar.CreatedAt = time.Now() // approximation; row's created_at is authoritative
	return newAuthRequestView(ar), nil
}

// AuthRequestByID looks up a previously created auth request. Called by
// the OP after the login UI redirects back, before issuing a code.
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid auth request id")
	}
	ar, err := repository.GetOIDCAuthRequestByID(ctx, s.db, parsed)
	if err != nil {
		return nil, err
	}
	return newAuthRequestView(ar), nil
}

// AuthRequestByCode resolves an auth request via its issued code. The OP
// calls this in the token endpoint to recover the original request before
// issuing access/refresh tokens. Code consumption (single-use enforcement)
// happens separately via repository.ConsumeOIDCAuthCode.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	ar, err := repository.GetOIDCAuthRequestByCode(ctx, s.db, code)
	if err != nil {
		return nil, err
	}
	return newAuthRequestView(ar), nil
}

// SaveAuthCode persists a freshly issued authorization code, linking it
// to the originating auth request id. The OP generates the code value
// (entropy is its concern); we just store it with our standard expiry.
func (s *Storage) SaveAuthCode(ctx context.Context, id string, code string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return errors.New("invalid auth request id")
	}
	return repository.SaveOIDCAuthCode(ctx, s.db, code, parsed, time.Now().Add(AuthorizationCodeLifetime))
}

// DeleteAuthRequest marks the request as consumed. We never hard-delete
// because we keep the row for audit; consumed_at stops it being reused.
// Idempotent: replays of DeleteAuthRequest are no-ops.
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return errors.New("invalid auth request id")
	}
	return repository.MarkOIDCAuthRequestConsumed(ctx, s.db, parsed)
}
