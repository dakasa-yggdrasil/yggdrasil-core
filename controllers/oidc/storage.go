// Package oidc implements the op.Storage interface required by the
// github.com/zitadel/oidc/v3 OpenID Provider. Each method delegates to
// repositories built in Phase 1 Tasks 1–5, with serializable transactions
// where atomicity is required (auth code consumption, refresh rotation).
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	jose "github.com/go-jose/go-jose/v4"
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

func (v *authRequestView) GetNonce() string                   { return v.r.Nonce }
func (v *authRequestView) GetRedirectURI() string             { return v.r.RedirectURI }
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

// generateOpaqueToken returns 32 bytes of base64url-encoded entropy.
// Used for both access-token IDs (which we don't persist; the JWT issued
// by the OP is the actual access token) and refresh tokens (which we do
// persist for rotation tracking).
func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateAccessToken is invoked when the flow doesn't issue a refresh
// token (rare in our setup, but kept correct). The returned ID is the
// "jti" the OP embeds in the access JWT — opaque, not persisted because
// access tokens are stateless.
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	id, err := generateOpaqueToken()
	if err != nil {
		return "", time.Time{}, err
	}
	return id, time.Now().Add(AccessTokenLifetime), nil
}

// CreateAccessAndRefreshTokens is the primary token-mint path. Two flows
// converge here:
//
//   - Code Flow: currentRefreshToken == "". A fresh refresh token is created.
//   - Refresh Flow: currentRefreshToken != "". The token is rotated: the
//     old token is revoked atomically and the new token is issued. If the
//     old token was already revoked or absent, the entire chain is revoked
//     (replay defense, RFC 6819 §5.2.2.3).
func (s *Storage) CreateAccessAndRefreshTokens(
	ctx context.Context, request op.TokenRequest, currentRefreshToken string,
) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	accessID, err := generateOpaqueToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	rt, err := generateOpaqueToken()
	if err != nil {
		return "", "", time.Time{}, err
	}

	collabID, perr := uuid.Parse(request.GetSubject())
	if perr != nil {
		return "", "", time.Time{}, fmt.Errorf("token subject is not a UUID: %w", perr)
	}

	// Determine client_id from the request; the concrete type is one of
	// authRequestView (code flow), refreshTokenRequestView (refresh flow),
	// or *oidc.JWTTokenRequest. Best-effort extraction with a nil-safe path.
	clientID := clientIDFromTokenRequest(request)

	rec := model.OIDCRefreshToken{
		Token:          rt,
		CollaboratorID: collabID,
		ClientID:       clientID,
		Scopes:         request.GetScopes(),
		ExpiresAt:      time.Now().Add(RefreshTokenLifetime),
	}

	if currentRefreshToken == "" {
		// Code Flow: fresh issuance, no chain entry.
		if err := repository.CreateOIDCRefreshToken(ctx, s.db, rec); err != nil {
			return "", "", time.Time{}, fmt.Errorf("create refresh: %w", err)
		}
	} else {
		// Refresh Flow: rotate atomically. Repository signals "already
		// revoked or missing" by returning a sentinel-shaped error; on
		// that, we revoke the chain to lock out the replayer.
		rec.RotatedFrom = &currentRefreshToken
		rotErr := repository.RotateOIDCRefreshToken(ctx, s.db, currentRefreshToken, rec)
		if rotErr != nil {
			if isReplayError(rotErr) {
				// Defensive — RotateOIDCRefreshToken found the old token
				// already revoked. Revoke the whole chain so any leaked
				// descendant can't be exchanged.
				_, _ = repository.RevokeOIDCRefreshChainByRoot(ctx, s.db, currentRefreshToken)
				// Audit after revocation so the chain is locked even if
				// the audit insert fails. Token prefix only; the full
				// token is sensitive material.
				cid := rec.CollaboratorID
				recordOIDCAudit(ctx, s.db, "oidc.refresh_token.replay_detected", &cid, rec.ClientID, map[string]any{
					"replayed_token_prefix": tokenPrefix(currentRefreshToken),
				}, "denied")
				return "", "", time.Time{}, fmt.Errorf("refresh token replay detected; chain revoked")
			}
			return "", "", time.Time{}, fmt.Errorf("rotate refresh: %w", rotErr)
		}
	}

	return accessID, rt, time.Now().Add(AccessTokenLifetime), nil
}

// isReplayError checks for the marker text used by RotateOIDCRefreshToken
// when the old token is already revoked / missing. Brittle on the message
// shape, so wrap the check in one place.
func isReplayError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "already revoked or missing")
}

// clientIDFromTokenRequest pulls the client identifier from whichever of
// the supported request types is presented. Returns "" only if the type
// genuinely doesn't expose one (which would be an error, but we leave
// blame to the caller — refresh-token row will then violate the FK).
func clientIDFromTokenRequest(req op.TokenRequest) string {
	type clientIDProvider interface{ GetClientID() string }
	if cp, ok := req.(clientIDProvider); ok {
		return cp.GetClientID()
	}
	// Last-resort: scope-only audience hint. Should not happen in our flows.
	if aud := req.GetAudience(); len(aud) > 0 {
		return aud[0]
	}
	return ""
}

// refreshTokenRequestView adapts a stored refresh token to the OP's
// op.RefreshTokenRequest interface. The OP uses this to assemble the new
// access token claims.
type refreshTokenRequestView struct {
	r       model.OIDCRefreshToken
	current []string
}

func (v *refreshTokenRequestView) GetAMR() []string            { return nil }
func (v *refreshTokenRequestView) GetAudience() []string       { return []string{v.r.ClientID} }
func (v *refreshTokenRequestView) GetAuthTime() time.Time      { return v.r.CreatedAt }
func (v *refreshTokenRequestView) GetClientID() string         { return v.r.ClientID }
func (v *refreshTokenRequestView) GetSubject() string          { return v.r.CollaboratorID.String() }
func (v *refreshTokenRequestView) SetCurrentScopes(s []string) { v.current = s }

// GetScopes returns the scopes the OP should embed in the new access
// token. We default to the original grant scopes; if SetCurrentScopes
// was called we honor that narrowing.
func (v *refreshTokenRequestView) GetScopes() []string {
	if v.current != nil {
		return v.current
	}
	return v.r.Scopes
}

// TokenRequestByRefreshToken loads a refresh token, validates its state,
// and returns a request view the OP can rebuild new tokens from. Critical:
// if the token is already revoked, we revoke the whole chain (replay) and
// return an error.
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	r, err := repository.GetOIDCRefreshToken(ctx, s.db, refreshToken)
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	if r.RevokedAt != nil {
		// Replay attempt: the token has been revoked. Revoke the entire
		// chain rooted at this token so even unrevoked descendants stop
		// working.
		_, _ = repository.RevokeOIDCRefreshChainByRoot(ctx, s.db, refreshToken)
		return nil, op.ErrInvalidRefreshToken
	}
	if time.Now().After(r.ExpiresAt) {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshTokenRequestView{r: r}, nil
}

// TerminateSession revokes all live refresh tokens issued for the given
// client/user pair. Access tokens are stateless (JWTs) — they expire on
// their own; we cannot recall them.
func (s *Storage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	parsed, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user id: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE oidc_refresh_tokens SET revoked_at = NOW()
		WHERE collaborator_id = $1 AND client_id = $2 AND revoked_at IS NULL
	`, parsed, clientID)
	if err != nil {
		return fmt.Errorf("terminate session: %w", err)
	}
	return nil
}

// RevokeToken handles the revocation endpoint. Per the OP contract, when
// the original request was for a refresh token, tokenOrTokenID is the
// raw refresh token and userID may be empty. For access tokens, only
// access-token-id is passed (we don't persist those — the JWT carries
// its own expiry, so we treat the request as a no-op except for chain
// revocation if the value happens to also be a refresh token).
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	r, err := repository.GetOIDCRefreshToken(ctx, s.db, tokenOrTokenID)
	if err != nil {
		// Not a refresh token we know about — treat as access token id.
		// We have nothing to revoke; the spec accepts silent no-op.
		return nil
	}
	if r.ClientID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	if _, err := repository.RevokeOIDCRefreshChainByRoot(ctx, s.db, tokenOrTokenID); err != nil {
		return oidc.ErrServerError().WithDescription("%s", err.Error())
	}
	return nil
}

// GetRefreshTokenInfo returns the user-id and token-id of a refresh
// token. The OP calls this from RevokeToken when the supplied value
// looks like a refresh token. Token id and token value are the same in
// our scheme (opaque base64url string).
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	r, err := repository.GetOIDCRefreshToken(ctx, s.db, token)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	if r.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return r.CollaboratorID.String(), token, nil
}

// signingKeyView adapts a stored OIDCSigningKey to the OP's op.SigningKey
// interface. The Key() method returns the parsed *rsa.PrivateKey so the
// OP can sign JWTs directly.
type signingKeyView struct {
	id      string
	private any // parsed via parseSigningKey
}

func (v *signingKeyView) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (v *signingKeyView) Key() any                                    { return v.private }
func (v *signingKeyView) ID() string                                  { return v.id }

// publicKeyView adapts a stored OIDCSigningKey to the OP's op.Key
// interface (used for /jwks publication and for validating tokens via
// the /userinfo endpoint).
type publicKeyView struct {
	id     string
	pubKey any
}

func (v *publicKeyView) ID() string                         { return v.id }
func (v *publicKeyView) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (v *publicKeyView) Use() string                        { return "sig" }
func (v *publicKeyView) Key() any                           { return v.pubKey }

// parseSigningKey extracts the *rsa.PrivateKey from a stored row's
// PrivatePEM blob. Returns the key and the kid (sourced from PublicJWK).
func parseSigningKey(k model.OIDCSigningKey) (privKey any, kid string, err error) {
	block, _ := pem.Decode([]byte(k.PrivatePEM))
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block in private key")
	}
	priv, perr := x509.ParsePKCS1PrivateKey(block.Bytes)
	if perr != nil {
		// Fall back to PKCS8 if PKCS1 parse fails.
		anyKey, p2err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if p2err != nil {
			return nil, "", fmt.Errorf("parse private key: %w (pkcs8: %v)", perr, p2err)
		}
		privKey = anyKey
	} else {
		privKey = priv
	}
	if v, ok := k.PublicJWK["kid"].(string); ok {
		kid = v
	} else {
		kid = k.ID.String()
	}
	return privKey, kid, nil
}

// SigningKey returns the active RS256 signing key. Called by the OP each
// time it needs to sign a JWT.
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	k, err := repository.GetCurrentOIDCSigningKey(ctx, s.db, SigningAlgorithm)
	if err != nil {
		return nil, err
	}
	priv, kid, err := parseSigningKey(k)
	if err != nil {
		return nil, err
	}
	return &signingKeyView{id: kid, private: priv}, nil
}

// SignatureAlgorithms enumerates the algorithms we publish in the
// discovery document. RS256-only for MVP.
func (s *Storage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet returns the public keys we publish at /jwks. Includes every
// active key (we may have two during rotation overlap).
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	keys, err := repository.ListActiveOIDCSigningKeys(ctx, s.db, SigningAlgorithm)
	if err != nil {
		return nil, err
	}
	out := make([]op.Key, 0, len(keys))
	for _, k := range keys {
		priv, kid, perr := parseSigningKey(k)
		if perr != nil {
			return nil, perr
		}
		// Extract the public part. RSA: priv.Public(). Other key types
		// would need similar treatment when added.
		type publicKeyer interface{ Public() any }
		var pub any
		if pp, ok := priv.(publicKeyer); ok {
			pub = pp.Public()
		} else {
			pub = priv
		}
		out = append(out, &publicKeyView{id: kid, pubKey: pub})
	}
	return out, nil
}

// GetKeyByIDAndClientID is used to validate JWT-Profile assertions
// (private_key_jwt etc.). We don't support that auth method in MVP,
// so always fail closed.
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("private_key_jwt not supported")
}

// SetUserinfoFromScopes populates the OP's UserInfo struct given the
// granted scopes. Per zitadel guidance this is deprecated in favor of
// SetUserinfoFromRequest, but we still implement it because the
// op.OPStorage interface requires it.
func (s *Storage) SetUserinfoFromScopes(
	ctx context.Context, userInfo *oidc.UserInfo, userID, clientID string, scopes []string,
) error {
	return s.populateUserInfo(ctx, userInfo, userID, scopes)
}

// SetUserinfoFromToken is the userinfo endpoint hook. The OP has already
// validated the bearer access token; we just need to populate claims.
func (s *Storage) SetUserinfoFromToken(
	ctx context.Context, userInfo *oidc.UserInfo, tokenID, subject, origin string,
) error {
	return s.populateUserInfo(ctx, userInfo, subject, []string{
		oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile, "roles",
	})
}

// SetIntrospectionFromToken is the introspection endpoint hook. We
// populate the same claims as userinfo plus a few token-specific fields.
func (s *Storage) SetIntrospectionFromToken(
	ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string,
) error {
	cid, email, displayName, err := loadCollaboratorForUserinfo(ctx, s.db, subject)
	if err != nil {
		return err
	}
	introspection.Subject = subject
	introspection.UserInfoEmail.Email = email
	introspection.UserInfoEmail.EmailVerified = true
	introspection.UserInfoProfile.Name = displayName
	introspection.ClientID = clientID

	teams, terr := buildTeamsClaim(ctx, s.db, cid)
	if terr == nil && len(teams) > 0 {
		if introspection.Claims == nil {
			introspection.Claims = make(map[string]any)
		}
		introspection.Claims["teams"] = teams
	}
	return nil
}

// populateUserInfo fills email/name and (if "roles" granted) teams on the
// shared *oidc.UserInfo struct. Used by SetUserinfoFromScopes and
// SetUserinfoFromToken which differ only in the trigger.
func (s *Storage) populateUserInfo(
	ctx context.Context, userInfo *oidc.UserInfo, userID string, scopes []string,
) error {
	cid, email, displayName, err := loadCollaboratorForUserinfo(ctx, s.db, userID)
	if err != nil {
		return err
	}
	userInfo.Subject = userID
	if scopesContains(scopes, oidc.ScopeEmail) {
		userInfo.UserInfoEmail.Email = email
		userInfo.UserInfoEmail.EmailVerified = true
	}
	if scopesContains(scopes, oidc.ScopeProfile) {
		userInfo.UserInfoProfile.Name = displayName
	}
	if scopesContains(scopes, "roles") {
		teams, terr := buildTeamsClaim(ctx, s.db, cid)
		if terr == nil {
			userInfo.AppendClaims("teams", teams)
		}
		if role, err := buildRoleClaim(ctx, s.db, cid); err == nil && role != "" {
			userInfo.AppendClaims("role", role)
		}
		if perms, err := buildPermissionsClaim(ctx, s.db, cid); err == nil && len(perms) > 0 {
			userInfo.AppendClaims("permissions", perms)
		}
		if attrs, err := buildAttributesClaim(ctx, s.db, cid); err == nil && len(attrs) > 0 {
			userInfo.AppendClaims("attributes", attrs)
		}
	}
	return nil
}

// GetPrivateClaimsFromScopes is invoked when minting a JWT access token.
// We surface the same "teams" claim there as in userinfo when the
// "roles" scope was granted, so resource servers can authorize without
// a separate /userinfo round-trip.
func (s *Storage) GetPrivateClaimsFromScopes(
	ctx context.Context, userID, clientID string, scopes []string,
) (map[string]any, error) {
	if !scopesContains(scopes, "roles") {
		return nil, nil
	}
	cid, _, _, err := loadCollaboratorForUserinfo(ctx, s.db, userID)
	if err != nil {
		// Don't fail the whole token mint over a missing claim — log
		// upstream when introduced. Empty private claims is valid.
		return nil, nil
	}
	teams, err := buildTeamsClaim(ctx, s.db, cid)
	if err != nil {
		return nil, nil
	}
	out := map[string]any{"teams": teams}
	if role, err := buildRoleClaim(ctx, s.db, cid); err == nil && role != "" {
		out["role"] = role
	}
	if perms, err := buildPermissionsClaim(ctx, s.db, cid); err == nil && len(perms) > 0 {
		out["permissions"] = perms
	}
	if attrs, err := buildAttributesClaim(ctx, s.db, cid); err == nil && len(attrs) > 0 {
		out["attributes"] = attrs
	}
	return out, nil
}

// ValidateJWTProfileScopes filters scopes for JWT Profile (RFC 7523)
// grants. We don't enable that grant type, but the interface requires
// the method. Echo back whatever was requested; the OP enforces the
// grant_type allow-list separately.
func (s *Storage) ValidateJWTProfileScopes(
	ctx context.Context, userID string, scopes []string,
) ([]string, error) {
	return scopes, nil
}

// Health pings the database. The OP exposes /healthz; we want a real
// signal there, not a constant green.
func (s *Storage) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// _ ensures the interface is satisfied at compile time.
var _ op.Storage = (*Storage)(nil)
