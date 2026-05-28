// Package oidc — RFC 8417 (OpenID Connect Back-Channel Logout) dispatcher.
//
// When yggdrasil-core terminates a session server-side (logout, admin
// revoke, password rotation, offboarding) it MUST notify every OIDC client
// that has an active session for the user so the revocation propagates in
// real time. This file implements the §13 INTEGRATION_CONTRACT requirement
// using the open IETF spec — no vendor lock-in (no Auth0/Okta/Fusionauth
// library).
//
// Spec: https://openid.net/specs/openid-connect-backchannel-1_0.html
//
// Wire shape — for each (collaborator, client) link with a registered
// backchannel_logout_uri:
//
//   POST <backchannel_logout_uri>
//   Content-Type: application/x-www-form-urlencoded
//
//   logout_token=<signed JWT with the §2.4 events claim>
//
// The signed JWT carries the §2.4 logout event:
//
//   {
//     "iss": "<issuer>",
//     "sub": "<collaborator id>",
//     "aud": "<client id>",
//     "iat": <now>,
//     "jti": "<uuid v4>",
//     "events": {
//       "http://schemas.openid.net/event/backchannel-logout": {}
//     },
//     "sid": "<oidc_session_links.sid>"
//   }
package oidc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// BackchannelEventClaim is the URI defined in RFC 8417 §2.4.
const BackchannelEventClaim = "http://schemas.openid.net/event/backchannel-logout"

// BackchannelDispatchTimeout bounds the per-client POST. RFC 8417 §3.1
// recommends a short timeout so a slow client doesn't block the dispatch
// loop — 5s is on the conservative end, change with care.
var BackchannelDispatchTimeout = 5 * time.Second

// BackchannelDispatchResult summarizes one POST attempt. Aggregated across
// every client into the dispatch summary written back to
// session_revocation.metadata for audit.
type BackchannelDispatchResult struct {
	ClientID   string `json:"client_id"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
	Succeeded  bool   `json:"succeeded"`
}

// BackchannelDispatcher fires logout_token POSTs against every active OIDC
// client when a collaborator's session terminates server-side. Pluggable
// HTTP client (test override) + injectable now() for deterministic JWT iat.
type BackchannelDispatcher struct {
	Storage  *Storage
	HTTP     *http.Client
	IssuerURL string
	Now      func() time.Time
}

// NewBackchannelDispatcher wires a dispatcher backed by the supplied
// Storage with sensible defaults for HTTP client + clock.
func NewBackchannelDispatcher(storage *Storage, issuerURL string) *BackchannelDispatcher {
	return &BackchannelDispatcher{
		Storage:   storage,
		HTTP:      &http.Client{Timeout: BackchannelDispatchTimeout},
		IssuerURL: issuerURL,
		Now:       time.Now,
	}
}

// DispatchForCollaborator fans out to every active OIDC client linked to
// the collaborator. Returns one result per client attempted. The dispatcher
// blocks until ALL clients have either responded or hit timeout — the
// caller decides whether to mark the revocation row complete (typical) or
// retry the failures later.
//
// Errors fetching the signing key or active links abort early with an
// error; per-client errors are recorded in the results slice (Succeeded=false)
// so a single slow client never blocks the others (concurrent dispatch).
func (d *BackchannelDispatcher) DispatchForCollaborator(
	ctx context.Context,
	collaboratorID uuid.UUID,
) ([]BackchannelDispatchResult, error) {
	links, err := repository.ListActiveOIDCSessionLinksForCollaborator(ctx, d.Storage.db, collaboratorID)
	if err != nil {
		return nil, fmt.Errorf("list session links: %w", err)
	}
	return d.dispatchLinks(ctx, links)
}

// DispatchForSession narrows the dispatch to one specific auth_session
// (logout from one device leaves other devices intact).
func (d *BackchannelDispatcher) DispatchForSession(
	ctx context.Context,
	sessionID uuid.UUID,
) ([]BackchannelDispatchResult, error) {
	links, err := repository.ListActiveOIDCSessionLinksForSession(ctx, d.Storage.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("list session links: %w", err)
	}
	return d.dispatchLinks(ctx, links)
}

func (d *BackchannelDispatcher) dispatchLinks(
	ctx context.Context,
	links []model.OIDCSessionLink,
) ([]BackchannelDispatchResult, error) {
	if len(links) == 0 {
		return nil, nil
	}

	// Pre-fetch the active signing key ONCE — every logout_token shares it.
	signer, err := d.buildSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("build signer: %w", err)
	}

	results := make([]BackchannelDispatchResult, len(links))
	var wg sync.WaitGroup
	for i, link := range links {
		wg.Add(1)
		go func(i int, link model.OIDCSessionLink) {
			defer wg.Done()
			results[i] = d.dispatchOne(ctx, signer, link)
			// Mark the link terminated regardless of outcome — the
			// revocation IS authoritative. Failures are surfaced via
			// the BackchannelDispatchResult and audit-logged.
			_ = repository.MarkOIDCSessionLinkTerminated(ctx, d.Storage.db, link.ID)
		}(i, link)
	}
	wg.Wait()
	return results, nil
}

// dispatchOne signs + POSTs the logout_token for one link. Never panics —
// failures show up as Succeeded=false with the error captured.
func (d *BackchannelDispatcher) dispatchOne(
	ctx context.Context,
	signer jose.Signer,
	link model.OIDCSessionLink,
) BackchannelDispatchResult {
	result := BackchannelDispatchResult{ClientID: link.ClientID}

	client, err := repository.GetOIDCClientByID(ctx, d.Storage.db, link.ClientID)
	if err != nil {
		result.Error = fmt.Sprintf("fetch client: %v", err)
		return result
	}
	uri := client.BackchannelLogoutURI
	if uri == "" {
		// No back-channel URI registered → silently skip; RFC 7662
		// introspection is the fallback path. Mark succeeded so the
		// audit summary doesn't flag a non-action as a failure.
		result.Succeeded = true
		result.Error = "client did not register backchannel_logout_uri"
		return result
	}
	if _, err := url.Parse(uri); err != nil {
		result.Error = fmt.Sprintf("invalid backchannel_logout_uri: %v", err)
		return result
	}

	token, err := d.buildLogoutToken(signer, link, client.ClientID)
	if err != nil {
		result.Error = fmt.Sprintf("build token: %v", err)
		return result
	}

	body := url.Values{"logout_token": []string{token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewBufferString(body.Encode()))
	if err != nil {
		result.Error = fmt.Sprintf("build request: %v", err)
		return result
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.HTTP.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("dispatch: %v", err)
		return result
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	result.StatusCode = resp.StatusCode

	// RFC 8417 §3.1: clients return 2xx on success. 200 is the canonical
	// response; we accept any 2xx for forward compat.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Succeeded = true
	} else {
		result.Error = fmt.Sprintf("client responded %d", resp.StatusCode)
	}
	return result
}

// buildSigner constructs a JWT signer rooted at the active OIDC signing
// key. RS256 is the only algorithm we issue today — same as the
// authorization-code path (storage.go SignatureAlgorithms).
func (d *BackchannelDispatcher) buildSigner(ctx context.Context) (jose.Signer, error) {
	k, err := repository.GetCurrentOIDCSigningKey(ctx, d.Storage.db, SigningAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("fetch signing key: %w", err)
	}
	priv, kid, err := parseSigningKey(k)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("active signing key is not RSA")
	}
	return jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:   rsaKey,
			KeyID: kid,
			Use:   "sig",
		},
	}, (&jose.SignerOptions{}).WithType("logout+jwt"))
}

// LogoutTokenClaims is the RFC 8417 §2.4 claim set, plus the empty events
// payload required by the spec. The signed token serializes these claims.
type LogoutTokenClaims struct {
	Issuer    string                 `json:"iss"`
	Subject   string                 `json:"sub"`
	Audience  string                 `json:"aud"`
	IssuedAt  int64                  `json:"iat"`
	JTI       string                 `json:"jti"`
	Events    map[string]interface{} `json:"events"`
	SessionID string                 `json:"sid,omitempty"`
}

// buildLogoutToken signs the §2.4 logout_token claims.
func (d *BackchannelDispatcher) buildLogoutToken(
	signer jose.Signer,
	link model.OIDCSessionLink,
	clientID string,
) (string, error) {
	now := d.Now().UTC()
	jti, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	claims := LogoutTokenClaims{
		Issuer:    d.IssuerURL,
		Subject:   link.CollaboratorID.String(),
		Audience:  clientID,
		IssuedAt:  now.Unix(),
		JTI:       jti.String(),
		Events:    map[string]interface{}{BackchannelEventClaim: map[string]interface{}{}},
		SessionID: link.SID.String(),
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	// Sanity-check that the token round-trips through our own parser before
	// we ship it — protects against signer misconfiguration that would
	// quietly emit malformed tokens.
	if _, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256}); err != nil {
		return "", fmt.Errorf("self-verify token shape: %w", err)
	}
	return token, nil
}

// SummarizeDispatch converts results into the JSONB summary persisted in
// session_revocation.metadata. Includes the overall success count so
// audit dashboards can flag revocations with partial failures.
func SummarizeDispatch(results []BackchannelDispatchResult) map[string]any {
	if len(results) == 0 {
		return map[string]any{"backchannel": map[string]any{
			"dispatched": 0,
			"succeeded":  0,
		}}
	}
	succeeded := 0
	for _, r := range results {
		if r.Succeeded {
			succeeded++
		}
	}
	raw, _ := json.Marshal(results)
	return map[string]any{
		"backchannel": map[string]any{
			"dispatched": len(results),
			"succeeded":  succeeded,
			"results":    json.RawMessage(raw),
		},
	}
}
