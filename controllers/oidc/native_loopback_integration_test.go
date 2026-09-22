package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TestNativeLoopbackProtocolIntegration exercises the real provider, storage,
// signing keys and PostgreSQL schema. The workflow applies every real migration
// before this test. Only external authentication is replaced: a test-only login
// handler binds a synthetic collaborator through the production repository API.
// It does not prove Google login, browser cookies, or an installed CLI's login UI.
func TestNativeLoopbackProtocolIntegration(t *testing.T) {
	fixture := newNativeProtocolFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run("success_"+strings.ToLower(method), func(t *testing.T) {
			code, nonce, verifier := fixture.authorize(t, method)
			tokens := fixture.exchange(t, code, verifier, fixture.redirectURI, http.StatusOK, "")
			fixture.verifyIdentity(t, tokens, nonce)
		})
	}
	t.Run("wrong_verifier", func(t *testing.T) {
		code, _, _ := fixture.authorize(t, http.MethodGet)
		fixture.exchange(t, code, strings.Repeat("wrong-verifier", 5), fixture.redirectURI, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("code_replay", func(t *testing.T) {
		code, _, verifier := fixture.authorize(t, http.MethodGet)
		fixture.exchange(t, code, verifier, fixture.redirectURI, http.StatusOK, "")
		fixture.exchange(t, code, verifier, fixture.redirectURI, http.StatusBadRequest, "invalid_grant")
	})
	t.Run("token_redirect_mismatch", func(t *testing.T) {
		code, _, verifier := fixture.authorize(t, http.MethodGet)
		fixture.exchange(t, code, verifier, fixture.redirectURI+"/other", http.StatusBadRequest, "invalid_grant")
	})
	t.Run("unregistered_redirect", func(t *testing.T) {
		for _, redirect := range []string{
			fixture.redirectURI + "/other",
			fixture.redirectURI + "?extra=true",
			strings.Replace(fixture.redirectURI, "127.0.0.1", "localhost", 1),
		} {
			before := fixture.authRequestCount(t)
			params, _, _ := fixture.authorizeParams()
			params.Set("redirect_uri", redirect)
			params.Set("response_type", "unsupported")
			resp := fixture.do(t, http.MethodGet, fixture.authorizationEndpoint+"?"+params.Encode(), nil, "")
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
				t.Fatalf("unregistered redirect: status %d, has Location %v", resp.StatusCode, resp.Header.Get("Location") != "")
			}
			if after := fixture.authRequestCount(t); after != before {
				t.Fatalf("unregistered redirect persisted an auth request: before=%d after=%d", before, after)
			}
		}
	})
}

type nativeProtocolFixture struct {
	db                    *sql.DB
	client                *http.Client
	clientID              string
	subject               uuid.UUID
	email                 string
	issuer                string
	redirectURI           string
	authorizationEndpoint string
	tokenEndpoint         string
	userinfoEndpoint      string
	jwksURI               string
	callbacks             chan url.Values
}

func newNativeProtocolFixture(t *testing.T) *nativeProtocolFixture {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_OIDC_NATIVE_INTEGRATION") == "true" {
			t.Fatal("DB_URL is required by the native OIDC integration gate")
		}
		t.Skip("DB_URL absent; native OIDC protocol integration requires a migrated test PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PostgreSQL unavailable: %v", err)
	}
	// No substitute schema or SQL mocks: a missing migration must fail the gate.
	if _, err := EnsureSigningKey(ctx, db); err != nil {
		t.Fatalf("real signing-key bootstrap (apply scripts/goose up first): %v", err)
	}
	f := &nativeProtocolFixture{db: db, clientID: "native-protocol-" + uuid.NewString(), callbacks: make(chan url.Values, 1)}
	f.email = f.clientID + "@example.test"
	if err := db.QueryRowContext(ctx, `INSERT INTO collaborators (slug, display_name, primary_email, status)
		VALUES ($1, 'Native Protocol Test', $2, 'active') RETURNING id`, f.clientID, f.email).Scan(&f.subject); err != nil {
		t.Fatalf("create synthetic identity: %v", err)
	}
	t.Cleanup(func() {
		for _, cleanup := range []struct {
			query string
			arg   any
		}{
			{`DELETE FROM oidc_auth_requests WHERE client_id=$1`, f.clientID},
			{`DELETE FROM oidc_refresh_tokens WHERE client_id=$1`, f.clientID},
			{`DELETE FROM oidc_clients WHERE client_id=$1`, f.clientID},
			{`DELETE FROM collaborators WHERE id=$1`, f.subject},
		} {
			if _, err := db.ExecContext(context.Background(), cleanup.query, cleanup.arg); err != nil {
				t.Errorf("clean synthetic fixture: %v", err)
			}
		}
	})

	// Bind a real ephemeral HTTP loopback listener, as a native client does.
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		select {
		case f.callbacks <- r.URL.Query():
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected duplicate callback", http.StatusConflict)
		}
	}))
	t.Cleanup(callback.Close)
	f.redirectURI = callback.URL + "/callback"
	registration, err := json.Marshal([]configuredPublicClient{{
		ClientID: f.clientID, RedirectURIs: []string{f.redirectURI},
		Scopes: []string{"openid", "email", "profile"}, GrantTypes: []string{"authorization_code"}, PKCERequired: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureConfiguredPublicClients(ctx, db, string(registration)); err != nil {
		t.Fatalf("register exact native callback: %v", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	f.issuer = server.URL + "/oidc"
	f.client = server.Client()
	f.client.Timeout = 10 * time.Second
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := MountOIDC(ctx, mux, db, f.issuer); err != nil {
		t.Fatalf("mount real OIDC provider: %v", err)
	}
	mux.HandleFunc("GET /api/v1/auth/third-party/start/google", func(w http.ResponseWriter, r *http.Request) {
		// Test-only authentication boundary. This is not a fake token endpoint:
		// issuance, PKCE, signatures, consumption and userinfo remain production code.
		id, err := uuid.Parse(r.URL.Query().Get("auth_request_id"))
		if err != nil {
			http.Error(w, "invalid test authentication request", http.StatusBadRequest)
			return
		}
		request, err := repository.GetOIDCAuthRequestByID(r.Context(), db, id)
		if err != nil || request.ClientID != f.clientID || request.RedirectURI != f.redirectURI || request.CollaboratorID != nil {
			http.Error(w, "unexpected test authentication request", http.StatusBadRequest)
			return
		}
		if err := repository.BindOIDCAuthRequestCollaborator(r.Context(), db, id, f.subject); err != nil {
			http.Error(w, "cannot bind synthetic identity", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, f.issuer+"/authorize/callback?id="+id.String(), http.StatusFound)
	})
	discovery := f.do(t, http.MethodGet, f.issuer+"/.well-known/openid-configuration", nil, "")
	var metadata struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		UserinfoEndpoint      string   `json:"userinfo_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	}
	decodeNativeProtocolJSON(t, discovery, http.StatusOK, &metadata)
	if metadata.Issuer != f.issuer || !strings.Contains(strings.Join(metadata.CodeChallengeMethods, ","), "S256") {
		t.Fatal("discovery must publish the exact issuer and S256 PKCE")
	}
	for _, endpoint := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.UserinfoEndpoint, metadata.JWKSURI} {
		if !strings.HasPrefix(endpoint, f.issuer+"/") {
			t.Fatal("discovery endpoint escaped issuer path")
		}
	}
	f.authorizationEndpoint, f.tokenEndpoint = metadata.AuthorizationEndpoint, metadata.TokenEndpoint
	f.userinfoEndpoint, f.jwksURI = metadata.UserinfoEndpoint, metadata.JWKSURI
	return f
}

func (f *nativeProtocolFixture) authorizeParams() (url.Values, string, string) {
	verifier := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	nonce := uuid.NewString()
	return url.Values{
		"client_id": {f.clientID}, "redirect_uri": {f.redirectURI}, "response_type": {"code"},
		"scope": {"openid email profile"}, "state": {uuid.NewString()}, "nonce": {nonce},
		"code_challenge": {oidc.NewSHACodeChallenge(verifier)}, "code_challenge_method": {"S256"},
	}, nonce, verifier
}

func (f *nativeProtocolFixture) authorize(t *testing.T, method string) (string, string, string) {
	t.Helper()
	params, nonce, verifier := f.authorizeParams()
	endpoint := f.authorizationEndpoint
	var body url.Values
	if method == http.MethodPost {
		body = params
	} else {
		endpoint += "?" + params.Encode()
	}
	response := f.do(t, method, endpoint, body, "")
	login := nativeProtocolRedirect(t, response)
	if !strings.HasPrefix(login, strings.TrimSuffix(f.issuer, "/oidc")+"/api/v1/auth/third-party/start/google?") {
		t.Fatal("authorize did not enter the controlled external-authentication boundary")
	}
	response = f.do(t, http.MethodGet, login, nil, "")
	resume := nativeProtocolRedirect(t, response)
	if !strings.HasPrefix(resume, f.issuer+"/authorize/callback?id=") {
		t.Fatal("controlled authentication did not resume the real provider callback")
	}
	response = f.do(t, http.MethodGet, resume, nil, "")
	loopback := nativeProtocolRedirect(t, response)
	parsed, err := url.Parse(loopback)
	if err != nil {
		t.Fatal(err)
	}
	base := *parsed
	base.RawQuery, base.Fragment = "", ""
	if base.String() != f.redirectURI {
		t.Fatal("provider returned a different native callback")
	}
	response = f.do(t, http.MethodGet, loopback, nil, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("loopback callback status %d", response.StatusCode)
	}
	select {
	case values := <-f.callbacks:
		if values.Get("error") != "" || values.Get("code") == "" || values.Get("state") != params.Get("state") {
			t.Fatal("native callback must carry a code, the original state, and no OAuth error")
		}
		return values.Get("code"), nonce, verifier
	default:
		t.Fatal("the real loopback listener did not receive the authorization callback")
		return "", "", ""
	}
}

type nativeProtocolTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

func (f *nativeProtocolFixture) exchange(t *testing.T, code, verifier, redirect string, status int, wantError string) nativeProtocolTokens {
	t.Helper()
	response := f.do(t, http.MethodPost, f.tokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {f.clientID}, "code": {code},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	}, "")
	var tokens nativeProtocolTokens
	decodeNativeProtocolJSON(t, response, status, &tokens)
	if tokens.Error != wantError {
		t.Fatalf("token error = %q, want %q", tokens.Error, wantError)
	}
	if wantError != "" {
		if tokens.AccessToken != "" || tokens.IDToken != "" || tokens.RefreshToken != "" {
			t.Fatal("a rejected exchange returned tokens")
		}
	} else if tokens.AccessToken == "" || tokens.IDToken == "" || !strings.EqualFold(tokens.TokenType, "Bearer") || tokens.ExpiresIn <= 0 {
		t.Fatal("successful exchange did not issue usable bearer and ID tokens")
	}
	return tokens
}

func (f *nativeProtocolFixture) verifyIdentity(t *testing.T, tokens nativeProtocolTokens, nonce string) {
	t.Helper()
	var keys jose.JSONWebKeySet
	decodeNativeProtocolJSON(t, f.do(t, http.MethodGet, f.jwksURI, nil, ""), http.StatusOK, &keys)
	idToken, err := jwt.ParseSigned(tokens.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(idToken.Headers) != 1 {
		t.Fatal("ID token must be an RS256 signed JWT")
	}
	matching := keys.Key(idToken.Headers[0].KeyID)
	if len(matching) != 1 {
		t.Fatal("ID token key is absent or ambiguous in the published JWKS")
	}
	var claims jwt.Claims
	var custom struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(matching[0].Key, &claims, &custom); err != nil {
		t.Fatalf("verify ID token signature: %v", err)
	}
	if err := claims.Validate(jwt.Expected{Issuer: f.issuer, Subject: f.subject.String(), AnyAudience: jwt.Audience{f.clientID}, Time: time.Now()}); err != nil {
		t.Fatalf("validate ID token claims: %v", err)
	}
	if custom.Nonce != nonce || claims.Expiry == nil || claims.Expiry.Time().Before(time.Now()) {
		t.Fatal("ID token must retain the nonce and a future expiry")
	}
	var userinfo struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
	}
	decodeNativeProtocolJSON(t, f.do(t, http.MethodGet, f.userinfoEndpoint, nil, tokens.AccessToken), http.StatusOK, &userinfo)
	if userinfo.Subject != f.subject.String() || userinfo.Email != f.email || userinfo.Name != "Native Protocol Test" {
		t.Fatal("userinfo did not return the authenticated synthetic identity")
	}
}

func (f *nativeProtocolFixture) authRequestCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.db.QueryRowContext(context.Background(), `SELECT count(*) FROM oidc_auth_requests WHERE client_id=$1`, f.clientID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (f *nativeProtocolFixture) do(t *testing.T, method, endpoint string, form url.Values, bearer string) *http.Response {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(context.Background(), method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatalf("protocol request failed: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func decodeNativeProtocolJSON(t *testing.T, response *http.Response, status int, destination any) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("protocol response status %d, want %d", response.StatusCode, status)
	}
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatalf("decode protocol response: %v", err)
	}
}

func nativeProtocolRedirect(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") == "" {
		t.Fatalf("protocol step did not redirect: status %d", response.StatusCode)
	}
	return response.Header.Get("Location")
}
