package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

const nativeTestRedirect = "http://127.0.0.1:47819/callback"

func nativeTestClient() model.OIDCClient {
	return model.OIDCClient{
		ClientID: "native-cli", RedirectURIs: []string{nativeTestRedirect},
		Scopes: []string{"openid"}, GrantTypes: []string{"authorization_code"}, PKCERequired: true,
	}
}

func TestNativeLoopbackClientClassification(t *testing.T) {
	tests := []struct {
		name      string
		redirects []string
		logout    []string
		secret    string
		noPKCE    bool
		want      op.ApplicationType
	}{
		{name: "IPv4", redirects: []string{nativeTestRedirect}, want: op.ApplicationTypeNative},
		{name: "localhost", redirects: []string{"http://localhost:47819/callback"}, want: op.ApplicationTypeNative},
		{name: "IPv6", redirects: []string{"http://[::1]:47819/callback"}, want: op.ApplicationTypeNative},
		{name: "all registered loopbacks", redirects: []string{nativeTestRedirect, "http://localhost:47820/other?mode=cli", "http://[::1]/callback"}, want: op.ApplicationTypeNative},
		{name: "non loopback HTTPS logout", redirects: []string{nativeTestRedirect}, logout: []string{"https://app.example/logout"}, want: op.ApplicationTypeNative},
		{name: "confidential loopback", redirects: []string{nativeTestRedirect}, secret: "test-secret-hash", want: op.ApplicationTypeWeb},
		{name: "confidential web", redirects: []string{"https://app.example/callback"}, secret: "test-secret-hash", want: op.ApplicationTypeWeb},
		{name: "PKCE disabled", redirects: []string{nativeTestRedirect}, noPKCE: true, want: op.ApplicationTypeUserAgent},
		{name: "empty allowlist", want: op.ApplicationTypeUserAgent},
		{name: "empty URI", redirects: []string{""}, want: op.ApplicationTypeUserAgent},
		{name: "public HTTPS", redirects: []string{"https://app.example/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "HTTPS loopback", redirects: []string{"https://127.0.0.1:47819/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "mixed native and web", redirects: []string{nativeTestRedirect, "https://app.example/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "non loopback HTTP", redirects: []string{"http://192.0.2.1/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "localhost suffix", redirects: []string{"http://localhost.attacker.example/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "relative URI", redirects: []string{"/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "custom scheme", redirects: []string{"native-app://callback"}, want: op.ApplicationTypeUserAgent},
		{name: "userinfo", redirects: []string{"http://user@127.0.0.1:47819/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "fragment", redirects: []string{nativeTestRedirect + "#fragment"}, want: op.ApplicationTypeUserAgent},
		{name: "bad escape", redirects: []string{nativeTestRedirect + "%zz"}, want: op.ApplicationTypeUserAgent},
		{name: "invalid port", redirects: []string{"http://127.0.0.1:invalid/callback"}, want: op.ApplicationTypeUserAgent},
		{name: "HTTP loopback logout", redirects: []string{nativeTestRedirect}, logout: []string{"http://localhost:47819/logout"}, want: op.ApplicationTypeUserAgent},
		{name: "HTTPS loopback logout", redirects: []string{nativeTestRedirect}, logout: []string{"https://[::1]:47819/logout"}, want: op.ApplicationTypeUserAgent},
		{name: "mixed logout allowlist", redirects: []string{nativeTestRedirect}, logout: []string{"https://app.example/logout", "http://127.0.0.1/logout"}, want: op.ApplicationTypeUserAgent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := nativeTestClient()
			c.RedirectURIs, c.PostLogoutRedirectURIs = tc.redirects, tc.logout
			c.ClientSecretHash, c.PKCERequired = tc.secret, !tc.noPKCE
			client := newClientView(c, "https://issuer.example/oidc")
			if got := client.ApplicationType(); got != tc.want {
				t.Fatalf("ApplicationType() = %v, want %v", got, tc.want)
			}
			if got := isNativeLoopbackClient(c); got != (tc.want == op.ApplicationTypeNative) {
				t.Errorf("isNativeLoopbackClient() = %v, type = %v", got, tc.want)
			}
			wantAuth := oidc.AuthMethodNone
			if tc.secret != "" {
				wantAuth = oidc.AuthMethodBasic
			}
			if client.AuthMethod() != wantAuth || client.DevMode() {
				t.Fatal("classification must preserve authentication method and keep development mode disabled")
			}
		})
	}
}

func nativeTestParams() url.Values {
	return url.Values{
		"client_id": {"native-cli"}, "redirect_uri": {nativeTestRedirect},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"state-for-test"}, "nonce": {"nonce-for-test"},
		"code_challenge":        {oidc.NewSHACodeChallenge("test-code-verifier-with-at-least-forty-three-characters")},
		"code_challenge_method": {"S256"},
	}
}

func nativeTestRequest(method, path string, params url.Values) *http.Request {
	if method == http.MethodPost {
		r := httptest.NewRequest(method, path, strings.NewReader(params.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	return httptest.NewRequest(method, path+"?"+params.Encode(), nil)
}

func expectNativeClientLookup(t *testing.T, mock sqlmock.Sqlmock, c model.OIDCClient) {
	t.Helper()
	redirects, err := pq.Array(c.RedirectURIs).Value()
	if err != nil {
		t.Fatal(err)
	}
	logout, err := pq.Array(c.PostLogoutRedirectURIs).Value()
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT client_id, client_secret_hash").WithArgs(c.ClientID).
		WillReturnRows(sqlmock.NewRows([]string{
			"client_id", "client_secret_hash", "redirect_uris", "post_logout_redirect_uris",
			"scopes", "grant_types", "pkce_required", "backchannel_logout_uri",
			"access_token_lifetime_seconds", "created_at",
		}).AddRow(c.ClientID, c.ClientSecretHash, redirects, logout, "{openid}", "{authorization_code}", c.PKCERequired, "", nil, time.Now().UTC()))
}

// Exercise MountOIDC itself: omitting the interceptor or installing it outside
// StripPrefix must fail these tests, even if the guard passes in isolation.
func mountNativeTestProvider(t *testing.T, issuer string) (http.Handler, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectQuery("SELECT id, algorithm, private_pem, public_jwk, created_at, active_at, retire_at").
		WithArgs(SigningAlgorithm).
		WillReturnRows(sqlmock.NewRows([]string{"id", "algorithm", "private_pem", "public_jwk", "created_at", "active_at", "retire_at"}).
			AddRow(uuid.New(), SigningAlgorithm, "test-only-crypto-key-material", []byte("{}"), time.Now().UTC(), time.Now().UTC(), nil))
	mux := http.NewServeMux()
	if err := MountOIDC(context.Background(), mux, db, issuer); err != nil {
		t.Fatalf("mount provider: %v", err)
	}
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})
	return mux, mock
}

func TestNativeLoopbackMountedAuthorizeAcceptsExactGETAndPOST(t *testing.T) {
	for _, issuer := range []string{"https://issuer.example", "https://issuer.example/oidc", "https://issuer.example/auth/oidc"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(issuer+"/"+method, func(t *testing.T) {
				provider, mock := mountNativeTestProvider(t, issuer)
				c := nativeTestClient()
				// Guard, upstream validation, and the storage recheck each load
				// the current registration before the single auth request insert.
				for range 3 {
					expectNativeClientLookup(t, mock, c)
				}
				params := nativeTestParams()
				id := uuid.New()
				mock.ExpectQuery("INSERT INTO oidc_auth_requests").
					WithArgs(c.ClientID, nil, nativeTestRedirect, pq.Array([]string{"openid"}), params.Get("code_challenge"), "S256", params.Get("state"), params.Get("nonce"), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
				u, err := url.Parse(issuer)
				if err != nil {
					t.Fatal(err)
				}
				prefix := u.Path
				if prefix == "" {
					prefix = "/oidc"
				}
				w := httptest.NewRecorder()
				provider.ServeHTTP(w, nativeTestRequest(method, prefix+"/authorize", params))
				wantLocation := "https://issuer.example/api/v1/auth/third-party/start/google?auth_request_id=" + id.String()
				if w.Code != http.StatusFound || w.Header().Get("Location") != wantLocation {
					t.Fatalf("authorize = %d, Location %q, body %q; want login redirect %q", w.Code, w.Header().Get("Location"), w.Body.String(), wantLocation)
				}
			})
		}
	}
}

func TestNativeLoopbackMountedAuthorizeRejectsUnregisteredURIWithoutRedirect(t *testing.T) {
	attacks := map[string]string{
		"port":                "http://127.0.0.1:47820/callback",
		"localhost alias":     "http://localhost:47819/callback",
		"IPv6 alias":          "http://[::1]:47819/callback",
		"other loopback":      "http://127.0.0.2:47819/callback",
		"remote host":         "http://attacker.example:47819/callback",
		"scheme":              "https://127.0.0.1:47819/callback",
		"path":                nativeTestRedirect + "/extra",
		"query":               nativeTestRedirect + "?next=https://attacker.example",
		"fragment":            nativeTestRedirect + "#fragment",
		"userinfo":            "http://attacker@127.0.0.1:47819/callback",
		"escaped path":        "http://127.0.0.1:47819/%63allback",
		"double encoded path": "http://127.0.0.1:47819/%2563allback",
		"double encoded URI":  url.QueryEscape(nativeTestRedirect),
		"relative":            "/callback",
	}
	for _, prefix := range []string{"", "/oidc", "/auth/oidc"} {
		for name, uri := range attacks {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				t.Run(prefix+"/"+name+"/"+method, func(t *testing.T) {
					provider, mock := mountNativeTestProvider(t, "https://issuer.example"+prefix)
					expectNativeClientLookup(t, mock, nativeTestClient())
					params := nativeTestParams()
					params.Set("redirect_uri", uri)
					// An upstream response-type error must not redirect to the
					// unregistered callback before CreateAuthRequest is reached.
					params.Set("response_type", "unsupported")
					path := prefix
					if path == "" {
						path = "/oidc"
					}
					w := httptest.NewRecorder()
					provider.ServeHTTP(w, nativeTestRequest(method, path+"/authorize", params))
					if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
						t.Fatalf("unsafe authorize response: status %d, Location %q, body %q", w.Code, w.Header().Get("Location"), w.Body.String())
					}
				})
			}
		}
	}
}

func TestNativeLoopbackMountedAuthorizeRejectsInvalidParameters(t *testing.T) {
	tests := []struct {
		name   string
		modify func(url.Values)
	}{
		{"missing client", func(v url.Values) { v.Del("client_id") }},
		{"empty client", func(v url.Values) { v.Set("client_id", "") }},
		{"duplicate client", func(v url.Values) { v.Add("client_id", "native-cli") }},
		{"missing redirect", func(v url.Values) { v.Del("redirect_uri") }},
		{"empty redirect", func(v url.Values) { v.Set("redirect_uri", "") }},
		{"duplicate redirect", func(v url.Values) { v.Add("redirect_uri", nativeTestRedirect) }},
		{"conflicting redirect", func(v url.Values) { v.Add("redirect_uri", "https://attacker.example/callback") }},
	}
	for _, tc := range tests {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				provider, _ := mountNativeTestProvider(t, "https://issuer.example/oidc")
				params := nativeTestParams()
				tc.modify(params)
				w := httptest.NewRecorder()
				provider.ServeHTTP(w, nativeTestRequest(method, "/oidc/authorize", params))
				if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
					t.Fatalf("invalid parameters: status %d, Location %q", w.Code, w.Header().Get("Location"))
				}
			})
		}
	}
	for _, name := range []string{"malformed query", "malformed body", "query body duplicate"} {
		t.Run(name, func(t *testing.T) {
			provider, _ := mountNativeTestProvider(t, "https://issuer.example/oidc")
			r := nativeTestRequest(http.MethodPost, "/oidc/authorize", nativeTestParams())
			switch name {
			case "malformed query":
				r = httptest.NewRequest(http.MethodGet, "/oidc/authorize?client_id=%zz", nil)
			case "malformed body":
				r = httptest.NewRequest(http.MethodPost, "/oidc/authorize", strings.NewReader("client_id=%zz"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			case "query body duplicate":
				r.URL.RawQuery = "redirect_uri=" + url.QueryEscape(nativeTestRedirect)
			}
			w := httptest.NewRecorder()
			provider.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
				t.Fatalf("invalid form: status %d, Location %q", w.Code, w.Header().Get("Location"))
			}
		})
	}
}

type nativeLookupStorage struct {
	op.Storage
	client op.Client
	err    error
	calls  int
}

func (s *nativeLookupStorage) GetClientByClientID(context.Context, string) (op.Client, error) {
	s.calls++
	return s.client, s.err
}

func TestNativeLoopbackGuardFailsClosedOnLookup(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{name: "nil client"}, {name: "lookup unavailable", err: errors.New("lookup unavailable")}} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &nativeLookupStorage{err: tc.err}
			called := false
			handler := exactAuthorizeRedirects(storage)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, nativeTestRequest(http.MethodGet, "/authorize", nativeTestParams()))
			if called || storage.calls != 1 || w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
				t.Fatalf("lookup failure escaped guard: downstream=%v calls=%d status=%d Location=%q", called, storage.calls, w.Code, w.Header().Get("Location"))
			}
		})
	}
}

// The upstream schema decoder accepts differently cased parameter aliases.
// Reject them before decoding can overwrite the values checked by the guard.
func TestNativeLoopbackGuardRejectsParameterAliasesBeforeLookup(t *testing.T) {
	for _, alias := range []string{"REDIRECT_URI", "Redirect_Uri", "CLIENT_ID", "Client_Id"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(alias+"/"+method, func(t *testing.T) {
				storage := &nativeLookupStorage{client: newClientView(nativeTestClient(), "https://issuer.example/oidc")}
				called := false
				handler := exactAuthorizeRedirects(storage)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
				params := nativeTestParams()
				params.Set("response_type", "unsupported")
				value := "other-client"
				if strings.EqualFold(alias, "redirect_uri") {
					value = "http://127.0.0.1:47820/callback"
				}
				var r *http.Request
				if method == http.MethodPost {
					// The canonical values are in the body and the alias in
					// the query; ParseForm merges both input sources.
					r = nativeTestRequest(method, "/authorize", params)
					r.URL.RawQuery = url.Values{alias: {value}}.Encode()
				} else {
					params.Set(alias, value)
					r = nativeTestRequest(method, "/authorize", params)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if called || storage.calls != 0 || w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
					t.Fatalf("parameter alias escaped guard: downstream=%v lookups=%d status=%d Location=%q", called, storage.calls, w.Code, w.Header().Get("Location"))
				}
			})
		}
	}
}

func TestNativeLoopbackGuardLeavesOtherEndpointsUntouched(t *testing.T) {
	for _, path := range []string{"/token", "/userinfo", "/keys", "/.well-known/openid-configuration", "/end_session", "/authorize/callback"} {
		t.Run(path, func(t *testing.T) {
			storage := &nativeLookupStorage{}
			called := false
			handler := exactAuthorizeRedirects(storage)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.URL.Path != path || r.Form != nil {
					t.Error("unrelated request was modified")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path+"?client_id=%zz", strings.NewReader("unrelated body")))
			if !called || storage.calls != 0 || w.Code != http.StatusNoContent {
				t.Fatalf("passthrough failed: downstream=%v lookups=%d status=%d", called, storage.calls, w.Code)
			}
		})
	}
}

func TestNativeLoopbackStorageChecksExactRedirectBeforePKCEAndInsert(t *testing.T) {
	for _, challenge := range []string{"", nativeTestParams().Get("code_challenge")} {
		t.Run("challenge="+challenge, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			expectNativeClientLookup(t, mock, nativeTestClient())
			request, err := NewStorage(db, "https://issuer.example/oidc").CreateAuthRequest(context.Background(), &oidc.AuthRequest{
				ClientID: "native-cli", RedirectURI: "http://127.0.0.1:47820/callback", Scopes: []string{"openid"},
				ResponseType: oidc.ResponseTypeCode, CodeChallenge: challenge, CodeChallengeMethod: oidc.CodeChallengeMethodS256,
			}, "")
			var oidcErr *oidc.Error
			if request != nil || !errors.As(err, &oidcErr) || !oidcErr.IsRedirectDisabled() || oidcErr.ErrorType != oidc.InvalidRequest {
				t.Fatalf("want redirect-disabled invalid_request before PKCE/INSERT, got request=%v err=%v", request, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeLoopbackStorageStillRequiresS256PKCE(t *testing.T) {
	tests := []struct {
		name, challenge string
		method          oidc.CodeChallengeMethod
		want            string
	}{
		{name: "missing", want: "code_challenge is required"},
		{name: "plain", challenge: nativeTestParams().Get("code_challenge"), method: oidc.CodeChallengeMethodPlain, want: "code_challenge_method must be S256"},
		{name: "malformed S256", challenge: "short", method: oidc.CodeChallengeMethodS256, want: "code_challenge"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			expectNativeClientLookup(t, mock, nativeTestClient())
			request, err := NewStorage(db, "https://issuer.example/oidc").CreateAuthRequest(context.Background(), &oidc.AuthRequest{
				ClientID: "native-cli", RedirectURI: nativeTestRedirect, Scopes: []string{"openid"},
				ResponseType: oidc.ResponseTypeCode, CodeChallenge: tc.challenge, CodeChallengeMethod: tc.method,
			}, "")
			var oidcErr *oidc.Error
			if request != nil || !errors.As(err, &oidcErr) || oidcErr.ErrorType != oidc.InvalidRequest || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want PKCE rejection %q before INSERT, got request=%v err=%v", tc.want, request, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
