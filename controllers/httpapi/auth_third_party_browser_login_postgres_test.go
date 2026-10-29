package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func thirdPartyLoginHTTPPostgres(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("DB_URL") == "" && os.Getenv("REQUIRE_THIRD_PARTY_LOGIN_POSTGRES") == "true" {
		t.Fatal("DB_URL is required by the third-party login PostgreSQL gate")
	}
	return directoryHTTPPostgres(t)
}

// fakeThirdPartyIdP is an OAuth provider that exchanges exactly one
// authorization code, for exactly one client, into one access token, and
// answers userinfo only for that token.
type fakeThirdPartyIdP struct {
	server      *httptest.Server
	clientID    string
	code        string
	accessToken string
}

func newFakeThirdPartyIdP(t *testing.T, clientID, clientSecret string, claims map[string]any) *fakeThirdPartyIdP {
	t.Helper()
	idp := &fakeThirdPartyIdP{
		clientID:    clientID,
		code:        "ci-code-" + uuid.NewString(),
		accessToken: "ci-access-" + uuid.NewString(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") != idp.code ||
			r.PostForm.Get("client_id") != clientID || r.PostForm.Get("client_secret") != clientSecret {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": idp.accessToken, "token_type": "Bearer"})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+idp.accessToken {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// ADR-0088 against the migrated schema: the body-asserted identity exchange
// creates no identity and no session for an active collaborator whose e-mail
// it names, while the browser login (start, provider code exchange,
// userinfo, callback) still links that collaborator by e-mail on the first
// login, signs in again through the linked identity, and refuses a forged
// state.
func TestThirdPartyBrowserLoginHTTPPostgres(t *testing.T) {
	db := thirdPartyLoginHTTPPostgres(t)
	ctx := context.Background()
	t.Setenv(contactphone.EnrollmentPolicyEnv, "false")

	person := directoryHTTPPerson(t, db, false)
	if _, err := db.Exec(`UPDATE public.auth_identities SET mfa_enrolled_at=NOW() WHERE collaborator_id=$1`, person.ID); err != nil {
		t.Fatal("MFA fixture failed")
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	secretNamespace := "ci-third-party-login"
	secretName := "client-" + suffix
	clientSecret := "ci-secret-" + uuid.NewString()
	if _, err := repository.UpsertManagedSecret(ctx, db, model.UpsertManagedSecretRequest{
		Namespace: secretNamespace,
		Name:      secretName,
		Data:      map[string]string{"client_secret": clientSecret},
	}); err != nil {
		t.Fatalf("client secret fixture failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.managed_secrets WHERE namespace=$1 AND name=$2`, secretNamespace, secretName)
	})

	nanos := uint64(time.Now().UnixNano())
	subject := fmt.Sprintf("1%020d", nanos)
	forgedSubject := fmt.Sprintf("2%020d", nanos)
	idp := newFakeThirdPartyIdP(t, "ci-client-"+suffix, clientSecret, map[string]any{
		"sub":            subject,
		"email":          person.PrimaryEmail,
		"email_verified": true,
		"name":           "Third Party Login CI",
	})
	provider, err := repository.UpsertThirdPartyAuthProvider(ctx, db, model.UpsertThirdPartyAuthProviderRequest{
		Name:            "ci-google-" + suffix,
		Type:            "oidc",
		Status:          "active",
		DisplayName:     "Google CI",
		AuthorizeURL:    idp.server.URL + "/authorize",
		TokenURL:        idp.server.URL + "/token",
		UserInfoURL:     idp.server.URL + "/userinfo",
		ClientID:        idp.clientID,
		ClientSecretRef: "secret://" + secretNamespace + "/" + secretName + "#client_secret",
		AutoLinkByEmail: true,
	})
	if err != nil {
		t.Fatalf("provider fixture failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.collaborator_third_party_identities WHERE provider=$1`, provider.Name)
		_, _ = db.Exec(`DELETE FROM public.auth_third_party_providers WHERE name=$1`, provider.Name)
	})

	h := directoryHTTPHandler(t, db)
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	cookieNamed := func(w *httptest.ResponseRecorder, name string) *http.Cookie {
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name == name {
				return cookie
			}
		}
		return nil
	}
	liveSessions := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM public.auth_sessions WHERE collaborator_id=$1 AND revoked_at IS NULL`, person.ID).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		return n
	}
	identityOwners := func(t *testing.T, sub string) []uuid.UUID {
		t.Helper()
		rows, err := db.Query(`SELECT collaborator_id FROM public.collaborator_third_party_identities WHERE provider=$1 AND subject=$2`, provider.Name, sub)
		if err != nil {
			t.Fatalf("read identities: %v", err)
		}
		defer rows.Close()
		var owners []uuid.UUID
		for rows.Next() {
			var owner uuid.UUID
			if err := rows.Scan(&owner); err != nil {
				t.Fatalf("scan identity: %v", err)
			}
			owners = append(owners, owner)
		}
		return owners
	}
	start := func(t *testing.T) (string, *http.Cookie) {
		t.Helper()
		w := serve(httptest.NewRequest(http.MethodGet, "/api/v1/auth/third-party/start/"+provider.Name+"?redirect_to=/console/after-login", nil))
		if w.Code != http.StatusFound {
			t.Fatalf("start: status=%d body=%s", w.Code, w.Body.String())
		}
		location, err := url.Parse(w.Header().Get("Location"))
		if err != nil || !strings.HasPrefix(location.String(), idp.server.URL+"/authorize?") {
			t.Fatalf("start redirected to %q, want the provider authorize URL", w.Header().Get("Location"))
		}
		if location.Query().Get("client_id") != idp.clientID || location.Query().Get("response_type") != "code" {
			t.Fatalf("start authorize query = %v", location.Query())
		}
		nonce := location.Query().Get("state")
		state := cookieNamed(w, authThirdPartyStateCookieName())
		if nonce == "" || state == nil || state.Value == "" {
			t.Fatalf("start did not issue a state nonce and its signed cookie")
		}
		return nonce, state
	}
	callback := func(nonce, code string, state *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/third-party/callback/"+provider.Name+
			"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(nonce), nil)
		if state != nil {
			r.AddCookie(&http.Cookie{Name: state.Name, Value: state.Value})
		}
		return serve(r)
	}
	requireSignedIn := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/console/after-login" {
			t.Fatalf("callback: status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
		}
		session := cookieNamed(w, authSessionCookieName())
		if session == nil || session.Value == "" {
			t.Fatal("callback did not set a session cookie")
		}
		if state := cookieNamed(w, authThirdPartyStateCookieName()); state == nil || state.MaxAge >= 0 {
			t.Fatal("callback did not clear the state cookie")
		}
		r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
		r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: session.Value})
		sw := serve(r)
		var envelope model.AuthSessionEnvelope
		if sw.Code != http.StatusOK || json.Unmarshal(sw.Body.Bytes(), &envelope) != nil || !envelope.Authenticated ||
			envelope.Collaborator == nil || envelope.Collaborator.ID != person.ID {
			t.Fatalf("session from the callback: status=%d body=%s", sw.Code, sw.Body.String())
		}
	}

	t.Run("identity_exchange_route_is_gone", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"provider":           provider.Name,
			"subject":            forgedSubject,
			"email":              person.PrimaryEmail,
			"auto_link_by_email": true,
		})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/third-party/login", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		w := serve(r)
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status=%d body=%s, want 404 or 405", w.Code, w.Body.String())
		}
		if cookie := cookieNamed(w, authSessionCookieName()); cookie != nil {
			t.Fatal("removed route set a session cookie")
		}
		if owners := identityOwners(t, forgedSubject); len(owners) != 0 {
			t.Fatalf("removed route linked the forged subject to %v", owners)
		}
		if n := liveSessions(t); n != 0 {
			t.Fatalf("removed route opened %d sessions", n)
		}
	})

	t.Run("forged_state_is_refused", func(t *testing.T) {
		nonce, state := start(t)
		w := callback("forged-"+nonce, idp.code, state)
		if w.Code == http.StatusFound {
			t.Fatalf("forged state redirected to %q", w.Header().Get("Location"))
		}
		if cookie := cookieNamed(w, authSessionCookieName()); cookie != nil && cookie.Value != "" {
			t.Fatal("forged state set a session cookie")
		}
		if owners := identityOwners(t, subject); len(owners) != 0 {
			t.Fatalf("forged state linked the subject to %v", owners)
		}
		if n := liveSessions(t); n != 0 {
			t.Fatalf("forged state opened %d sessions", n)
		}
	})

	t.Run("browser_callback_links_by_email_and_signs_in", func(t *testing.T) {
		nonce, state := start(t)
		requireSignedIn(t, callback(nonce, idp.code, state))
		owners := identityOwners(t, subject)
		if len(owners) != 1 || owners[0] != person.ID {
			t.Fatalf("callback linked the subject to %v, want [%s]", owners, person.ID)
		}
		if n := liveSessions(t); n != 1 {
			t.Fatalf("callback opened %d sessions, want 1", n)
		}
		var flow string
		if err := db.QueryRow(`SELECT COALESCE(metadata->>'auth_flow','') FROM public.auth_sessions WHERE collaborator_id=$1 AND revoked_at IS NULL`, person.ID).Scan(&flow); err != nil || flow != "browser_callback" {
			t.Fatalf("callback session auth_flow=%q err=%v", flow, err)
		}
	})

	t.Run("returning_identity_signs_in_again", func(t *testing.T) {
		nonce, state := start(t)
		requireSignedIn(t, callback(nonce, idp.code, state))
		if owners := identityOwners(t, subject); len(owners) != 1 || owners[0] != person.ID {
			t.Fatalf("returning login changed the identity owners to %v", owners)
		}
		if n := liveSessions(t); n != 2 {
			t.Fatalf("returning login left %d live sessions, want 2", n)
		}
	})
}
