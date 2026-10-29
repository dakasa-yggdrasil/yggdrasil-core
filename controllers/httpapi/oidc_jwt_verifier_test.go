package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	jose "github.com/go-jose/go-jose/v4"
)

// testKey is a minimal verifyPublicKey backed by an in-memory RSA public key.
type testKey struct {
	id  string
	key any
}

func (k testKey) ID() string { return k.id }
func (k testKey) Key() any   { return k.key }

func mintJWT(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(b)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return s
}

func newTestVerifier(priv *rsa.PrivateKey, kid string, now time.Time) *opJWTVerifier {
	return &opJWTVerifier{
		keys: func(_ context.Context) ([]verifyPublicKey, error) {
			return []verifyPublicKey{testKey{id: kid, key: &priv.PublicKey}}, nil
		},
		issuer:    "https://ygg.test",
		audiences: map[string]struct{}{"tartaro-console": {}},
		now:       func() time.Time { return now },
		leeway:    0,
	}
}

func baseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://ygg.test",
		"aud": "tartaro-console",
		"sub": "11111111-1111-1111-1111-111111111111",
		"sid": "session-abc",
		"exp": float64(now.Add(10 * time.Minute).Unix()),
	}
}

func TestOPJWTVerifier_ValidToken_ReturnsClaims(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(priv, "kid-1", now)

	tok := mintJWT(t, priv, "kid-1", baseClaims(now))
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if claims["sub"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("sub: got %v", claims["sub"])
	}
}

func TestOPJWTVerifier_AudienceArray_Allowed(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(priv, "kid-1", now)

	c := baseClaims(now)
	c["aud"] = []any{"some-other-client", "tartaro-console"}
	tok := mintJWT(t, priv, "kid-1", c)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected array-aud token to pass, got %v", err)
	}
}

func TestOPJWTVerifier_Rejections(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(priv, "kid-1", now)

	cases := map[string]func() string{
		"expired": func() string {
			c := baseClaims(now)
			c["exp"] = float64(now.Add(-1 * time.Minute).Unix())
			return mintJWT(t, priv, "kid-1", c)
		},
		"wrong issuer": func() string {
			c := baseClaims(now)
			c["iss"] = "https://evil.test"
			return mintJWT(t, priv, "kid-1", c)
		},
		"audience not allowlisted": func() string {
			c := baseClaims(now)
			c["aud"] = "some-other-client"
			return mintJWT(t, priv, "kid-1", c)
		},
		"signed by foreign key": func() string {
			// Minted with a key NOT in the verifier's key set.
			return mintJWT(t, other, "kid-1", baseClaims(now))
		},
		"garbage token": func() string { return "not-a-jwt" },
	}

	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), mk()); err == nil {
				t.Errorf("expected rejection for %q, got nil error", name)
			}
		})
	}
}

func TestOPJWTVerifier_Unconfigured_AlwaysFails(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	// No audiences configured → JWT branch must be inert.
	v := &opJWTVerifier{
		keys:      func(_ context.Context) ([]verifyPublicKey, error) { return nil, nil },
		issuer:    "https://ygg.test",
		audiences: map[string]struct{}{},
		now:       func() time.Time { return now },
	}
	tok := mintJWT(t, priv, "kid-1", baseClaims(now))
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Error("unconfigured verifier must never authenticate")
	}
}

// newOPJWTVerifier returns nil (disabled) unless fully configured.
func TestNewOPJWTVerifier_DisabledWhenUnconfigured(t *testing.T) {
	if newOPJWTVerifier(nil, "", nil) != nil {
		t.Error("nil storage / empty issuer must yield a nil (disabled) verifier")
	}
}

func TestParseConsoleJWTAudiences(t *testing.T) {
	got := parseConsoleJWTAudiences(" a , ,b,  c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("idx %d: got %q want %q", i, got[i], want[i])
		}
	}
	if len(parseConsoleJWTAudiences("")) != 0 {
		t.Error("empty input must yield empty slice (keeps JWT branch disabled)")
	}
}

// Gate-level: a valid OP JWT authenticates the console gate and sets the same
// collaborator_id claim the session path would, WITHOUT touching the DB.
func TestRequireAuthenticatedConsoleAPIs_AcceptsOPJWT(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectCurrentPhoneProfile(mock, "11111111-1111-1111-1111-111111111111", false)
	// baseClaims carries no iat, so the token counts as issued at the epoch.
	expectGlobalRevocationRead(mock, "11111111-1111-1111-1111-111111111111", time.Unix(0, 0), false)
	s := &Server{db: db, consoleJWTVerifier: newTestVerifier(priv, "kid-1", now)}

	var gotCollab string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := claimsFromContext(r.Context())
		gotCollab, _ = claims["collaborator_id"].(string)
		w.WriteHeader(http.StatusOK)
	})
	h := s.requireAuthenticatedConsoleAPIs(next)

	tok := mintJWT(t, priv, "kid-1", baseClaims(now))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid OP JWT, got %d (%s)", w.Code, w.Body.String())
	}
	if gotCollab != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("collaborator_id should come from JWT sub, got %q", gotCollab)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Gate-level: with the verifier configured but NO credentials, the JWT branch
// is skipped and the request still 401s via the session path (before any DB
// access), proving the branch is additive and not a bypass.
func TestRequireAuthenticatedConsoleAPIs_NoCreds_Still401(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	s := &Server{consoleJWTVerifier: newTestVerifier(priv, "kid-1", now)}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := s.requireAuthenticatedConsoleAPIs(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no credentials, got %d", w.Code)
	}
}

// expectCollaboratorStatusRow expects the single collaborator read of a human
// JWT branch (allowSignedInHumanID) and answers a row in the given status with
// no pending phone profile.
func expectCollaboratorStatusRow(mock sqlmock.Sqlmock, id, status string) {
	mock.ExpectQuery(`(?i)FROM\s+public\.collaborators`).WithArgs(id).
		WillReturnRows(sqlmock.NewRows(collaboratorColumns()).AddRow(id, "status-ci", status, "Status CI", "person@example.test", nil, nil,
			[]byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), []byte("{}"), 0, time.Now(), time.Now()))
}

// expectGlobalRevocationRead expects the session_revocation read of a human
// JWT branch (allowSignedInHumanID) for the subject and the token's iat, and
// answers whether a global revocation at or after that iat exists.
func expectGlobalRevocationRead(mock sqlmock.Sqlmock, id string, issuedAt time.Time, revoked bool) {
	mock.ExpectQuery(`(?i)FROM\s+session_revocation`).WithArgs(id, sqlmock.AnyArg(), issuedAt).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(revoked))
}

// Gate-level: a termination writes a global session_revocation row, and a
// reactivation must not revive an OP JWT minted before it. A token whose iat
// is at or before such a row is refused with 401 before any handler runs,
// although the collaborator is active again (ADR-0087).
func TestRequireAuthenticatedConsoleAPIs_RefusesOPJWTIssuedBeforeAGlobalRevocation(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	claims := baseClaims(now)
	claims["iat"] = float64(now.Add(-5 * time.Minute).Unix())
	tok := mintJWT(t, priv, "kid-1", claims)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	expectCollaboratorStatusRow(mock, "11111111-1111-1111-1111-111111111111", "active")
	expectGlobalRevocationRead(mock, "11111111-1111-1111-1111-111111111111", now.Add(-5*time.Minute), true)
	s := &Server{db: db, consoleJWTVerifier: newTestVerifier(priv, "kid-1", now)}

	called := false
	h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized || called {
		t.Fatalf("got %d (handler called=%v), want 401 before any handler", w.Code, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestJWTIssuedAtReadsNumericClaims(t *testing.T) {
	for name, tc := range map[string]struct {
		claims map[string]any
		want   int64
	}{
		"float":   {map[string]any{"iat": float64(1_700_000_123)}, 1_700_000_123},
		"number":  {map[string]any{"iat": json.Number("1700000124")}, 1_700_000_124},
		"int64":   {map[string]any{"iat": int64(1_700_000_125)}, 1_700_000_125},
		"missing": {map[string]any{}, 0},
		"string":  {map[string]any{"iat": "1700000126"}, 0},
	} {
		if got := jwtIssuedAt(tc.claims).Unix(); got != tc.want {
			t.Errorf("%s: got %d, want %d", name, got, tc.want)
		}
	}
}

// Gate-level: an OP JWT outlives a status change by up to its lifetime. Its
// subject is re-read on every request, and a collaborator who cannot sign in
// is refused with 401 before any handler runs (ADR-0087). The collaborator
// read is the same single statement the phone profile rule already used.
func TestRequireAuthenticatedConsoleAPIs_RefusesOPJWTOfCollaboratorWhoCannotSignIn(t *testing.T) {
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", "")
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	tok := mintJWT(t, priv, "kid-1", baseClaims(now))
	for _, status := range []string{"pending_start", "on_leave", "suspended", "offboarded"} {
		t.Run(status, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			expectCollaboratorStatusRow(mock, "11111111-1111-1111-1111-111111111111", status)
			s := &Server{db: db, consoleJWTVerifier: newTestVerifier(priv, "kid-1", now)}

			called := false
			h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized || called {
				t.Fatalf("status %q: got %d (handler called=%v), want 401 before any handler", status, w.Code, called)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
