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
	s := &Server{consoleJWTVerifier: newTestVerifier(priv, "kid-1", now)}

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
