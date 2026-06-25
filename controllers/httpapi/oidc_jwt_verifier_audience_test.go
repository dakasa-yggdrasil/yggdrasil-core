package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// testSigner builds a one-key keySource + a signer so we can mint real RS256
// JWTs the verifier will accept. Mirrors how the OP signs in production but
// stays self-contained (no DB).
func testSigner(t *testing.T) (keySource, func(claims map[string]any) string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	const kid = "test-kid-1"
	ks := func(context.Context) ([]verifyPublicKey, error) {
		return []verifyPublicKey{stubKey{id: kid, key: priv.Public()}}, nil
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	mint := func(claims map[string]any) string {
		raw, _ := json.Marshal(claims)
		jws, err := signer.Sign(raw)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		s, err := jws.CompactSerialize()
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}
		return s
	}
	return ks, mint
}

type stubKey struct {
	id  string
	key any
}

func (s stubKey) ID() string { return s.id }
func (s stubKey) Key() any   { return s.key }

func newTestSurfaceVerifier(ks keySource) *opJWTVerifier {
	return &opJWTVerifier{
		keys:   ks,
		issuer: "https://yggdrasil.dakasa.me/oidc",
		now:    time.Now,
		leeway: 30 * time.Second,
	}
}

func TestVerifyForAudience_AcceptsMatchingAudience(t *testing.T) {
	ks, mint := testSigner(t)
	v := newTestSurfaceVerifier(ks)
	token := mint(map[string]any{
		"iss": "https://yggdrasil.dakasa.me/oidc",
		"aud": "dakasa-ai",
		"sub": "collab-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	claims, err := v.VerifyForAudience(context.Background(), token, "dakasa-ai")
	if err != nil {
		t.Fatalf("expected accept, got err: %v", err)
	}
	if claims["sub"] != "collab-1" {
		t.Errorf("sub: got %v, want collab-1", claims["sub"])
	}
}

func TestVerifyForAudience_RejectsWrongAudience(t *testing.T) {
	ks, mint := testSigner(t)
	v := newTestSurfaceVerifier(ks)
	token := mint(map[string]any{
		"iss": "https://yggdrasil.dakasa.me/oidc",
		"aud": "some-other-client",
		"sub": "collab-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	if _, err := v.VerifyForAudience(context.Background(), token, "dakasa-ai"); err == nil {
		t.Fatal("expected reject for audience mismatch, got nil error")
	}
}

func TestVerifyForAudience_RejectsExpired(t *testing.T) {
	ks, mint := testSigner(t)
	v := newTestSurfaceVerifier(ks)
	token := mint(map[string]any{
		"iss": "https://yggdrasil.dakasa.me/oidc",
		"aud": "dakasa-ai",
		"sub": "collab-1",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	})
	if _, err := v.VerifyForAudience(context.Background(), token, "dakasa-ai"); err == nil {
		t.Fatal("expected reject for expired token, got nil error")
	}
}

func TestVerifyForAudience_RejectsBlankExpectedAudience(t *testing.T) {
	ks, mint := testSigner(t)
	v := newTestSurfaceVerifier(ks)
	token := mint(map[string]any{
		"iss": "https://yggdrasil.dakasa.me/oidc",
		"aud": "dakasa-ai",
		"sub": "collab-1",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	if _, err := v.VerifyForAudience(context.Background(), token, ""); err == nil {
		t.Fatal("expected reject when expected audience is blank, got nil error")
	}
}

func TestVerifyForAudience_NilVerifier(t *testing.T) {
	var v *opJWTVerifier
	if _, err := v.VerifyForAudience(context.Background(), "x", "dakasa-ai"); err == nil {
		t.Fatal("nil verifier must fail closed")
	}
}
