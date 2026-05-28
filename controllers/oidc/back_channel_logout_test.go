package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TestBuildLogoutTokenShape asserts the §2.4 RFC 8417 token claim set:
// iss / sub / aud / iat / jti / events / sid populated correctly and the
// JWT verifies under the same signing key. No DB required — exercises the
// pure JWT path so signing failures surface in unit tests.
func TestBuildLogoutTokenShape(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:   priv,
			KeyID: "test-kid",
			Use:   "sig",
		},
	}, (&jose.SignerOptions{}).WithType("logout+jwt"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	d := &BackchannelDispatcher{
		IssuerURL: "https://yggdrasil.test",
		Now:       func() time.Time { return now },
	}

	collabID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	sid := uuid.MustParse("00000000-0000-0000-0000-0000000000aa")
	link := model.OIDCSessionLink{
		ID:             uuid.New(),
		CollaboratorID: collabID,
		ClientID:       "test-client",
		SID:            sid,
	}

	tok, err := d.buildLogoutToken(signer, link, "test-client")
	if err != nil {
		t.Fatalf("buildLogoutToken: %v", err)
	}

	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}

	var claims map[string]interface{}
	if err := parsed.Claims(priv.Public(), &claims); err != nil {
		t.Fatalf("verify claims: %v", err)
	}

	if got, want := claims["iss"], "https://yggdrasil.test"; got != want {
		t.Errorf("iss: got %v want %v", got, want)
	}
	if got, want := claims["sub"], collabID.String(); got != want {
		t.Errorf("sub: got %v want %v", got, want)
	}
	if got, want := claims["aud"], "test-client"; got != want {
		t.Errorf("aud: got %v want %v", got, want)
	}
	if got := claims["iat"]; got == nil {
		t.Errorf("iat missing")
	}
	if got := claims["jti"]; got == nil || got == "" {
		t.Errorf("jti missing")
	}
	if got, want := claims["sid"], sid.String(); got != want {
		t.Errorf("sid: got %v want %v", got, want)
	}
	events, ok := claims["events"].(map[string]interface{})
	if !ok {
		t.Fatalf("events claim missing or wrong type: %T", claims["events"])
	}
	if _, ok := events[BackchannelEventClaim]; !ok {
		t.Errorf("events claim must contain %q, got %v", BackchannelEventClaim, events)
	}

	// JOSE header MUST have typ=logout+jwt per RFC 8417 §2.4.
	if len(parsed.Headers) == 0 {
		t.Fatalf("no JOSE headers on token")
	}
	if got, want := parsed.Headers[0].ExtraHeaders[jose.HeaderType], "logout+jwt"; got != want {
		t.Errorf("typ header: got %v want %v", got, want)
	}
}

// TestSummarizeDispatchAggregatesResults verifies the audit summary helper
// correctly tallies succeeded vs total when persisting to
// session_revocation.metadata.
func TestSummarizeDispatchAggregatesResults(t *testing.T) {
	results := []BackchannelDispatchResult{
		{ClientID: "a", StatusCode: 200, Succeeded: true},
		{ClientID: "b", StatusCode: 500, Succeeded: false, Error: "boom"},
		{ClientID: "c", StatusCode: 204, Succeeded: true},
	}
	summary := SummarizeDispatch(results)
	bc, ok := summary["backchannel"].(map[string]any)
	if !ok {
		t.Fatalf("missing backchannel summary key: %v", summary)
	}
	if got, want := bc["dispatched"], 3; got != want {
		t.Errorf("dispatched: got %v want %v", got, want)
	}
	if got, want := bc["succeeded"], 2; got != want {
		t.Errorf("succeeded: got %v want %v", got, want)
	}
}

// TestSummarizeDispatchEmpty asserts the zero-results case produces a
// well-formed summary (avoids nil-map drama in audit consumers).
func TestSummarizeDispatchEmpty(t *testing.T) {
	summary := SummarizeDispatch(nil)
	bc, ok := summary["backchannel"].(map[string]any)
	if !ok {
		t.Fatalf("missing backchannel summary key: %v", summary)
	}
	if got, want := bc["dispatched"], 0; got != want {
		t.Errorf("dispatched: got %v want %v", got, want)
	}
}

// helperPEM returns a PEM-encoded PKCS1 key — used by future integration
// tests that need a synthesized OIDCSigningKey row.
func helperPEM(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

var _ = helperPEM // tests above don't need it yet; kept as a hook
