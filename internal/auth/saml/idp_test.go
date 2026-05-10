package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIdentityProviderSSOInvalidRequestDoesNotPanic(t *testing.T) {
	baseURL, err := url.Parse("https://idp.example.com")
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	priv, cert := testSigningMaterial(t)
	idp := newIdentityProvider(Config{
		BaseURL:     baseURL,
		IDPEntityID: "https://idp.example.com/saml/metadata",
	}, nil, priv, cert)

	if idp.Logger == nil {
		t.Fatal("IdentityProvider logger is nil")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/sso", nil)
	idp.ServeSSO(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func testSigningMaterial(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return priv, cert
}
