package externalidentity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifySignature_GithubHmacSha256_Valid(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"a":1}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	hdr := http.Header{"X-Hub-Signature-256": []string{sig}}
	assert.NoError(t, VerifySignature("github_hmac_sha256", secret, hdr, body))
}

func TestVerifySignature_GithubHmacSha256_Tampered(t *testing.T) {
	secret := "topsecret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(`{"a":2}`))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	hdr := http.Header{"X-Hub-Signature-256": []string{sig}}
	assert.Error(t, VerifySignature("github_hmac_sha256", secret, hdr, []byte(`{"a":1}`)))
}

func TestVerifySignature_MissingHeader(t *testing.T) {
	assert.Error(t, VerifySignature("github_hmac_sha256", "x", http.Header{}, []byte(`{}`)))
}

func TestVerifySignature_UnknownScheme(t *testing.T) {
	assert.Error(t, VerifySignature("bogus", "x", http.Header{}, nil))
}
