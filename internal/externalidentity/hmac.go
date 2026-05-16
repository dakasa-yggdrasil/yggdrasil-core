package externalidentity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// VerifySignature dispatches to the per-scheme HMAC verification.
// Schemes supported initially:
//
//	github_hmac_sha256   — X-Hub-Signature-256: "sha256=<hex>", HMAC over body
//
// Adding new schemes is a tiny case clause; signature verification stays
// in core (does NOT route through adapters).
func VerifySignature(scheme, secret string, headers http.Header, body []byte) error {
	switch scheme {
	case "github_hmac_sha256":
		return verifyGithubHmacSha256(secret, headers, body)
	default:
		return fmt.Errorf("unknown webhook signature scheme %q", scheme)
	}
}

func verifyGithubHmacSha256(secret string, headers http.Header, body []byte) error {
	got := strings.TrimSpace(headers.Get("X-Hub-Signature-256"))
	if got == "" {
		return fmt.Errorf("missing X-Hub-Signature-256 header")
	}
	if !strings.HasPrefix(got, "sha256=") {
		return fmt.Errorf("malformed signature header: %s", got)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(got), []byte(want)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
