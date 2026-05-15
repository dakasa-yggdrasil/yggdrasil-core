// internal/auth/password/token_test.go
package password

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateTokenDistinct(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		tok, err := GenerateToken()
		if err != nil {
			t.Fatalf("gen: %v", err)
		}
		if len(tok.Raw) < 40 {
			t.Fatalf("raw too short: %d", len(tok.Raw))
		}
		if _, err := base64.RawURLEncoding.DecodeString(tok.Raw); err != nil {
			t.Fatalf("raw not base64url: %v (%q)", err, tok.Raw)
		}
		if strings.ContainsAny(tok.Raw, "+/=") {
			t.Fatalf("raw must be url-safe: %q", tok.Raw)
		}
		if _, dup := seen[tok.Raw]; dup {
			t.Fatalf("duplicate raw token at i=%d", i)
		}
		seen[tok.Raw] = struct{}{}
		if len(tok.Hash) != 64 {
			t.Fatalf("hash must be 64 hex chars, got %d", len(tok.Hash))
		}
	}
}

func TestHashTokenStable(t *testing.T) {
	h1 := HashToken("abc")
	h2 := HashToken("abc")
	if h1 != h2 {
		t.Fatalf("HashToken not deterministic: %s vs %s", h1, h2)
	}
	if h1 == HashToken("abd") {
		t.Fatalf("HashToken collision on different inputs")
	}
}
