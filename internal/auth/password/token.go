// internal/auth/password/token.go
package password

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GeneratedToken pairs a raw token (returned to the caller exactly once)
// with the hash that will be persisted in auth_credential_tokens.
type GeneratedToken struct {
	Raw  string // url-safe base64, 32-byte entropy
	Hash string // hex sha256(raw)
}

// GenerateToken produces a fresh 32-byte token and its sha256 hash.
func GenerateToken() (GeneratedToken, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return GeneratedToken{}, fmt.Errorf("token rand: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	return GeneratedToken{Raw: raw, Hash: HashToken(raw)}, nil
}

// HashToken is the canonical hashing applied before storage and lookup.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
