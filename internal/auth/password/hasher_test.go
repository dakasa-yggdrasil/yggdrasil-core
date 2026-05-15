// internal/auth/password/hasher_test.go
package password

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestArgon2idRoundTrip(t *testing.T) {
	plain := "correct horse battery staple!"
	scheme, hash, err := Hash(plain)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if scheme != SchemeArgon2id {
		t.Fatalf("expected scheme %q, got %q", SchemeArgon2id, scheme)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected argon2id-encoded hash, got %q", hash)
	}
	if err := Verify(scheme, hash, plain); err != nil {
		t.Fatalf("verify accept: %v", err)
	}
	if err := Verify(scheme, hash, "wrong"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("verify reject: got %v want %v", err, ErrPasswordMismatch)
	}
}

func TestVerifyLegacyPBKDF2(t *testing.T) {
	// Build a known pbkdf2_sha256 hash inline (no Hash() exists for this scheme;
	// we use crypto/pbkdf2 directly), then assert Verify accepts and rejects.
	plain := "legacy-pa55-word-fixture"
	salt := []byte("0123456789abcdef")
	iter := 600000
	key := pbkdf2.Key([]byte(plain), salt, iter, 32, sha256.New)
	encoded := fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		iter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	if err := Verify(SchemePBKDF2SHA256, encoded, plain); err != nil {
		t.Fatalf("legacy verify accept: %v", err)
	}
	if err := Verify(SchemePBKDF2SHA256, encoded, "wrong"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("legacy verify reject: got %v want %v", err, ErrPasswordMismatch)
	}
	// Malformed
	if err := Verify(SchemePBKDF2SHA256, "pbkdf2_sha256$bad", plain); !errors.Is(err, ErrHashCorrupt) {
		t.Fatalf("malformed expected ErrHashCorrupt, got %v", err)
	}
}

func TestVerifyUnknownScheme(t *testing.T) {
	if err := Verify(Scheme("bcrypt-future"), "x", "y"); !errors.Is(err, ErrSchemeUnknown) {
		t.Fatalf("expected ErrSchemeUnknown, got %v", err)
	}
}
