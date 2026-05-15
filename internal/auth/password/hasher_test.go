// internal/auth/password/hasher_test.go
package password

import (
	"strings"
	"testing"
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
	if err := Verify(scheme, hash, "wrong"); err != ErrPasswordMismatch {
		t.Fatalf("verify reject: got %v want %v", err, ErrPasswordMismatch)
	}
}

func TestVerifyLegacyPBKDF2(t *testing.T) {
	t.Skip("requires real legacy fixture; enable when fixture is supplied from a pre-existing pbkdf2 hash captured in repo")
}

func TestVerifyUnknownScheme(t *testing.T) {
	if err := Verify(Scheme("bcrypt-future"), "x", "y"); err != ErrSchemeUnknown {
		t.Fatalf("expected ErrSchemeUnknown, got %v", err)
	}
}
