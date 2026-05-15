// internal/auth/password/hasher.go
package password

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

type Scheme string

const (
	SchemeArgon2id     Scheme = "argon2id"
	SchemePBKDF2SHA256 Scheme = "pbkdf2_sha256"
)

var (
	ErrPasswordMismatch = errors.New("password mismatch")
	ErrSchemeUnknown    = errors.New("password scheme unknown")
	ErrHashCorrupt      = errors.New("password hash corrupt")
)

type argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	KeyLen  uint32
}

var loadedArgonParams = sync.OnceValue(func() argon2Params {
	return argon2Params{
		Memory:  uint32(envInt("AUTH_PASSWORD_ARGON2ID_MEMORY_KB", 65536)),
		Time:    uint32(envInt("AUTH_PASSWORD_ARGON2ID_TIME", 3)),
		Threads: uint8(envInt("AUTH_PASSWORD_ARGON2ID_THREADS", 4)),
		KeyLen:  32,
	}
})

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// Hash returns the active scheme and the encoded hash string.
func Hash(plain string) (Scheme, string, error) {
	params := loadedArgonParams()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		params.Memory, params.Time, params.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return SchemeArgon2id, encoded, nil
}

// Verify checks plain against encoded under the given scheme.
func Verify(scheme Scheme, encoded, plain string) error {
	switch scheme {
	case SchemeArgon2id:
		return verifyArgon2id(encoded, plain)
	case SchemePBKDF2SHA256:
		return verifyPBKDF2(encoded, plain)
	default:
		return ErrSchemeUnknown
	}
}

func verifyArgon2id(encoded, plain string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrHashCorrupt
	}
	if parts[2] != "v=19" {
		return ErrHashCorrupt
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return ErrHashCorrupt
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrHashCorrupt
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return ErrHashCorrupt
	}
	got := argon2.IDKey([]byte(plain), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func verifyPBKDF2(encoded, plain string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return ErrHashCorrupt
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return ErrHashCorrupt
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrHashCorrupt
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return ErrHashCorrupt
	}
	got := pbkdf2.Key([]byte(plain), salt, iter, len(want), sha256.New)
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
