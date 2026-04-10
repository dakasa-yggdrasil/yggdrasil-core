package coreauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	passwordSchemePBKDF2SHA256 = "pbkdf2_sha256"
	passwordSaltBytes          = 16
	passwordKeyBytes           = 32
	passwordIterations         = 210000
)

// HashPassword derives a deterministic PBKDF2-SHA256 hash using only standard library primitives.
func HashPassword(password string) (string, error) {
	password = strings.TrimSpace(password)
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters long")
	}

	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	derived := pbkdf2SHA256([]byte(password), salt, passwordIterations, passwordKeyBytes)
	return fmt.Sprintf(
		"%s$%d$%s$%s",
		passwordSchemePBKDF2SHA256,
		passwordIterations,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(derived),
	), nil
}

// VerifyPassword checks one cleartext password against the stored PBKDF2-SHA256 hash.
func VerifyPassword(encodedHash, password string) (bool, error) {
	parts := strings.Split(strings.TrimSpace(encodedHash), "$")
	if len(parts) != 4 {
		return false, fmt.Errorf("invalid password hash format")
	}
	if parts[0] != passwordSchemePBKDF2SHA256 {
		return false, fmt.Errorf("unsupported password scheme %q", parts[0])
	}

	iterations := passwordIterations
	if _, err := fmt.Sscanf(parts[1], "%d", &iterations); err != nil || iterations <= 0 {
		return false, fmt.Errorf("invalid password iteration count")
	}

	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("decode password salt: %w", err)
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("decode password hash: %w", err)
	}

	actual := pbkdf2SHA256([]byte(password), salt, iterations, len(expected))
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return false, nil
	}
	return true, nil
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	hashLength := sha256.Size
	blockCount := (keyLength + hashLength - 1) / hashLength
	output := make([]byte, 0, blockCount*hashLength)

	for block := 1; block <= blockCount; block++ {
		var blockIndex [4]byte
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))

		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(blockIndex[:])
		u := mac.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for index := range t {
				t[index] ^= u[index]
			}
		}

		output = append(output, t...)
	}

	return output[:keyLength]
}

