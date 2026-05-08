package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidRecoveryCode is returned when a code does not match any stored hash
// or has already been consumed.
var ErrInvalidRecoveryCode = errors.New("invalid recovery code")

// RecoveryCodeCount is the number of single-use codes generated per enroll.
const RecoveryCodeCount = 10

// recoveryCodeBytes is 80 bits per code (16 chars base32 no-padding).
const recoveryCodeBytes = 10

// GenerateRecoveryCodes returns 10 plaintext recovery codes plus their SHA-256
// hashes. Codes are shown to the user exactly once; only the hashes are
// persisted. Format: 4-char chunks split by `-` for readability.
func GenerateRecoveryCodes() (codes []string, hashes []string, err error) {
	codes = make([]string, RecoveryCodeCount)
	hashes = make([]string, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("rand: %w", err)
		}
		raw32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		formatted := formatRecoveryCode(raw32)
		codes[i] = formatted
		hashes[i] = hashRecoveryCode(formatted)
	}
	return codes, hashes, nil
}

// VerifyRecoveryCode returns the index of the matching hash for the supplied
// plaintext code, or -1 + ErrInvalidRecoveryCode if no match is found.
// Caller is responsible for atomically removing/marking the matching hash to
// enforce single-use.
func VerifyRecoveryCode(code string, storedHashes []string) (int, error) {
	candidate := hashRecoveryCode(code)
	for i, h := range storedHashes {
		if h == candidate {
			return i, nil
		}
	}
	return -1, ErrInvalidRecoveryCode
}

func hashRecoveryCode(code string) string {
	normalized := normalizeRecoveryCode(code)
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func formatRecoveryCode(raw32 string) string {
	// Standard format: XXXX-XXXX-XXXX-XXXX (16 chars without dashes).
	if len(raw32) < 16 {
		return raw32
	}
	raw32 = strings.ToUpper(raw32[:16])
	return fmt.Sprintf("%s-%s-%s-%s", raw32[0:4], raw32[4:8], raw32[8:12], raw32[12:16])
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}
