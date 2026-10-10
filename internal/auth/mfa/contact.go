package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"unicode"
)

// ContactDeliverySelector accepts one operator-owned namespace/name pair.
// A persisted contact factor with no valid delivery selector cannot serve as
// the alternate factor when removing another primary authentication method.
func ContactDeliverySelector(channel string) (namespace, name string, ok bool) {
	key := "AUTH_EMAIL_INTEGRATION"
	if channel == "sms" {
		key = "AUTH_SMS_INTEGRATION"
	} else if channel != "email" {
		return "", "", false
	}
	value := strings.TrimSpace(os.Getenv(key))
	if strings.Count(value, "/") != 1 || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return "", "", false
	}
	namespace, name, ok = strings.Cut(value, "/")
	if !ok || namespace == "" || name == "" {
		return "", "", false
	}
	return namespace, name, true
}

// GenerateContactOTP returns independent high-entropy challenge material and a
// six-digit delivery code. Only the token reaches the HTTP client; the code
// belongs exclusively to the selected delivery adapter. Never log either.
func GenerateContactOTP() (rawToken, code string, err error) {
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return "", "", fmt.Errorf("generate contact challenge: %w", err)
	}
	value, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", "", fmt.Errorf("generate contact code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(token), fmt.Sprintf("%06d", value.Int64()), nil
}

func HashContactOTPToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// HashContactOTPCode uses the unpersisted challenge token as the HMAC key.
// Possession of the database's token and code digests cannot enumerate the
// one-million-value code space without knowing the original challenge token.
func HashContactOTPCode(rawToken, code string) string {
	mac := hmac.New(sha256.New, []byte(rawToken))
	_, _ = mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func ValidContactOTPToken(rawToken string) bool {
	if len(rawToken) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(rawToken)
	return err == nil && len(raw) == 32
}

func ValidContactOTPCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func VerifyContactOTPCode(rawToken, code, storedHash string) bool {
	if !ValidContactOTPCode(code) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(HashContactOTPCode(rawToken, code)), []byte(storedHash)) == 1
}
