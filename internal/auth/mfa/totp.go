// Package mfa wraps the project's MFA primitives: TOTP, WebAuthn, and recovery codes.
package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ErrInvalidTOTP is returned when a 6-digit TOTP code does not match the
// stored secret within the configured drift window.
var ErrInvalidTOTP = errors.New("invalid TOTP code")

const (
	totpIssuerDefault = "Yggdrasil"
	totpDigits        = otp.DigitsSix
	totpAlgorithm     = otp.AlgorithmSHA1
	totpPeriod        = 30
	totpWindowSteps   = 1 // ±30s drift
)

// TOTPSecret is the plaintext shared secret + the otpauth:// provisioning URI.
// Persistence layer encrypts the secret at rest using cryptoenvelope.
type TOTPSecret struct {
	Base32     string
	OTPAuthURL string
}

// GenerateTOTPSecret allocates a fresh 160-bit secret and returns it together
// with the otpauth:// URI suitable for QR-code rendering.
func GenerateTOTPSecret(accountName string) (TOTPSecret, error) {
	if accountName == "" {
		return TOTPSecret{}, fmt.Errorf("accountName required")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuerDefault,
		AccountName: accountName,
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgorithm,
		Rand:        rand.Reader,
	})
	if err != nil {
		return TOTPSecret{}, fmt.Errorf("totp generate: %w", err)
	}
	return TOTPSecret{
		Base32:     key.Secret(),
		OTPAuthURL: key.URL(),
	}, nil
}

// ValidateTOTP checks code against secret with the configured drift window.
func ValidateTOTP(secretBase32, code string) error {
	if secretBase32 == "" {
		return fmt.Errorf("totp secret required")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretBase32); err != nil {
		return fmt.Errorf("totp secret invalid base32: %w", err)
	}
	ok, err := totp.ValidateCustom(code, secretBase32, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpWindowSteps,
		Digits:    totpDigits,
		Algorithm: totpAlgorithm,
	})
	if err != nil {
		return fmt.Errorf("totp validate: %w", err)
	}
	if !ok {
		return ErrInvalidTOTP
	}
	return nil
}
