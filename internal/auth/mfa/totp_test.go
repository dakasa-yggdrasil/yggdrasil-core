package mfa

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTPSecret_ReturnsBase32AndURL(t *testing.T) {
	s, err := GenerateTOTPSecret("alice@dakasa.me")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if s.Base32 == "" {
		t.Fatal("expected non-empty Base32")
	}
	if s.OTPAuthURL == "" {
		t.Fatal("expected non-empty OTPAuthURL")
	}
}

func TestValidateTOTP_AcceptsCurrentCode(t *testing.T) {
	s, err := GenerateTOTPSecret("alice@dakasa.me")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	code, err := totp.GenerateCode(s.Base32, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if err := ValidateTOTP(s.Base32, code); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateTOTP_RejectsWrongCode(t *testing.T) {
	s, err := GenerateTOTPSecret("alice@dakasa.me")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ValidateTOTP(s.Base32, "000000"); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("expected ErrInvalidTOTP, got %v", err)
	}
}

func TestValidateTOTP_RejectsInvalidSecret(t *testing.T) {
	if err := ValidateTOTP("not-base32!!!", "123456"); err == nil {
		t.Fatal("expected error for invalid base32 secret")
	}
}
