package mfa

import (
	"errors"
	"testing"
)

func TestGenerateRecoveryCodes_TenUniqueCodes(t *testing.T) {
	codes, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("expected %d/%d, got %d/%d codes/hashes", RecoveryCodeCount, RecoveryCodeCount, len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 19 { // 16 chars + 3 dashes
			t.Errorf("unexpected length: %q", c)
		}
		if seen[c] {
			t.Errorf("duplicate code: %q", c)
		}
		seen[c] = true
	}
}

func TestVerifyRecoveryCode_AcceptsAndRejects(t *testing.T) {
	codes, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	idx, err := VerifyRecoveryCode(codes[3], hashes)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if idx != 3 {
		t.Fatalf("expected idx 3, got %d", idx)
	}
	// case insensitivity + dash normalization
	idx, err = VerifyRecoveryCode("  "+codes[3]+"  ", hashes)
	if err != nil {
		t.Fatalf("verify normalized: %v", err)
	}
	if idx != 3 {
		t.Fatalf("expected idx 3, got %d", idx)
	}
	// reject random
	if _, err := VerifyRecoveryCode("AAAA-BBBB-CCCC-DDDD", hashes); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatalf("expected ErrInvalidRecoveryCode, got %v", err)
	}
}
