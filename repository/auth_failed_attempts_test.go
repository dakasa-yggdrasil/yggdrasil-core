package repository

import (
	"errors"
	"testing"
)

// TestErrAuthAccountLocked guards the new lockout error surface for the
// security audit 2026-05-27 A4 fix. The error MUST be a distinct
// sentinel from ErrAuthInvalidCredentials so the HTTP layer can return
// 423 Locked (rather than 401) and the FE can surface a "your account
// is temporarily locked" message.
func TestErrAuthAccountLocked_DistinctSentinel(t *testing.T) {
	if ErrAuthAccountLocked == nil {
		t.Fatal("ErrAuthAccountLocked must be exported")
	}
	if errors.Is(ErrAuthAccountLocked, ErrAuthInvalidCredentials) {
		t.Fatal("ErrAuthAccountLocked must NOT be ErrAuthInvalidCredentials")
	}
}
