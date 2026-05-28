package metrics

import (
	"testing"
)

// TestAuthLoginCounters_IncrementCorrectBuckets verifies each outcome
// goes to its dedicated counter and unknown outcomes are dropped (no
// cardinality explosion).
//
// Audit ref: reference_yggdrasil_dakasa_me_deep_audit_2026_05_27.md G3
// (no Prometheus metrics on auth flows).
func TestAuthLoginCounters_IncrementCorrectBuckets(t *testing.T) {
	ResetForTest()
	IncAuthLogin(AuthLoginSucceeded)
	IncAuthLogin(AuthLoginSucceeded)
	IncAuthLogin(AuthLoginFailed)
	IncAuthLogin(AuthLoginRateLimited)
	IncAuthLogin(AuthLoginAccountLocked)
	IncAuthLogin(AuthLoginMFARequired)
	IncAuthLogin("unknown_outcome") // must be a no-op

	snap := AuthLoginSnapshot()
	if snap[AuthLoginSucceeded] != 2 {
		t.Errorf("expected succeeded=2, got %d", snap[AuthLoginSucceeded])
	}
	if snap[AuthLoginFailed] != 1 {
		t.Errorf("expected failed=1, got %d", snap[AuthLoginFailed])
	}
	if snap[AuthLoginRateLimited] != 1 {
		t.Errorf("expected rate_limited=1, got %d", snap[AuthLoginRateLimited])
	}
	if snap[AuthLoginAccountLocked] != 1 {
		t.Errorf("expected account_locked=1, got %d", snap[AuthLoginAccountLocked])
	}
	if snap[AuthLoginMFARequired] != 1 {
		t.Errorf("expected mfa_required=1, got %d", snap[AuthLoginMFARequired])
	}
	// Unknown outcomes are silently dropped — no panic, no map growth.
	if len(snap) != 5 {
		t.Errorf("expected exactly 5 buckets, got %d", len(snap))
	}
}

// TestAuthMFAVerifyCounters_LabelByOutcomeAndFactor verifies the
// (outcome, factor) cardinality is bounded.
func TestAuthMFAVerifyCounters_LabelByOutcomeAndFactor(t *testing.T) {
	ResetForTest()
	IncAuthMFAVerify(AuthMFAVerifySucceeded, AuthMFAFactorTOTP)
	IncAuthMFAVerify(AuthMFAVerifySucceeded, AuthMFAFactorTOTP)
	IncAuthMFAVerify(AuthMFAVerifyFailed, AuthMFAFactorTOTP)
	IncAuthMFAVerify(AuthMFAVerifySucceeded, AuthMFAFactorRecoveryCode)
	IncAuthMFAVerify(AuthMFAVerifyFailed, AuthMFAFactorWebAuthn)
	IncAuthMFAVerify("bogus", AuthMFAFactorTOTP) // dropped

	snap := AuthMFAVerifySnapshot()
	if got := snap[AuthMFAVerifySucceeded+"|"+AuthMFAFactorTOTP]; got != 2 {
		t.Errorf("succeeded|totp = %d, want 2", got)
	}
	if got := snap[AuthMFAVerifyFailed+"|"+AuthMFAFactorTOTP]; got != 1 {
		t.Errorf("failed|totp = %d, want 1", got)
	}
	if got := snap[AuthMFAVerifySucceeded+"|"+AuthMFAFactorRecoveryCode]; got != 1 {
		t.Errorf("succeeded|recovery_code = %d, want 1", got)
	}
	if got := snap[AuthMFAVerifyFailed+"|"+AuthMFAFactorWebAuthn]; got != 1 {
		t.Errorf("failed|webauthn = %d, want 1", got)
	}
}

// TestAuthSessionCounters_LifetimeCount verifies the session-lifecycle
// counters add up over their lifetime.
func TestAuthSessionCounters_LifetimeCount(t *testing.T) {
	ResetForTest()
	for i := 0; i < 10; i++ {
		IncAuthSessionCreated()
	}
	for i := 0; i < 3; i++ {
		IncAuthSessionRevoked()
	}
	if got := AuthSessionsCreatedTotalSnapshot(); got != 10 {
		t.Errorf("created total = %d, want 10", got)
	}
	if got := AuthSessionsRevokedTotalSnapshot(); got != 3 {
		t.Errorf("revoked total = %d, want 3", got)
	}
}
