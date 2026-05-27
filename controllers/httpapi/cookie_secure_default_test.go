package httpapi

import (
	"testing"
)

// TestAuthSessionCookieSecure_DefaultsTrue locks down the security audit
// 2026-05-27 A3 fix: when AUTH_SESSION_COOKIE_SECURE is unset, the cookie
// MUST be issued with the Secure flag. The previous default-false was a
// production-time foot-gun (an operator who forgot the env var would
// silently emit cookies usable over plaintext HTTP).
//
// Set the env var explicitly to "false" for local-dev plaintext setups.
func TestAuthSessionCookieSecure_DefaultsTrue(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SECURE", "")
	if !authSessionCookieSecure() {
		t.Fatal("default AUTH_SESSION_COOKIE_SECURE: expected true when env unset, got false")
	}
}

// TestAuthSessionCookieSecure_RespectsExplicitFalse preserves the
// local-dev escape hatch: an explicit "false" turns it off.
func TestAuthSessionCookieSecure_RespectsExplicitFalse(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SECURE", "false")
	if authSessionCookieSecure() {
		t.Fatal("AUTH_SESSION_COOKIE_SECURE=false: expected false, got true")
	}
}

// TestAuthSessionCookieSecure_RespectsExplicitTrue: production stays
// secure with the explicit setting too.
func TestAuthSessionCookieSecure_RespectsExplicitTrue(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SECURE", "true")
	if !authSessionCookieSecure() {
		t.Fatal("AUTH_SESSION_COOKIE_SECURE=true: expected true, got false")
	}
}

// TestAuthSessionCookieSecure_GarbageValueDefaultsTrue: unparseable
// values fall back to the secure default rather than the unsafe one —
// fail-closed.
func TestAuthSessionCookieSecure_GarbageValueDefaultsTrue(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SECURE", "garbage")
	if !authSessionCookieSecure() {
		t.Fatal("AUTH_SESSION_COOKIE_SECURE=garbage: expected true (fail-closed), got false")
	}
}
