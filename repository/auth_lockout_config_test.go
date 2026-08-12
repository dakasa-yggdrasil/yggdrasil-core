package repository

import (
	"testing"
	"time"
)

func TestLoginFailureThresholdFromEnv(t *testing.T) {
	if got := loginFailureThresholdFromEnv(); got != 10 {
		t.Fatalf("default threshold = %d, want 10", got)
	}
	t.Setenv("YGGDRASIL_LOGIN_FAILURE_THRESHOLD", "3")
	if got := loginFailureThresholdFromEnv(); got != 3 {
		t.Fatalf("override threshold = %d, want 3", got)
	}
	// A 0 or garbage value must not disable the lockout entirely.
	t.Setenv("YGGDRASIL_LOGIN_FAILURE_THRESHOLD", "0")
	if got := loginFailureThresholdFromEnv(); got != 10 {
		t.Fatalf("zero override threshold = %d, want fallback 10", got)
	}
}

func TestLoginLockDurationFromEnv(t *testing.T) {
	if got := loginLockDurationFromEnv(); got != 5*time.Minute {
		t.Fatalf("default lock = %s, want 5m", got)
	}
	t.Setenv("YGGDRASIL_LOGIN_LOCK_MINUTES", "30")
	if got := loginLockDurationFromEnv(); got != 30*time.Minute {
		t.Fatalf("override lock = %s, want 30m", got)
	}
	t.Setenv("YGGDRASIL_LOGIN_LOCK_MINUTES", "bad")
	if got := loginLockDurationFromEnv(); got != 5*time.Minute {
		t.Fatalf("bad override lock = %s, want fallback 5m", got)
	}
}
