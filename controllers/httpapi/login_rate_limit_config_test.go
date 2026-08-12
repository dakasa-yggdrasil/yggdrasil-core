package httpapi

import (
	"testing"
	"time"
)

func TestLoginRateBurstDefaultAndOverride(t *testing.T) {
	if got := loginRateBurst(); got != 20 {
		t.Fatalf("default burst = %d, want 20", got)
	}
	t.Setenv("YGGDRASIL_LOGIN_RATE_BURST", "50")
	if got := loginRateBurst(); got != 50 {
		t.Fatalf("override burst = %d, want 50", got)
	}
	// Garbage / non-positive falls back to the default rather than
	// silently disabling the limiter with a 0 burst.
	t.Setenv("YGGDRASIL_LOGIN_RATE_BURST", "0")
	if got := loginRateBurst(); got != 20 {
		t.Fatalf("zero override burst = %d, want fallback 20", got)
	}
	t.Setenv("YGGDRASIL_LOGIN_RATE_BURST", "nope")
	if got := loginRateBurst(); got != 20 {
		t.Fatalf("bad override burst = %d, want fallback 20", got)
	}
}

func TestLoginRateRefillDefaultAndOverride(t *testing.T) {
	if got := loginRateRefill(); got != 6*time.Second {
		t.Fatalf("default refill = %s, want 6s", got)
	}
	t.Setenv("YGGDRASIL_LOGIN_RATE_REFILL_SECONDS", "2")
	if got := loginRateRefill(); got != 2*time.Second {
		t.Fatalf("override refill = %s, want 2s", got)
	}
	t.Setenv("YGGDRASIL_LOGIN_RATE_REFILL_SECONDS", "-1")
	if got := loginRateRefill(); got != 6*time.Second {
		t.Fatalf("negative override refill = %s, want fallback 6s", got)
	}
}
