package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestLoginRateLimiter_BlocksAfterThreshold verifies the per-IP rate
// limiter: after the configured threshold of failed logins from one IP,
// subsequent attempts return 429 Too Many Requests instead of reaching
// the handler.
//
// Audit ref: reference_yggdrasil_dakasa_me_deep_audit_2026_05_27.md A4
// (no rate limit on /api/v1/auth/login).
func TestLoginRateLimiter_BlocksAfterThreshold(t *testing.T) {
	limiter := newLoginRateLimiter(5, 100*time.Millisecond, 10*time.Minute)
	clientIP := "203.0.113.42"

	// First 5 record-fail attempts should NOT block.
	for i := 0; i < 5; i++ {
		if blocked, _ := limiter.checkOrConsume(clientIP); blocked {
			t.Fatalf("attempt %d/5 should not be blocked", i+1)
		}
	}
	// 6th attempt MUST be blocked.
	if blocked, _ := limiter.checkOrConsume(clientIP); !blocked {
		t.Fatalf("6th attempt should be blocked but was allowed")
	}
}

// TestLoginRateLimiter_PerIPIsolation verifies that one IP exhausting
// its quota doesn't impact another IP's attempts.
func TestLoginRateLimiter_PerIPIsolation(t *testing.T) {
	limiter := newLoginRateLimiter(5, 100*time.Millisecond, 10*time.Minute)

	for i := 0; i < 6; i++ {
		_, _ = limiter.checkOrConsume("198.51.100.1")
	}
	if blocked, _ := limiter.checkOrConsume("198.51.100.1"); !blocked {
		t.Fatalf("IP .1 should be blocked")
	}
	// Different IP should still be allowed.
	if blocked, _ := limiter.checkOrConsume("198.51.100.2"); blocked {
		t.Fatalf("IP .2 should NOT be blocked by .1's exhaustion")
	}
}

// TestLoginRateLimiter_RefillsAfterCooldown verifies the leaky-bucket
// refill: after the cooldown window elapses, the IP gets a fresh quota.
func TestLoginRateLimiter_RefillsAfterCooldown(t *testing.T) {
	// 5 burst, 1 refill per 20ms — fast for test.
	limiter := newLoginRateLimiter(5, 20*time.Millisecond, 10*time.Minute)
	clientIP := "192.0.2.5"

	for i := 0; i < 6; i++ {
		_, _ = limiter.checkOrConsume(clientIP)
	}
	if blocked, _ := limiter.checkOrConsume(clientIP); !blocked {
		t.Fatalf("expected block before refill")
	}

	// Wait for refill.
	time.Sleep(40 * time.Millisecond)
	if blocked, _ := limiter.checkOrConsume(clientIP); blocked {
		t.Fatalf("expected unblock after refill")
	}
}

// TestLoginRateLimitMiddleware_429AfterBurst wires the middleware
// end-to-end: 6th login from the same IP returns 429 with a
// retry-after-style hint.
func TestLoginRateLimitMiddleware_429AfterBurst(t *testing.T) {
	limiter := newLoginRateLimiter(5, 100*time.Millisecond, 10*time.Minute)
	called := 0
	handler := loginRateLimit(limiter, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called++
	}))

	clientIP := "203.0.113.99:12345"
	body := bytes.NewBufferString(`{"identifier":"x","password":"y"}`)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
		req.RemoteAddr = clientIP
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d/5 should not be 429 (got code=%d)", i+1, w.Code)
		}
	}
	// 6th attempt → 429
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.RemoteAddr = clientIP
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: got %d, want %d", w.Code, http.StatusTooManyRequests)
	}
	if called != 5 {
		t.Fatalf("handler should have been called exactly 5 times before block, got %d", called)
	}
}
