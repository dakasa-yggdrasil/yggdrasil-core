package httpapi

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// loginRateLimiter caps anonymous /api/v1/auth/login attempts per source
// IP using a leaky-bucket (golang.org/x/time/rate). Each IP gets `burst`
// attempts immediately; subsequent attempts are admitted at the
// `refill` interval. The map is bounded by `idleTTL` — entries that
// haven't been touched in that long are evicted on the next sweep so
// the in-memory map can't grow unboundedly.
//
// Security audit 2026-05-27 A4: production currently has zero rate
// limit on /api/v1/auth/login, so a 7-char password is brute-forceable
// from a small botnet in days. This middleware closes the open door.
//
// Conservative defaults: 5 attempts burst, 1 attempt refill per 60s
// (so 5 in the first instant, then 1/min ramp). idleTTL=10 min so we
// never accumulate stale entries.
type loginRateLimiter struct {
	mu      sync.Mutex
	limits  map[string]*loginLimitEntry
	burst   int
	refill  rate.Limit
	idleTTL time.Duration
}

type loginLimitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newLoginRateLimiter constructs a per-IP rate limiter.
//   - burst: how many attempts an IP can make instantly.
//   - refillInterval: time between subsequent refills (1 token per
//     interval after burst is consumed).
//   - idleTTL: entries not touched in this long are eligible for GC.
func newLoginRateLimiter(burst int, refillInterval, idleTTL time.Duration) *loginRateLimiter {
	rl := rate.Every(refillInterval)
	return &loginRateLimiter{
		limits:  make(map[string]*loginLimitEntry),
		burst:   burst,
		refill:  rl,
		idleTTL: idleTTL,
	}
}

// checkOrConsume tries to consume one token for the given IP. Returns
// (blocked, retryAfter). When blocked is true, retryAfter is a hint
// for the client.
func (l *loginRateLimiter) checkOrConsume(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	entry, ok := l.limits[ip]
	if !ok {
		entry = &loginLimitEntry{
			limiter: rate.NewLimiter(l.refill, l.burst),
		}
		l.limits[ip] = entry
	}
	entry.lastSeen = now

	// Opportunistic GC: every 1 in 32 calls sweep stale entries. Cheap
	// in the steady state, never grows the map unbounded.
	if len(l.limits) > 32 && (now.UnixNano()%32) == 0 {
		for k, e := range l.limits {
			if now.Sub(e.lastSeen) > l.idleTTL {
				delete(l.limits, k)
			}
		}
	}

	if entry.limiter.AllowN(now, 1) {
		return false, 0
	}

	// Compute a coarse retry-after hint: the reservation's wait time.
	res := entry.limiter.ReserveN(now, 1)
	wait := time.Duration(0)
	if res.OK() {
		wait = res.DelayFrom(now)
		// Cancel — we're not actually consuming, just reporting the wait.
		res.Cancel()
	}
	return true, wait
}

// loginRateLimit wraps the login handler with the per-IP rate gate.
// Clients that exceed the burst receive 429 Too Many Requests with a
// JSON body shaped like the other writeMappedError responses so the
// frontend humanizer continues to work.
func loginRateLimit(limiter *loginRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := loginClientIP(r)
		blocked, retryAfter := limiter.checkOrConsume(ip)
		if blocked {
			if retryAfter > 0 {
				w.Header().Set("Retry-After", retryAfterHeaderValue(retryAfter))
			}
			writeJSON(w, http.StatusTooManyRequests, errorResponse{
				Error: "too many login attempts, please slow down",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loginClientIP extracts the source IP for rate-limiting purposes.
// Prefers X-Forwarded-For (first hop) when present — yggdrasil sits
// behind traefik in production so r.RemoteAddr is the proxy's address.
// Falls back to r.RemoteAddr stripped of its port.
func loginClientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		// First entry is the original client.
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		return real
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// retryAfterHeaderValue formats a duration as a non-negative integer
// number of seconds (RFC 7231 retry-after delta-seconds form).
func retryAfterHeaderValue(d time.Duration) string {
	if d <= 0 {
		return "1"
	}
	secs := int((d + time.Second - 1) / time.Second) // ceil
	if secs < 1 {
		secs = 1
	}
	return intToASCII(secs)
}

// intToASCII converts a non-negative int into its decimal ASCII form
// without pulling in strconv (we already have it, but this keeps the
// header-formatting function locally pure and ASCII-only).
func intToASCII(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + (n % 10))
		n /= 10
	}
	return string(buf[pos:])
}
