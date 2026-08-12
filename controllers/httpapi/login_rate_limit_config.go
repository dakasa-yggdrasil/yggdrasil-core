package httpapi

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Login rate-limit tuning. The per-IP login limiter (see login_rate_limit.go)
// gates /api/v1/auth/login, the password-change endpoint, and BOTH legs of
// the WebAuthn login ceremony (begin + finish) — so a single passkey sign-in
// costs two tokens. The original audit defaults (5 burst, 1 token/min) were
// tight enough to punish ordinary use: a couple of fumbled sign-ins, or a
// developer exercising the flow, exhausted the burst and dropped to one
// attempt per minute. These give a roomier default while staying bounded
// (a real limit, not an open door), and expose env overrides so an operator
// can tighten prod or loosen a shared test env without a rebuild.

const (
	defaultLoginRateBurst         = 20
	defaultLoginRateRefillSeconds = 6
)

// loginRateBurst is how many login attempts one IP can make instantly before
// the refill drip applies. Override with YGGDRASIL_LOGIN_RATE_BURST.
func loginRateBurst() int {
	if v := strings.TrimSpace(os.Getenv("YGGDRASIL_LOGIN_RATE_BURST")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultLoginRateBurst
}

// loginRateRefill is the interval between refilled tokens once the burst is
// spent (one token per interval). Default 6s -> 10 attempts/min sustained.
// Override with YGGDRASIL_LOGIN_RATE_REFILL_SECONDS.
func loginRateRefill() time.Duration {
	if v := strings.TrimSpace(os.Getenv("YGGDRASIL_LOGIN_RATE_REFILL_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultLoginRateRefillSeconds * time.Second
}
