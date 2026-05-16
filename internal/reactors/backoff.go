package reactors

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// BackoffFor returns the wait duration before the next attempt, plus a
// boolean indicating whether the reaction must be dead-lettered instead.
//
// Defaults: attempt 1 → 1m, attempt 2 → 5m, attempt 3 → 15m, attempt 4+ → dead-letter.
// Env overrides: REACTOR_BACKOFF_ATTEMPT_1/2/3 (Go duration syntax), REACTOR_MAX_ATTEMPTS (default 3).
func BackoffFor(attempt int) (time.Duration, bool) {
	maxAttempts := envIntPositive("REACTOR_MAX_ATTEMPTS", 3)
	if attempt < 1 || attempt > maxAttempts {
		return 0, true
	}
	switch attempt {
	case 1:
		return envDuration("REACTOR_BACKOFF_ATTEMPT_1", time.Minute), false
	case 2:
		return envDuration("REACTOR_BACKOFF_ATTEMPT_2", 5*time.Minute), false
	case 3:
		return envDuration("REACTOR_BACKOFF_ATTEMPT_3", 15*time.Minute), false
	default:
		return 0, true
	}
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func envIntPositive(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
