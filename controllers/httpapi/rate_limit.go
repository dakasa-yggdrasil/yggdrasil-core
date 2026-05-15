package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrRateLimitExceeded is returned by enforceForgotRateLimit when the caller
// has exceeded the allowed number of requests within the rolling window.
var ErrRateLimitExceeded = errors.New("rate limit exceeded")

// enforceForgotRateLimit counts how many unexpired reset tokens carry the given
// rl_key in their metadata within the rolling window. If the count meets or
// exceeds maxPerWindow, ErrRateLimitExceeded is returned.
//
// Note: int(window.Seconds()) is safe to interpolate because the value comes
// from a trusted duration constant (never from user input).
func enforceForgotRateLimit(ctx context.Context, db *sql.DB, key string, maxPerWindow int, window time.Duration) error {
	var count int
	row := db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT COUNT(*) FROM auth_credential_tokens
		WHERE purpose = 'reset'
		  AND created_at > NOW() - INTERVAL '%d seconds'
		  AND metadata ->> 'rl_key' = $1
	`, int(window.Seconds())), key)
	if err := row.Scan(&count); err != nil {
		return err
	}
	if count >= maxPerWindow {
		return ErrRateLimitExceeded
	}
	return nil
}
