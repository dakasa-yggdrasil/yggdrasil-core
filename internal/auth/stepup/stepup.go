// Package stepup enforces step-up auth for sensitive capabilities. A session
// must have re-authenticated within FreshnessWindow to call protected ops
// (db:psql-prod, aws:iam:create-user, etc.).
package stepup

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// DefaultFreshnessWindow is the default re-auth grace window. Spec §6.7
// recommends 5min; can be tuned per-tenant via Yggdrasil config.
const DefaultFreshnessWindow = 5 * time.Minute

// ErrStepUpRequired is returned when the current session has not re-auth'd
// within the freshness window.
var ErrStepUpRequired = errors.New("step-up auth required")

// Context resolved by the auth middleware before stepup runs.
type sessionCtxKey struct{}

// SessionInfo is the slice of session state stepup needs.
type SessionInfo struct {
	SessionID            uuid.UUID
	StepUpAuthenticatedAt *time.Time
}

// WithSession decorates ctx with the active session for downstream stepup.
func WithSession(ctx context.Context, info SessionInfo) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, info)
}

// FromContext returns the session info attached by WithSession.
func FromContext(ctx context.Context) (SessionInfo, bool) {
	s, ok := ctx.Value(sessionCtxKey{}).(SessionInfo)
	return s, ok
}

// Require enforces step-up freshness on the request. Caller wraps protected
// handlers; stepup answers 401 with WWW-Authenticate hint if the gate fails.
func Require(window time.Duration) func(http.Handler) http.Handler {
	if window <= 0 {
		window = DefaultFreshnessWindow
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, ok := FromContext(r.Context())
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="yggdrasil", error="invalid_request"`)
				http.Error(w, "session required", http.StatusUnauthorized)
				return
			}
			if !IsFresh(info, window) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="yggdrasil", error="step_up_required"`)
				http.Error(w, ErrStepUpRequired.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsFresh reports whether the session's last step-up timestamp falls inside
// the configured window.
func IsFresh(info SessionInfo, window time.Duration) bool {
	if info.StepUpAuthenticatedAt == nil {
		return false
	}
	return time.Since(*info.StepUpAuthenticatedAt) <= window
}

// Mark records a successful step-up re-auth on the session row. Caller is
// responsible for verifying credentials before invoking this.
func Mark(ctx context.Context, db *sql.DB, sessionID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE public.auth_sessions
		SET step_up_authenticated_at = NOW()
		WHERE id = $1
	`, sessionID)
	return err
}
