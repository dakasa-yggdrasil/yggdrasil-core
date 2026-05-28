package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// CSRF defense — double-submit cookie + HMAC binding (audit 2026-05-27 A7).
//
// Per-session CSRF token derived deterministically as
// `base64url(HMAC-SHA256(csrf_secret, session_id))`. Stored in two places
// the browser can mirror back to us:
//
//  1. Non-HttpOnly cookie `yggdrasil_csrf_token` so JS that doesn't read
//     the /auth/session envelope can still mirror it.
//  2. `csrf_token` field on the /auth/session envelope so any client that
//     hits that endpoint at startup gets the value without reading the
//     cookie.
//
// On a state-changing request (POST/PUT/DELETE/PATCH) the caller must echo
// the token in the `X-CSRF-Token` request header. The middleware recomputes
// the HMAC server-side and rejects mismatches. The session token itself
// never leaves the HttpOnly cookie, so even with the CSRF token cookie
// readable, an attacker can't forge requests without ALSO knowing the
// HMAC secret — which they shouldn't.
//
// Routes exempt from enforcement:
//
//   - GET / HEAD / OPTIONS (state-changing methods only)
//   - Public endpoints (/api/v1/auth/login, /auth/passwords/setup, etc.)
//     where the caller has no session yet
//   - Workflow-run token / manifest-token paths — those carry their own
//     bearer auth and are called by automation, not browsers
//   - Webhook receivers — third-party callers can't echo our header
//
// Mode is gated by `YGGDRASIL_CSRF_ENFORCE`:
//
//   - "warn" (default): missing/invalid header logs a warning + bumps a
//     metric but still passes the request through. Lets us roll the
//     backend independent of surface-console; flip to enforce once both
//     sides ship the matching change.
//   - "enforce": missing/invalid header returns 403 Problem+JSON.

// csrfTokenCookieName is the cookie that mirrors the token to the browser.
// Non-HttpOnly so the SPA can read it via document.cookie; this is fine
// because the value alone gives no attack capability — the session cookie
// is still HttpOnly and the only way to perform a state change.
const csrfTokenCookieName = "yggdrasil_csrf_token"

// csrfHeaderName is the request header the SPA must echo on mutating calls.
const csrfHeaderName = "X-CSRF-Token"

// csrfSecret returns the HMAC key for deriving CSRF tokens.
//
// Production deploys MUST set `YGGDRASIL_CSRF_HMAC_SECRET` to a 32+ byte
// random value. The fallback "yggdrasil-dev-csrf-hmac-secret" exists so
// local dev / tests don't have to wire the env.
func csrfSecret() []byte {
	if v := strings.TrimSpace(os.Getenv("YGGDRASIL_CSRF_HMAC_SECRET")); v != "" {
		return []byte(v)
	}
	return []byte("yggdrasil-dev-csrf-hmac-secret")
}

// computeCSRFToken returns the deterministic CSRF token for a session.
// Same session ID → same token, so the SPA can refresh state without
// re-deriving and the middleware can recompute on every request without
// keeping state.
func computeCSRFToken(sessionID uuid.UUID) string {
	mac := hmac.New(sha256.New, csrfSecret())
	mac.Write(sessionID[:])
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

// writeCSRFCookie installs the CSRF token cookie on the response.
//
// Path=/ so the cookie rides every request the SPA makes. Non-HttpOnly so
// JS can mirror it; Secure tracks the session cookie's Secure flag so we
// don't go down on HTTP-only dev setups. SameSite tracks the session
// cookie's SameSite — if the session cookie can't ride a request, the
// CSRF cookie shouldn't either (same blast radius).
func writeCSRFCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfTokenCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: false,
		SameSite: authSessionCookieSameSite(),
		Secure:   authSessionCookieSecure(),
		Domain:   authSessionCookieDomain(),
	})
}

// clearCSRFCookie deletes the CSRF cookie on logout. Same attributes as
// writeCSRFCookie so the browser doesn't keep an orphan around.
func clearCSRFCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfTokenCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: false,
		SameSite: authSessionCookieSameSite(),
		Secure:   authSessionCookieSecure(),
		Domain:   authSessionCookieDomain(),
	})
}

// csrfEnforceMode resolves the enforcement mode (warn or enforce).
// Default warn so a partial rollout (backend ships first, surface-console
// later) doesn't 403-storm legitimate traffic.
func csrfEnforceMode() string {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("YGGDRASIL_CSRF_ENFORCE")))
	switch value {
	case "enforce":
		return "enforce"
	case "warn", "":
		return "warn"
	default:
		return "warn"
	}
}

// csrfMethodRequiresToken returns true for state-changing methods.
// Same list HTML forms can produce + browser fetch defaults.
func csrfMethodRequiresToken(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

// csrfPathExempt returns true for paths that don't participate in the
// SPA-session CSRF model. Login/logout aren't gated because the caller
// has no session yet (login) or just terminated it (logout). Setup +
// password reset use one-time bearer tokens from email links. The
// workflow_run / webhook routes carry their own bearer auth and are
// hit by non-browser automation that can't echo X-CSRF-Token.
func csrfPathExempt(path string) bool {
	exemptPrefixes := []string{
		"/api/v1/auth/login",
		"/api/v1/auth/logout",
		"/api/v1/auth/passwords/setup",
		"/api/v1/auth/passwords/setup-tokens",
		"/api/v1/auth/passwords/forgot",
		"/api/v1/auth/passwords/reset",
		"/api/v1/auth/mfa/enroll",
		"/api/v1/auth/mfa/factors/totp/begin",
		"/api/v1/auth/mfa/factors/totp/finish",
		"/api/v1/auth/mfa/factors/webauthn/begin",
		"/api/v1/auth/mfa/factors/webauthn/finish",
		// Third-party flows kick off as top-level navigations; the OAuth
		// state cookie carries CSRF protection for the callback.
		"/api/v1/auth/third-party/",
		// Bearer-token endpoints: workflow-run automation + webhook
		// receivers don't echo our header. They have their own auth.
		"/api/v1/workflow-runs",
		"/api/v1/manifests",
		"/api/v1/events",
		"/api/v1/github/webhook",
		"/api/v1/integration-types/",
		"/api/v1/products/",
		"/api/v1/bootstrap",
		"/api/v1/provision",
		"/api/v1/secrets/materialize-all",
		"/api/v1/oidc/introspect",
		"/api/v1/admin/", // admin-token endpoints (revoke-sessions etc.)
		// Catalog discovery register comes from adapter automation, not
		// the SPA.
		"/api/v1/catalog/discovery/register",
		// Saml endpoints: SP-initiated SSO POST is cross-site by spec.
		"/saml/sso",
		"/saml/slo",
	}
	for _, p := range exemptPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// csrfMiddleware enforces the X-CSRF-Token contract for state-changing
// requests with a valid session. Wraps the auth middleware so claims have
// already been resolved by the time we run.
//
// Algorithm:
//
//  1. If method isn't state-changing → pass.
//  2. If path is exempt → pass.
//  3. If caller has no session (workflow_run_token / unauthenticated) → pass.
//  4. Recompute the expected CSRF token from session_id.
//  5. Compare against `X-CSRF-Token` header (constant-time).
//  6. On mismatch / missing: warn-mode logs + bumps metric; enforce-mode
//     returns 403 Problem+JSON.
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !csrfMethodRequiresToken(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if csrfPathExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		claims, ok := claimsFromContext(r.Context())
		if !ok {
			// No session → no CSRF token to check. Token-authed
			// callers (workflow_run_token) live here too.
			next.ServeHTTP(w, r)
			return
		}
		sessionIDStr, _ := claims["session_id"].(string)
		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			// Defensive: a session without a parseable id is a bug
			// upstream. Don't 403-storm — log and pass.
			if s.logger != nil {
				s.logger.Warn("csrf: session_id in claims not a UUID",
					zap.String("path", r.URL.Path),
					zap.String("session_id", sessionIDStr),
				)
			}
			next.ServeHTTP(w, r)
			return
		}

		expected := computeCSRFToken(sessionID)
		got := strings.TrimSpace(r.Header.Get(csrfHeaderName))

		if got == "" {
			s.csrfFail(w, r, "missing_token", "csrf.missing_token", "CSRF token is required on state-changing requests")
			if csrfEnforceMode() != "enforce" {
				next.ServeHTTP(w, r)
			}
			return
		}
		if !hmac.Equal([]byte(got), []byte(expected)) {
			s.csrfFail(w, r, "token_mismatch", "csrf.token_mismatch", "CSRF token does not match the active session")
			if csrfEnforceMode() != "enforce" {
				next.ServeHTTP(w, r)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfFail logs and bumps the metric for an invalid request. In enforce
// mode the caller writes the 403 response; in warn mode the caller is
// expected to proceed with the request (the log line + metric capture the
// would-have-failed signal).
func (s *Server) csrfFail(w http.ResponseWriter, r *http.Request, outcome string, code string, message string) {
	if s.logger != nil {
		s.logger.Warn("csrf: token validation failed",
			zap.String("mode", csrfEnforceMode()),
			zap.String("outcome", outcome),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
		)
	}
	metrics.IncCSRFRejected(outcome, csrfEnforceMode())
	if csrfEnforceMode() == "enforce" {
		writeProblemJSON(w, http.StatusForbidden, code, message)
	}
}

// writeProblemJSON writes a minimal RFC 7807 Problem+JSON response.
// Reuses the existing writeJSON helper for the body but sets the
// problem+json content type so the SPA's humanizer can route on it.
func writeProblemJSON(w http.ResponseWriter, status int, code string, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{
		"type":   "https://yggdrasil.dakasa.me/problems/" + code,
		"title":  code,
		"status": status,
		"detail": detail,
		"code":   code,
	}
	_ = json.NewEncoder(w).Encode(body)
}
