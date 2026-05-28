package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAuthSessionCookieSameSite_DefaultsStrict locks down the security audit
// 2026-05-27 A6 fix: when AUTH_SESSION_COOKIE_SAMESITE is unset, the cookie
// MUST be issued with SameSite=Strict. The previous default Lax allowed
// top-level cross-site requests (e.g. a phishing-site form POST) to carry
// the cookie — narrow but real CSRF surface for an admin IDP.
func TestAuthSessionCookieSameSite_DefaultsStrict(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "")
	if got := authSessionCookieSameSite(); got != http.SameSiteStrictMode {
		t.Fatalf("default AUTH_SESSION_COOKIE_SAMESITE: expected Strict, got %v", got)
	}
}

// TestAuthSessionCookieSameSite_RespectsExplicitStrict: production stays
// strict with the explicit setting too.
func TestAuthSessionCookieSameSite_RespectsExplicitStrict(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "Strict")
	if got := authSessionCookieSameSite(); got != http.SameSiteStrictMode {
		t.Fatalf("AUTH_SESSION_COOKIE_SAMESITE=Strict: expected Strict, got %v", got)
	}
}

// TestAuthSessionCookieSameSite_RespectsExplicitLax: operators who need Lax
// for a federated host can opt in explicitly.
func TestAuthSessionCookieSameSite_RespectsExplicitLax(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "Lax")
	if got := authSessionCookieSameSite(); got != http.SameSiteLaxMode {
		t.Fatalf("AUTH_SESSION_COOKIE_SAMESITE=Lax: expected Lax, got %v", got)
	}
}

// TestAuthSessionCookieSameSite_RespectsExplicitNone: None is permitted
// (cross-origin scenarios with explicit Secure=true), discouraged but valid.
func TestAuthSessionCookieSameSite_RespectsExplicitNone(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "None")
	if got := authSessionCookieSameSite(); got != http.SameSiteNoneMode {
		t.Fatalf("AUTH_SESSION_COOKIE_SAMESITE=None: expected None, got %v", got)
	}
}

// TestAuthSessionCookieSameSite_GarbageDefaultsStrict: unparseable values
// fall back to the secure default rather than the unsafe one — fail-closed.
func TestAuthSessionCookieSameSite_GarbageDefaultsStrict(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "garbage")
	if got := authSessionCookieSameSite(); got != http.SameSiteStrictMode {
		t.Fatalf("AUTH_SESSION_COOKIE_SAMESITE=garbage: expected Strict (fail-closed), got %v", got)
	}
}

// TestAuthSessionCookieSameSite_CaseInsensitive: env values are matched
// case-insensitively so operators don't trip on capitalization typos.
func TestAuthSessionCookieSameSite_CaseInsensitive(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "lax")
	if got := authSessionCookieSameSite(); got != http.SameSiteLaxMode {
		t.Fatalf("AUTH_SESSION_COOKIE_SAMESITE=lax: expected Lax, got %v", got)
	}
}

// TestWriteAuthCookie_EmitsSameSiteStrictHeader proves the end-to-end wire
// behavior: writeAuthCookie applied to a ResponseWriter emits a Set-Cookie
// header whose SameSite attribute is Strict by default. This is the
// production smoke test in test form — production curl will see the same
// header value.
func TestWriteAuthCookie_EmitsSameSiteStrictHeader(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "")
	w := httptest.NewRecorder()
	writeAuthCookie(w, "token-abc", time.Now().Add(time.Hour))
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie SameSite: expected Strict, got %v", cookies[0].SameSite)
	}
	// Also assert the raw Set-Cookie header — that's what curl sees.
	if header := strings.Join(w.Header().Values("Set-Cookie"), ""); !strings.Contains(header, "SameSite=Strict") {
		t.Fatalf("Set-Cookie header missing SameSite=Strict: %q", header)
	}
}

// TestClearAuthCookie_EmitsSameSiteStrictHeader: the logout path also emits
// the same SameSite value so the browser doesn't reject the deletion (a
// SameSite mismatch on the clear-cookie would silently leave the previous
// cookie installed in some browsers).
func TestClearAuthCookie_EmitsSameSiteStrictHeader(t *testing.T) {
	t.Setenv("AUTH_SESSION_COOKIE_SAMESITE", "")
	w := httptest.NewRecorder()
	clearAuthCookie(w)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("clear cookie SameSite: expected Strict, got %v", cookies[0].SameSite)
	}
}
