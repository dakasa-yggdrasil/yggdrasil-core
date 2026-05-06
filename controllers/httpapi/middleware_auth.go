package httpapi

import (
	"context"
	"net/http"
	"strings"
)

// jwtVerifier abstracts JWT validation so the middleware can be unit-tested
// with a fake. The production implementation will wrap the OIDC client
// JWKS-cache verifier (see plan Task 13: dakasa-commons/oidcclient).
type jwtVerifier interface {
	Verify(ctx context.Context, token string) (claims map[string]any, err error)
}

// claimsContextKey is the unexported type used as a context.Context key
// for downstream handlers to retrieve verified JWT claims.
type claimsContextKey struct{}

// contextWithClaims attaches verified claims to ctx for downstream handlers.
func contextWithClaims(ctx context.Context, claims map[string]any) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// claimsFromContext retrieves claims previously attached by bearerOrSession.
// Returns (nil, false) when the request was not authenticated via this
// middleware (e.g. a public endpoint or a still-using-session-cookie route).
func claimsFromContext(ctx context.Context) (map[string]any, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(map[string]any)
	return c, ok
}

// bearerOrSession returns middleware that authenticates a request via a
// JWT in the Authorization Bearer header OR via the session cookie. On
// success, it attaches the verified claims to the request context. On
// failure, it writes a 401 response without invoking the next handler.
//
// The cookie name is read from the same env-driven helper that
// auth.go's writeAuthCookie/extractAuthToken use, so the middleware
// stays consistent with the existing auth surface.
func bearerOrSession(v jwtVerifier) func(http.Handler) http.Handler {
	cookieName := authSessionCookieName()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if claims, ok := tryBearerHeader(r, v); ok {
				next.ServeHTTP(w, r.WithContext(contextWithClaims(r.Context(), claims)))
				return
			}
			if claims, ok := tryCookieToken(r, v, cookieName); ok {
				next.ServeHTTP(w, r.WithContext(contextWithClaims(r.Context(), claims)))
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
}

func tryBearerHeader(r *http.Request, v jwtVerifier) (map[string]any, bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return nil, false
	}
	token := strings.TrimSpace(h[7:])
	if token == "" {
		return nil, false
	}
	claims, err := v.Verify(r.Context(), token)
	if err != nil {
		return nil, false
	}
	return claims, true
}

func tryCookieToken(r *http.Request, v jwtVerifier, cookieName string) (map[string]any, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, false
	}
	token := strings.TrimSpace(c.Value)
	if token == "" {
		return nil, false
	}
	claims, err := v.Verify(r.Context(), token)
	if err != nil {
		return nil, false
	}
	return claims, true
}
