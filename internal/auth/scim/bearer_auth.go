// Package scim implements the read-only side of a SCIM 2.0 Identity Provider.
// External SPs (GitHub Enterprise, AWS Identity Center, Slack, etc.) authenticate
// with a Bearer token issued by `repository.CreateSCIMClient` and consume User
// + Group resources projected from collaborators/teams.
//
// Yggdrasil is the source of truth: PUT/PATCH/DELETE always return 403 to
// preserve the project's zero-drift Crossplane invariant.
package scim

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// ErrUnauthorized is returned when the Authorization header is missing,
// malformed, or matches no active SCIM client. Errors collapse on purpose to
// avoid disclosing whether the bearer was unknown vs revoked.
var ErrUnauthorized = errors.New("scim unauthorized")

// scimClientCtxKey carries the resolved SCIMClient through the request context.
type scimClientCtxKey struct{}

// HashBearer returns the canonical SHA-256 hex of a raw bearer token. Storage
// only persists this hash; the raw value is shown to the operator exactly once.
func HashBearer(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

// BearerAuth is an HTTP middleware that resolves the SCIM client from the
// `Authorization: Bearer <token>` header. On success the *model.SCIMClient is
// attached to the request context (use ClientFromContext). Failures write 401
// with an empty body — never include a hint as to why.
func BearerAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := extractBearer(r.Header.Get("Authorization"))
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			client, err := repository.GetSCIMClientByBearerHash(r.Context(), db, HashBearer(raw))
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), scimClientCtxKey{}, client)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClientFromContext returns the resolved SCIMClient from a request that passed
// BearerAuth. Returns ok=false when called outside an authenticated handler.
func ClientFromContext(ctx context.Context) (model.SCIMClient, bool) {
	c, ok := ctx.Value(scimClientCtxKey{}).(model.SCIMClient)
	return c, ok
}

func extractBearer(header string) (string, bool) {
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}
