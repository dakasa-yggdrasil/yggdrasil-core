package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

var errAuthAdminUnauthorized = errors.New("auth admin unauthorized")

// authorizeAuthAdminRequest authorizes admin/break-glass endpoints
// (POST /api/v1/auth/passwords, setup-tokens, mfa enroll-link, admin
// session revoke, admin oidc-clients). It accepts a request via either:
//
//   - a console identity (claims attached by the middleware, OR a session
//     cookie we resolve ourselves on paths outside the middleware
//     allowlist) whose collaborator holds a REAL admin capability
//     (yggdrasil:manage_organization or the yggdrasil:* god-mode grant /
//     traits.yggdrasil_admin) — a plain authenticated session is NOT
//     admin; every logged-in collaborator carries claims/a session, so
//     accepting bare authentication here was a full account-takeover hole
//     (a low-priv user could mint a victim setup token); or
//   - the static machine admin token (YGGDRASIL_AUTH_ADMIN_TOKEN) sent as a
//     header — used by external workflows and bootstrap scripts that don't
//     carry a session. The broadly-distributed YGGDRASIL_WORKFLOW_RUN_TOKEN
//     is intentionally NOT accepted here.
//
// db may be nil (older test paths); when nil, the capability paths are
// skipped and authorization only succeeds via the static admin-token header.
func authorizeAuthAdminRequest(r *http.Request, db *sql.DB) error {
	ctx := r.Context()

	// Path 1: claims attached by the console auth middleware. Require a REAL
	// admin capability — presence of claims only proves authentication, not
	// authorization. Fail closed when the capability cannot be resolved.
	if claims, ok := claimsFromContext(ctx); ok && db != nil {
		if id := claimsCollaboratorUUID(claims); id != uuid.Nil {
			if held, err := collaboratorHoldsAuthAdmin(ctx, db, id); err == nil && held {
				return nil
			}
		}
	}

	// Path 2: a resolvable console session whose collaborator holds admin
	// capability. The break-glass routes (setup-tokens/setup, admin
	// oidc-clients, mfa enroll-link, admin session revoke) sit OUTSIDE the
	// console middleware allowlist, so claims are not attached upfront and we
	// resolve the session token here.
	if db != nil {
		if token, has := extractAuthToken(r); has {
			if _, collab, err := repository.ResolveAuthSession(ctx, db, token); err == nil {
				if held, err := collaboratorHoldsAuthAdmin(ctx, db, collab.ID); err == nil && held {
					return nil
				}
			}
		}
	}

	// Path 3: static machine admin token. Only the dedicated
	// YGGDRASIL_AUTH_ADMIN_TOKEN authorizes; workflow credentials must never act
	// as auth-admin.
	if requestHasStaticAuthAdminCredential(r) {
		return nil
	}

	return errAuthAdminUnauthorized
}

// requestHasStaticAuthAdminCredential isolates the purpose-built non-human
// auth-admin path from session authorization. The outer console gate uses this
// narrower predicate so an administrator's cookie still travels through the
// normal MFA, CSRF, claims, and RBAC pipeline instead of inheriting the
// no-claims machine bypass.
func requestHasStaticAuthAdminCredential(r *http.Request) bool {
	expected := strings.TrimSpace(os.Getenv("YGGDRASIL_AUTH_ADMIN_TOKEN"))
	if expected == "" {
		return false
	}
	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Yggdrasil-Auth-Admin-Token")),
		bearerToken(r.Header.Get("Authorization")),
	}
	for _, candidate := range candidates {
		if candidate != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

// claimsCollaboratorUUID pulls the collaborator UUID out of a claims map,
// accepting either the "collaborator_id" key (session path) or "sub" (OP
// JWT path). Returns uuid.Nil when neither is a parseable UUID.
func claimsCollaboratorUUID(claims map[string]any) uuid.UUID {
	for _, key := range []string{"collaborator_id", "sub"} {
		if raw, ok := claims[key].(string); ok {
			if id, err := uuid.Parse(strings.TrimSpace(raw)); err == nil {
				return id
			}
		}
	}
	return uuid.Nil
}

// collaboratorHoldsAuthAdmin reports whether the collaborator holds a real
// admin capability for the break-glass auth endpoints: the
// yggdrasil:manage_organization permission, or the yggdrasil:* god-mode
// grant (which ResolveYggdrasilPermissions also emits for
// traits.yggdrasil_admin=true). Mirrors collaboratorHasOpsPermission but is
// a free function so the db-only authorizeAuthAdminRequest can call it.
func collaboratorHoldsAuthAdmin(ctx context.Context, db *sql.DB, collabID uuid.UUID) (bool, error) {
	var traits map[string]any
	if collab, err := repository.GetCollaborator(ctx, db, collabID.String()); err == nil {
		traits = collab.Traits
	}
	perms, err := repository.ResolveYggdrasilPermissions(ctx, db, collabID, traits)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == permManageOrganization || p == repository.YggdrasilGodModeAction {
			return true, nil
		}
	}
	return false, nil
}
