package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// requirePasswordValid wraps next and short-circuits with 401/403 when:
//   - session resolution fails (401)
//   - mfa_enrolled_at is NULL (403 mfa_enrollment_required)
//   - password_must_change OR password_expires_at < NOW() (403 password_change_required)
//
// Allowlisted paths skip all checks (handlers that must remain reachable while
// the collaborator is in a locked state, e.g. the enroll / change-password
// endpoints themselves).
func (s *Server) requirePasswordValid(allowlist []string, next http.HandlerFunc) http.HandlerFunc {
	allow := make(map[string]struct{}, len(allowlist))
	for _, p := range allowlist {
		allow[p] = struct{}{}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Allowlisted paths bypass all checks — these are the escape hatches the
		// collaborator needs while in a locked/unenrolled state.
		if _, ok := allow[r.URL.Path]; ok {
			next(w, r)
			return
		}

		token, ok := extractAuthToken(r)
		if !ok {
			httperr.WriteProblem(w, http.StatusUnauthorized,
				httperr.CodeAuthUnauthenticated,
				"Unauthenticated",
				"a valid session token is required",
				httperr.WithInstance(r.URL.Path))
			return
		}

		_, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
		if err != nil {
			httperr.WriteProblem(w, http.StatusUnauthorized,
				httperr.CodeAuthUnauthenticated,
				"Unauthenticated",
				"the provided session token is invalid or expired",
				httperr.WithInstance(r.URL.Path))
			return
		}

		// Load the auth_identity to check MFA enrollment status.
		identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, collaborator.ID)
		if err != nil {
			writeMappedError(w, err)
			return
		}

		if identity.MFAEnrolledAt == nil {
			httperr.WriteProblem(w, http.StatusForbidden,
				httperr.CodeAuthMFANotEnrolled,
				"MFA enrollment required",
				"a second factor must be enrolled before accessing this resource",
				httperr.WithInstance(r.URL.Path),
				httperr.WithExtra("enroll_url", "/api/v1/auth/mfa/enroll"))
			return
		}

		// Load password credential state separately — GetAuthIdentityByCollaboratorID
		// does not scan password columns (they live in a different query path).
		pwState, err := repository.GetPasswordCredentialState(r.Context(), s.db, collaborator.ID)
		if err != nil && !errors.Is(err, repository.ErrPasswordCredentialNotFound) {
			writeMappedError(w, err)
			return
		}

		// ErrPasswordCredentialNotFound means the collaborator has no password row
		// (e.g. SSO-only accounts).  Skip the password checks in that case.
		if !errors.Is(err, repository.ErrPasswordCredentialNotFound) {
			expired := pwState.PasswordExpiresAt != nil && pwState.PasswordExpiresAt.Before(time.Now())
			if pwState.PasswordMustChange || expired {
				reason := "rotation_expired"
				if pwState.PasswordMustChange && !expired {
					reason = "admin_forced"
				}
				httperr.WriteProblem(w, http.StatusForbidden,
					httperr.CodeAuthPasswordChangeRequired,
					"Password change required",
					"the current password must be changed before continuing",
					httperr.WithInstance(r.URL.Path),
					httperr.WithExtra("change_url", "/api/v1/auth/passwords/change"),
					httperr.WithExtra("reason", reason))
				return
			}
		}

		next(w, r)
	}
}
