package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// errAutoProvisionRejected is the sentinel that httpStatusFromError matches
// to map auto-provision rejections to HTTP 403. It is never returned directly;
// callers wrap a reason in *provisionRejectedError, which satisfies
// errors.Is(err, errAutoProvisionRejected).
var errAutoProvisionRejected = errors.New("auto_provision rejected")

// provisionRejectedError wraps a rejection reason while signalling 403 to the
// response mapper via the errAutoProvisionRejected sentinel.
type provisionRejectedError struct {
	Reason string
	inner  error // optional underlying cause (currently unused)
}

func (e *provisionRejectedError) Error() string {
	if e == nil {
		return ""
	}
	return e.Reason
}

func (e *provisionRejectedError) Unwrap() error { return e.inner }

func (e *provisionRejectedError) Is(target error) bool {
	return target == errAutoProvisionRejected
}

// provisionCollaboratorFromClaim ensures a collaborator exists for the given
// (claim email, display_name) pair before the third-party callback hands off
// to repository.AuthenticateWithThirdPartyIdentity.
//
// Algorithm (matches spec §5.1):
//  1. Normalise email (lowercase + trim). Reject empty.
//  2. Look up collaborator by primary_email — EXISTING USER short-circuit, no
//     gates applied. This is critical because providers like GitHub do not
//     send an email_verified claim; rejecting existing users on that gate
//     would break every returning login.
//  3. NEW USER PATH ONLY: apply emailVerified, AutoProvision, and domain
//     gates. Each rejection wraps in *provisionRejectedError so the HTTP
//     layer maps it to 403 (spec §7.1).
//  4. Atomically insert the collaborator + a default-team membership.
//     On unique-constraint violation (concurrent INSERT race), rollback
//     and re-fetch the row that won the race.
//
// On success the existing third-party flow continues unchanged: the email
// match in AuthenticateWithThirdPartyIdentity will resolve the new row when
// AutoLinkByEmail is enabled on the provider.
func provisionCollaboratorFromClaim(ctx context.Context, db *sql.DB, email, displayName string, emailVerified bool) (model.Collaborator, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return model.Collaborator{}, &provisionRejectedError{Reason: "email empty in claim"}
	}

	settings, err := repository.GetOIDCProviderSettings(ctx, db)
	if err != nil {
		return model.Collaborator{}, err
	}

	// Existing user short-circuit — no gates applied.
	collab, err := repository.GetCollaboratorByPrimaryEmail(ctx, db, email)
	if err == nil {
		return collab, nil
	}
	if !errors.Is(err, repository.ErrCollaboratorNotFound) {
		return model.Collaborator{}, err
	}

	// NEW USER PATH — apply all gates here, only when we'd actually create a row.
	if !emailVerified {
		return model.Collaborator{}, &provisionRejectedError{Reason: "email not verified by provider"}
	}
	if !settings.AutoProvision {
		return model.Collaborator{}, &provisionRejectedError{Reason: "collaborator does not exist and auto_provision is disabled"}
	}
	if !domainAllowed(email, settings.AllowedEmailDomains) {
		return model.Collaborator{}, &provisionRejectedError{Reason: fmt.Sprintf("email domain not allowed: %s", email)}
	}

	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		if at := strings.LastIndex(email, "@"); at > 0 {
			displayName = email[:at]
		} else {
			// Defensive — email validation above should make this unreachable.
			displayName = email
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return model.Collaborator{}, err
	}
	defer func() { _ = tx.Rollback() }()

	created, err := repository.CreateCollaboratorTx(ctx, tx, model.CreateCollaboratorRequest{
		Slug:         uuid.NewString(),
		Status:       "active",
		DisplayName:  displayName,
		PrimaryEmail: email,
	})
	if err != nil {
		// Recover from the concurrent-INSERT race: another callback for the
		// same email won the partial unique index on LOWER(primary_email)
		// (migration 00006). Roll the doomed tx back and re-fetch via db.
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			_ = tx.Rollback()
			existing, err2 := repository.GetCollaboratorByPrimaryEmail(ctx, db, email)
			if err2 == nil {
				return existing, nil
			}
			return model.Collaborator{}, fmt.Errorf("provision race recovery failed: %w", err2)
		}
		return model.Collaborator{}, err
	}
	if err := repository.AddCollaboratorToTeamBySlugTx(ctx, tx, created.ID, settings.DefaultTeamSlug, "auto_provision"); err != nil {
		return model.Collaborator{}, err
	}
	// TODO(phase-2-audit): emit an oidc_audit_events row for
	// "collaborator.auto_provisioned" per spec §5.1.3d. The audit table is
	// not yet in migrations; tracked in plan as a Phase 2 task.
	if err := tx.Commit(); err != nil {
		return model.Collaborator{}, err
	}

	return created, nil
}

// domainAllowed reports whether the email's domain (case-insensitive) is
// present in the allowed list. An empty allowed list disallows everything.
func domainAllowed(email string, allowed []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == domain {
			return true
		}
	}
	return false
}
