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
)

// provisionCollaboratorFromClaim ensures a collaborator exists for the given
// (claim email, display_name) pair before the third-party callback hands off
// to repository.AuthenticateWithThirdPartyIdentity.
//
// Behaviour:
//   - Reject when emailVerified is false (Google OAuth: "email_verified" claim).
//   - Return the existing collaborator when one is found by primary_email.
//   - When auto_provision is enabled AND the email's domain is in
//     allowed_email_domains, create the collaborator and add a default-team
//     membership atomically (single transaction).
//   - Otherwise return an error.
//
// On success the existing third-party flow continues unchanged: the email
// match in AuthenticateWithThirdPartyIdentity will resolve the new row when
// AutoLinkByEmail is enabled on the provider.
func provisionCollaboratorFromClaim(ctx context.Context, db *sql.DB, email, displayName string, emailVerified bool) (model.Collaborator, error) {
	if !emailVerified {
		return model.Collaborator{}, errors.New("email not verified by provider")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return model.Collaborator{}, errors.New("email empty in claim")
	}

	settings, err := repository.GetOIDCProviderSettings(ctx, db)
	if err != nil {
		return model.Collaborator{}, err
	}

	collab, err := repository.GetCollaboratorByPrimaryEmail(ctx, db, email)
	if err == nil {
		return collab, nil
	}
	if !errors.Is(err, repository.ErrCollaboratorNotFound) {
		return model.Collaborator{}, err
	}

	if !settings.AutoProvision {
		return model.Collaborator{}, errors.New("collaborator does not exist and auto_provision is disabled")
	}
	if !domainAllowed(email, settings.AllowedEmailDomains) {
		return model.Collaborator{}, fmt.Errorf("email domain not allowed: %s", email)
	}

	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = email
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
		return model.Collaborator{}, err
	}
	if err := repository.AddCollaboratorToTeamBySlugTx(ctx, tx, created.ID, settings.DefaultTeamSlug, "auto_provision"); err != nil {
		return model.Collaborator{}, err
	}
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
