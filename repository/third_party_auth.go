package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var (
	ErrThirdPartyIdentityNotFound = errors.New("third-party identity not found")
	ErrThirdPartyIdentityConflict = errors.New("third-party identity conflict")
)

// UpsertThirdPartyIdentity creates or updates one linked external identity for one collaborator.
func UpsertThirdPartyIdentity(
	ctx context.Context,
	db *sql.DB,
	req model.UpsertThirdPartyIdentityRequest,
) (model.ThirdPartyIdentity, model.Collaborator, error) {
	collaborator, err := resolveCollaboratorForLogin(ctx, db, req.CollaboratorID)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	provider := normalizeThirdPartyIdentityProvider(req.Provider)
	subject := normalizeThirdPartyIdentitySubject(req.Subject)
	if provider == "" {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, fmt.Errorf("third-party provider is required")
	}
	if subject == "" {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, fmt.Errorf("third-party subject is required")
	}

	if existing, err := getThirdPartyIdentityByProviderSubject(ctx, db, provider, subject); err == nil {
		if existing.CollaboratorID != collaborator.ID {
			return model.ThirdPartyIdentity{}, model.Collaborator{}, ErrThirdPartyIdentityConflict
		}
	} else if !errors.Is(err, ErrThirdPartyIdentityNotFound) {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	status := normalizeThirdPartyIdentityStatus(req.Status)
	if status == "" {
		status = "active"
	}
	if err := validateThirdPartyIdentityStatus(status); err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	claimsRaw, err := marshalJSONObject(req.Claims)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}
	metadataRaw, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.collaborator_third_party_identities (
				collaborator_id,
				provider,
				subject,
				status,
				login,
				email,
				display_name,
				profile_url,
				avatar_url,
				claims,
				metadata
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6,
				$7,
				$8,
				$9,
				$10::jsonb,
				$11::jsonb
			)
			ON CONFLICT (collaborator_id, provider)
			DO UPDATE SET
				subject = EXCLUDED.subject,
				status = EXCLUDED.status,
				login = EXCLUDED.login,
				email = EXCLUDED.email,
				display_name = EXCLUDED.display_name,
				profile_url = EXCLUDED.profile_url,
				avatar_url = EXCLUDED.avatar_url,
				claims = EXCLUDED.claims,
				metadata = EXCLUDED.metadata,
				updated_at = NOW()
			RETURNING
				id,
				collaborator_id,
				provider,
				subject,
				status,
				login,
				email,
				display_name,
				profile_url,
				avatar_url,
				claims,
				metadata,
				last_authenticated_at,
				created_at,
				updated_at
		`,
		collaborator.ID,
		provider,
		subject,
		status,
		strings.TrimSpace(req.Login),
		strings.ToLower(strings.TrimSpace(req.Email)),
		strings.TrimSpace(req.DisplayName),
		strings.TrimSpace(req.ProfileURL),
		strings.TrimSpace(req.AvatarURL),
		claimsRaw,
		metadataRaw,
	)

	identity, err := scanThirdPartyIdentity(row)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	collaborator, err = syncCollaboratorThirdPartyIdentityProjection(ctx, db, collaborator.ID, identity.Provider, &identity)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	return identity, collaborator, nil
}

// ListThirdPartyIdentities returns linked external identities matching the requested filters.
func ListThirdPartyIdentities(
	ctx context.Context,
	db *sql.DB,
	req model.ListThirdPartyIdentitiesRequest,
) ([]model.ThirdPartyIdentity, error) {
	query := `
		SELECT
			id,
			collaborator_id,
			provider,
			subject,
			status,
			login,
			email,
			display_name,
			profile_url,
			avatar_url,
			claims,
			metadata,
			last_authenticated_at,
			created_at,
			updated_at
		FROM public.collaborator_third_party_identities
	`

	var (
		args    []any
		clauses []string
	)
	if collaboratorID := strings.TrimSpace(req.CollaboratorID); collaboratorID != "" {
		resolvedID, err := resolveCollaboratorIdentityID(ctx, db, collaboratorID)
		if err != nil {
			return nil, err
		}
		args = append(args, resolvedID)
		clauses = append(clauses, fmt.Sprintf("collaborator_id = $%d", len(args)))
	}
	if provider := normalizeThirdPartyIdentityProvider(req.Provider); provider != "" {
		args = append(args, provider)
		clauses = append(clauses, fmt.Sprintf("provider = $%d", len(args)))
	}
	if status := normalizeThirdPartyIdentityStatus(req.Status); status != "" {
		if err := validateThirdPartyIdentityStatus(status); err != nil {
			return nil, err
		}
		args = append(args, status)
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY provider, created_at"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]model.ThirdPartyIdentity, 0)
	for rows.Next() {
		item, err := scanThirdPartyIdentity(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// DeleteThirdPartyIdentity removes one linked external identity and clears the collaborator projection.
func DeleteThirdPartyIdentity(
	ctx context.Context,
	db *sql.DB,
	req model.DeleteThirdPartyIdentityRequest,
) (model.ThirdPartyIdentity, model.Collaborator, error) {
	identity, err := getThirdPartyIdentityByProviderSubject(ctx, db, req.Provider, req.Subject)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM public.collaborator_third_party_identities WHERE id = $1`,
		identity.ID,
	); err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	collaborator, err := syncCollaboratorThirdPartyIdentityProjection(ctx, db, identity.CollaboratorID, identity.Provider, nil)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	return identity, collaborator, nil
}

// AuthenticateWithThirdPartyIdentity validates one externally verified identity and opens a new session.
func AuthenticateWithThirdPartyIdentity(
	ctx context.Context,
	db *sql.DB,
	req model.LoginWithThirdPartyIdentityRequest,
	ttl time.Duration,
) (model.Collaborator, model.ThirdPartyIdentity, model.AuthSession, string, error) {
	provider := normalizeThirdPartyIdentityProvider(req.Provider)
	subject := normalizeThirdPartyIdentitySubject(req.Subject)
	if provider == "" {
		return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", fmt.Errorf("third-party provider is required")
	}
	if subject == "" {
		return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", fmt.Errorf("third-party subject is required")
	}

	identity, err := getThirdPartyIdentityByProviderSubject(ctx, db, provider, subject)
	if err != nil {
		if !errors.Is(err, ErrThirdPartyIdentityNotFound) || !req.AutoLinkByEmail {
			if errors.Is(err, ErrThirdPartyIdentityNotFound) {
				return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
			}
			return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", err
		}

		email := strings.ToLower(strings.TrimSpace(req.Email))
		if email == "" {
			return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
		}
		collaborator, err := getCollaboratorByPrimaryEmail(ctx, db, email)
		if err != nil {
			if errors.Is(err, ErrCollaboratorNotFound) {
				return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
			}
			return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", err
		}
		if strings.ToLower(strings.TrimSpace(collaborator.Status)) != "active" {
			return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
		}

		identity, collaborator, err = UpsertThirdPartyIdentity(ctx, db, model.UpsertThirdPartyIdentityRequest{
			CollaboratorID: collaborator.ID.String(),
			Provider:       provider,
			Subject:        subject,
			Status:         "active",
			Login:          req.Login,
			Email:          email,
			DisplayName:    req.DisplayName,
			ProfileURL:     req.ProfileURL,
			AvatarURL:      req.AvatarURL,
			Claims:         req.Claims,
		})
		if err != nil {
			if errors.Is(err, ErrThirdPartyIdentityConflict) {
				return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
			}
			return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", err
		}

		return createThirdPartyAuthSession(ctx, db, collaborator, identity, req.SessionMetadata, ttl)
	}

	if strings.ToLower(strings.TrimSpace(identity.Status)) != "active" {
		return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
	}

	collaborator, err := GetCollaborator(ctx, db, identity.CollaboratorID.String())
	if err != nil {
		if errors.Is(err, ErrCollaboratorNotFound) {
			return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
		}
		return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", err
	}
	if strings.ToLower(strings.TrimSpace(collaborator.Status)) != "active" {
		return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
	}

	identity, collaborator, err = recordThirdPartyIdentityAuthentication(ctx, db, collaborator, identity, req)
	if err != nil {
		return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", err
	}

	return createThirdPartyAuthSession(ctx, db, collaborator, identity, req.SessionMetadata, ttl)
}

func createThirdPartyAuthSession(
	ctx context.Context,
	db *sql.DB,
	collaborator model.Collaborator,
	identity model.ThirdPartyIdentity,
	sessionMetadata map[string]any,
	ttl time.Duration,
) (model.Collaborator, model.ThirdPartyIdentity, model.AuthSession, string, error) {
	metadata := cloneJSONObject(sessionMetadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["auth_method"] = "third_party"
	metadata["provider"] = identity.Provider
	metadata["third_party_identity"] = map[string]any{
		"id":       identity.ID.String(),
		"provider": identity.Provider,
		"subject":  identity.Subject,
		"login":    identity.Login,
	}

	session, token, err := createAuthSession(ctx, db, collaborator.ID, metadata, ttl)
	if err != nil {
		return model.Collaborator{}, model.ThirdPartyIdentity{}, model.AuthSession{}, "", err
	}

	return collaborator, identity, session, token, nil
}

func getThirdPartyIdentityByProviderSubject(
	ctx context.Context,
	db *sql.DB,
	provider string,
	subject string,
) (model.ThirdPartyIdentity, error) {
	provider = normalizeThirdPartyIdentityProvider(provider)
	subject = normalizeThirdPartyIdentitySubject(subject)
	if provider == "" {
		return model.ThirdPartyIdentity{}, fmt.Errorf("third-party provider is required")
	}
	if subject == "" {
		return model.ThirdPartyIdentity{}, fmt.Errorf("third-party subject is required")
	}

	row := db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				collaborator_id,
				provider,
				subject,
				status,
				login,
				email,
				display_name,
				profile_url,
				avatar_url,
				claims,
				metadata,
				last_authenticated_at,
				created_at,
				updated_at
			FROM public.collaborator_third_party_identities
			WHERE provider = $1
				AND subject = $2
			ORDER BY created_at DESC
			LIMIT 1
		`,
		provider,
		subject,
	)

	identity, err := scanThirdPartyIdentity(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ThirdPartyIdentity{}, ErrThirdPartyIdentityNotFound
		}
		return model.ThirdPartyIdentity{}, err
	}
	return identity, nil
}

func recordThirdPartyIdentityAuthentication(
	ctx context.Context,
	db *sql.DB,
	collaborator model.Collaborator,
	current model.ThirdPartyIdentity,
	req model.LoginWithThirdPartyIdentityRequest,
) (model.ThirdPartyIdentity, model.Collaborator, error) {
	claims := current.Claims
	if req.Claims != nil {
		claims = cloneJSONObject(req.Claims)
	}
	claimsRaw, err := marshalJSONObject(claims)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}

	login := strings.TrimSpace(req.Login)
	if login == "" {
		login = current.Login
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		email = current.Email
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = current.DisplayName
	}
	profileURL := strings.TrimSpace(req.ProfileURL)
	if profileURL == "" {
		profileURL = current.ProfileURL
	}
	avatarURL := strings.TrimSpace(req.AvatarURL)
	if avatarURL == "" {
		avatarURL = current.AvatarURL
	}

	now := time.Now().UTC()
	row := db.QueryRowContext(
		ctx,
		`
			UPDATE public.collaborator_third_party_identities
			SET
				login = $2,
				email = $3,
				display_name = $4,
				profile_url = $5,
				avatar_url = $6,
				claims = $7::jsonb,
				last_authenticated_at = $8,
				updated_at = NOW()
			WHERE id = $1
			RETURNING
				id,
				collaborator_id,
				provider,
				subject,
				status,
				login,
				email,
				display_name,
				profile_url,
				avatar_url,
				claims,
				metadata,
				last_authenticated_at,
				created_at,
				updated_at
		`,
		current.ID,
		login,
		email,
		displayName,
		profileURL,
		avatarURL,
		claimsRaw,
		now,
	)

	identity, err := scanThirdPartyIdentity(row)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}
	collaborator, err = syncCollaboratorThirdPartyIdentityProjection(ctx, db, collaborator.ID, identity.Provider, &identity)
	if err != nil {
		return model.ThirdPartyIdentity{}, model.Collaborator{}, err
	}
	return identity, collaborator, nil
}

func syncCollaboratorThirdPartyIdentityProjection(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
	provider string,
	identity *model.ThirdPartyIdentity,
) (model.Collaborator, error) {
	collaborator, err := GetCollaborator(ctx, db, collaboratorID.String())
	if err != nil {
		return model.Collaborator{}, err
	}

	projection := cloneJSONObject(collaborator.ThirdPartyIdentities)
	if projection == nil {
		projection = map[string]any{}
	}
	if identity == nil {
		delete(projection, provider)
	} else {
		projection[provider] = buildThirdPartyIdentityProjection(*identity)
	}

	projectionRaw, err := marshalJSONObject(projection)
	if err != nil {
		return model.Collaborator{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			UPDATE public.collaborators
			SET third_party_identities = $2::jsonb
			WHERE id = $1
			RETURNING
				id,
				slug,
				status,
				display_name,
				primary_email,
				manager_id,
				primary_team_id,
				personal_data,
				employment_data,
				third_party_identities,
				traits,
				metadata,
				created_at,
				updated_at
		`,
		collaborator.ID,
		projectionRaw,
	)
	return scanCollaborator(row)
}

func buildThirdPartyIdentityProjection(identity model.ThirdPartyIdentity) map[string]any {
	output := map[string]any{
		"id":       identity.ID.String(),
		"provider": identity.Provider,
		"subject":  identity.Subject,
		"status":   identity.Status,
	}
	if identity.Login != "" {
		output["login"] = identity.Login
	}
	if identity.Email != "" {
		output["email"] = identity.Email
	}
	if identity.DisplayName != "" {
		output["display_name"] = identity.DisplayName
	}
	if identity.ProfileURL != "" {
		output["profile_url"] = identity.ProfileURL
	}
	if identity.AvatarURL != "" {
		output["avatar_url"] = identity.AvatarURL
	}
	if identity.LastAuthenticatedAt != nil {
		output["last_authenticated_at"] = identity.LastAuthenticatedAt.UTC()
	}
	output["linked_at"] = identity.CreatedAt.UTC()
	return output
}

func scanThirdPartyIdentity(row scanner) (model.ThirdPartyIdentity, error) {
	var (
		identity              model.ThirdPartyIdentity
		claimsRaw             []byte
		metadataRaw           []byte
		lastAuthenticatedTime sql.NullTime
	)

	if err := row.Scan(
		&identity.ID,
		&identity.CollaboratorID,
		&identity.Provider,
		&identity.Subject,
		&identity.Status,
		&identity.Login,
		&identity.Email,
		&identity.DisplayName,
		&identity.ProfileURL,
		&identity.AvatarURL,
		&claimsRaw,
		&metadataRaw,
		&lastAuthenticatedTime,
		&identity.CreatedAt,
		&identity.UpdatedAt,
	); err != nil {
		return model.ThirdPartyIdentity{}, err
	}

	claims, err := unmarshalJSONObject(claimsRaw)
	if err != nil {
		return model.ThirdPartyIdentity{}, err
	}
	metadata, err := unmarshalJSONObject(metadataRaw)
	if err != nil {
		return model.ThirdPartyIdentity{}, err
	}
	identity.Claims = claims
	identity.Metadata = metadata
	if lastAuthenticatedTime.Valid {
		value := lastAuthenticatedTime.Time.UTC()
		identity.LastAuthenticatedAt = &value
	}
	return identity, nil
}

func normalizeThirdPartyIdentityProvider(value string) string {
	return normalizeSlug(value)
}

func normalizeThirdPartyIdentitySubject(value string) string {
	return strings.TrimSpace(value)
}

func normalizeThirdPartyIdentityStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validateThirdPartyIdentityStatus(value string) error {
	switch normalizeThirdPartyIdentityStatus(value) {
	case "active", "disabled":
		return nil
	default:
		return fmt.Errorf("third-party identity status %q is unsupported", value)
	}
}
