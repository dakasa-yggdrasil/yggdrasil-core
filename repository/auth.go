package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreauth"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var (
	ErrPasswordCredentialNotFound = errors.New("password credential not found")
	ErrAuthInvalidCredentials     = errors.New("invalid credentials")
	ErrAuthSessionNotFound        = errors.New("auth session not found")
	ErrAuthSessionExpired         = errors.New("auth session expired")
)

// UpsertPasswordCredential creates or updates one local password credential for an existing collaborator.
func UpsertPasswordCredential(
	ctx context.Context,
	db *sql.DB,
	req model.UpsertPasswordCredentialRequest,
) (model.PasswordCredential, model.Collaborator, error) {
	collaborator, err := resolveCollaboratorForLogin(ctx, db, req.CollaboratorID)
	if err != nil {
		return model.PasswordCredential{}, model.Collaborator{}, err
	}

	passwordHash, err := coreauth.HashPassword(req.Password)
	if err != nil {
		return model.PasswordCredential{}, model.Collaborator{}, err
	}

	metadata, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.PasswordCredential{}, model.Collaborator{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.collaborator_password_credentials (
				collaborator_id,
				status,
				password_scheme,
				password_hash,
				metadata,
				password_updated_at
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5::jsonb,
				NOW()
			)
			ON CONFLICT (collaborator_id)
			DO UPDATE SET
				status = EXCLUDED.status,
				password_scheme = EXCLUDED.password_scheme,
				password_hash = EXCLUDED.password_hash,
				metadata = EXCLUDED.metadata,
				password_updated_at = NOW(),
				updated_at = NOW()
			RETURNING
				collaborator_id,
				status,
				password_scheme,
				metadata,
				password_updated_at,
				created_at,
				updated_at
		`,
		collaborator.ID,
		normalizeAuthStatus(req.Status),
		"pbkdf2_sha256",
		passwordHash,
		metadata,
	)

	credential, err := scanPasswordCredential(row)
	if err != nil {
		return model.PasswordCredential{}, model.Collaborator{}, err
	}

	return credential, collaborator, nil
}

// AuthenticateWithPassword validates one login and opens a new session.
func AuthenticateWithPassword(
	ctx context.Context,
	db *sql.DB,
	req model.LoginWithPasswordRequest,
	ttl time.Duration,
) (model.Collaborator, model.AuthSession, string, error) {
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		return model.Collaborator{}, model.AuthSession{}, "", fmt.Errorf("identifier is required")
	}
	if strings.TrimSpace(req.Password) == "" {
		return model.Collaborator{}, model.AuthSession{}, "", fmt.Errorf("password is required")
	}

	collaborator, err := resolveCollaboratorForLogin(ctx, db, identifier)
	if err != nil {
		if errors.Is(err, ErrCollaboratorNotFound) {
			return model.Collaborator{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
		}
		return model.Collaborator{}, model.AuthSession{}, "", err
	}
	if strings.ToLower(strings.TrimSpace(collaborator.Status)) != "active" {
		return model.Collaborator{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
	}

	credential, passwordHash, err := getPasswordCredentialRow(ctx, db, collaborator.ID)
	if err != nil {
		if errors.Is(err, ErrPasswordCredentialNotFound) {
			return model.Collaborator{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
		}
		return model.Collaborator{}, model.AuthSession{}, "", err
	}
	if strings.ToLower(strings.TrimSpace(credential.Status)) != "active" {
		return model.Collaborator{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
	}

	valid, err := coreauth.VerifyPassword(passwordHash, req.Password)
	if err != nil {
		return model.Collaborator{}, model.AuthSession{}, "", err
	}
	if !valid {
		return model.Collaborator{}, model.AuthSession{}, "", ErrAuthInvalidCredentials
	}

	session, token, err := createAuthSession(ctx, db, collaborator.ID, req.Metadata, ttl)
	if err != nil {
		return model.Collaborator{}, model.AuthSession{}, "", err
	}

	return collaborator, session, token, nil
}

// ResolveAuthSession returns one active session and its collaborator from a raw token.
func ResolveAuthSession(
	ctx context.Context,
	db *sql.DB,
	token string,
) (model.AuthSession, model.Collaborator, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return model.AuthSession{}, model.Collaborator{}, ErrAuthSessionNotFound
	}

	session, err := getAuthSessionByTokenHash(ctx, db, coreauth.HashSessionToken(token))
	if err != nil {
		return model.AuthSession{}, model.Collaborator{}, err
	}

	if strings.ToLower(strings.TrimSpace(session.Status)) != "active" {
		return model.AuthSession{}, model.Collaborator{}, ErrAuthSessionNotFound
	}
	if time.Now().After(session.ExpiresAt) {
		_, _ = db.ExecContext(
			ctx,
			`UPDATE public.auth_sessions SET status = 'expired', updated_at = NOW() WHERE id = $1`,
			session.ID,
		)
		return model.AuthSession{}, model.Collaborator{}, ErrAuthSessionExpired
	}

	now := time.Now().UTC()
	if _, err := db.ExecContext(
		ctx,
		`UPDATE public.auth_sessions SET last_seen_at = $2, updated_at = NOW() WHERE id = $1`,
		session.ID,
		now,
	); err == nil {
		session.LastSeenAt = &now
		session.UpdatedAt = now
	}

	collaborator, err := GetCollaborator(ctx, db, session.CollaboratorID.String())
	if err != nil {
		return model.AuthSession{}, model.Collaborator{}, err
	}

	return session, collaborator, nil
}

// RevokeAuthSession revokes one active session token.
func RevokeAuthSession(ctx context.Context, db *sql.DB, token string) (model.AuthSession, error) {
	session, err := getAuthSessionByTokenHash(ctx, db, coreauth.HashSessionToken(strings.TrimSpace(token)))
	if err != nil {
		return model.AuthSession{}, err
	}

	now := time.Now().UTC()
	row := db.QueryRowContext(
		ctx,
		`
			UPDATE public.auth_sessions
			SET
				status = 'revoked',
				revoked_at = $2,
				updated_at = NOW()
			WHERE id = $1
			RETURNING
				id,
				collaborator_id,
				status,
				metadata,
				last_seen_at,
				expires_at,
				revoked_at,
				created_at,
				updated_at
		`,
		session.ID,
		now,
	)

	return scanAuthSession(row)
}

func resolveCollaboratorForLogin(ctx context.Context, db *sql.DB, identity string) (model.Collaborator, error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator identity is required")
	}

	if strings.Contains(identity, "@") {
		return GetCollaboratorByPrimaryEmail(ctx, db, identity)
	}

	return GetCollaborator(ctx, db, identity)
}

// GetCollaboratorByPrimaryEmail returns one collaborator by their lowercased
// primary_email. Returns ErrCollaboratorNotFound when no row matches.
func GetCollaboratorByPrimaryEmail(ctx context.Context, db *sql.DB, email string) (model.Collaborator, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return model.Collaborator{}, fmt.Errorf("collaborator primary_email is required")
	}

	row := db.QueryRowContext(
		ctx,
		`
			SELECT
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
			FROM public.collaborators
			WHERE LOWER(primary_email) = $1
			ORDER BY created_at ASC
			LIMIT 1
		`,
		email,
	)

	collaborator, err := scanCollaborator(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Collaborator{}, ErrCollaboratorNotFound
		}
		return model.Collaborator{}, err
	}

	return collaborator, nil
}

func getPasswordCredentialRow(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
) (model.PasswordCredential, string, error) {
	var (
		credential   model.PasswordCredential
		passwordHash string
		metadataRaw  []byte
	)

	err := db.QueryRowContext(
		ctx,
		`
			SELECT
				collaborator_id,
				status,
				password_scheme,
				password_hash,
				metadata,
				password_updated_at,
				created_at,
				updated_at
			FROM public.collaborator_password_credentials
			WHERE collaborator_id = $1
		`,
		collaboratorID,
	).Scan(
		&credential.CollaboratorID,
		&credential.Status,
		&credential.PasswordScheme,
		&passwordHash,
		&metadataRaw,
		&credential.PasswordUpdatedAt,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.PasswordCredential{}, "", ErrPasswordCredentialNotFound
		}
		return model.PasswordCredential{}, "", err
	}

	credential.Metadata = map[string]any{}
	if len(metadataRaw) > 0 {
		if err := json.Unmarshal(metadataRaw, &credential.Metadata); err != nil {
			return model.PasswordCredential{}, "", err
		}
	}

	return credential, passwordHash, nil
}

func createAuthSession(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
	metadata map[string]any,
	ttl time.Duration,
) (model.AuthSession, string, error) {
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}

	token, tokenHash, err := coreauth.GenerateSessionToken()
	if err != nil {
		return model.AuthSession{}, "", err
	}

	metadataRaw, err := marshalJSONObject(metadata)
	if err != nil {
		return model.AuthSession{}, "", err
	}

	expiresAt := time.Now().UTC().Add(ttl)
	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.auth_sessions (
				collaborator_id,
				status,
				token_hash,
				metadata,
				expires_at
			) VALUES (
				$1,
				'active',
				$2,
				$3::jsonb,
				$4
			)
			RETURNING
				id,
				collaborator_id,
				status,
				metadata,
				last_seen_at,
				expires_at,
				revoked_at,
				created_at,
				updated_at
		`,
		collaboratorID,
		tokenHash,
		metadataRaw,
		expiresAt,
	)

	session, err := scanAuthSession(row)
	if err != nil {
		return model.AuthSession{}, "", err
	}

	return session, token, nil
}

func getAuthSessionByTokenHash(ctx context.Context, db *sql.DB, tokenHash string) (model.AuthSession, error) {
	session, err := scanAuthSession(db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				collaborator_id,
				status,
				metadata,
				last_seen_at,
				expires_at,
				revoked_at,
				created_at,
				updated_at
			FROM public.auth_sessions
			WHERE token_hash = $1
			ORDER BY created_at DESC
			LIMIT 1
		`,
		tokenHash,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.AuthSession{}, ErrAuthSessionNotFound
		}
		return model.AuthSession{}, err
	}
	return session, nil
}

func scanPasswordCredential(row scanner) (model.PasswordCredential, error) {
	var (
		credential  model.PasswordCredential
		metadataRaw []byte
	)

	err := row.Scan(
		&credential.CollaboratorID,
		&credential.Status,
		&credential.PasswordScheme,
		&metadataRaw,
		&credential.PasswordUpdatedAt,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)
	if err != nil {
		return model.PasswordCredential{}, err
	}

	credential.Metadata = map[string]any{}
	if len(metadataRaw) > 0 {
		if err := json.Unmarshal(metadataRaw, &credential.Metadata); err != nil {
			return model.PasswordCredential{}, err
		}
	}

	return credential, nil
}

func scanAuthSession(row scanner) (model.AuthSession, error) {
	var (
		session     model.AuthSession
		metadataRaw []byte
	)

	err := row.Scan(
		&session.ID,
		&session.CollaboratorID,
		&session.Status,
		&metadataRaw,
		&session.LastSeenAt,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		return model.AuthSession{}, err
	}

	session.Metadata = map[string]any{}
	if len(metadataRaw) > 0 {
		if err := json.Unmarshal(metadataRaw, &session.Metadata); err != nil {
			return model.AuthSession{}, err
		}
	}

	return session, nil
}

func normalizeAuthStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "active"
	}
	return value
}
