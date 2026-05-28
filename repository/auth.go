package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreauth"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// metadataString extracts a string field from session metadata (set by the
// HTTP layer via mergeAuthMetadata). Returns "" when the key is missing or
// not a string, so callers can pass the result directly to NOT-NULL columns
// that default to ”.
func metadataString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

var (
	ErrPasswordCredentialNotFound = errors.New("password credential not found")
	ErrAuthInvalidCredentials     = errors.New("invalid credentials")
	ErrAuthSessionNotFound        = errors.New("auth session not found")
	ErrAuthSessionExpired         = errors.New("auth session expired")
	// ErrAuthAccountLocked is returned when an account has too many
	// recent failed login attempts and is temporarily inaccessible
	// until LockedUntil expires (security audit 2026-05-27 A4).
	ErrAuthAccountLocked = errors.New("account locked")
)

// loginFailureThreshold + loginLockDuration tune the lockout behavior.
// Match the conservative defaults documented in the audit fix plan:
// 5 failed attempts → 15-min lock. Backstop against rapid attacks even
// after the per-IP rate limiter; brute-force at the account level
// (e.g. credential-stuffing distributed across many IPs).
const (
	loginFailureThreshold = 5
	loginLockDuration     = 15 * time.Minute
)

// UpsertPasswordCredential creates or updates one local password credential for
// an existing collaborator. The caller is responsible for hashing the password
// and validating its strength before calling this function; passwordHash and
// passwordScheme must already be in the encoded format expected by the password
// package (e.g. argon2id PHC string, or pbkdf2_sha256$... legacy format).
func UpsertPasswordCredential(
	ctx context.Context,
	db *sql.DB,
	req model.UpsertPasswordCredentialRequest,
	passwordScheme, passwordHash string,
) (model.PasswordCredential, model.Collaborator, error) {
	collaborator, err := resolveCollaboratorForLogin(ctx, db, req.CollaboratorID)
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
			UPDATE public.auth_identities
			SET
				password_scheme     = $2,
				password_hash       = $3,
				password_updated_at = NOW(),
				password_metadata   = COALESCE(NULLIF($4::jsonb, 'null'::jsonb), password_metadata)
			WHERE collaborator_id = $1
			RETURNING
				collaborator_id,
				password_scheme,
				password_metadata,
				password_updated_at,
				created_at,
				updated_at
		`,
		collaborator.ID,
		passwordScheme,
		passwordHash,
		metadata,
	)

	credential, err := scanPasswordCredential(row)
	if err != nil {
		return model.PasswordCredential{}, model.Collaborator{}, err
	}

	return credential, collaborator, nil
}

// VerifyPasswordCredential validates the identifier/password pair and returns
// the collaborator when the credential is active. It intentionally does not
// issue a session; HTTP callers layer MFA verification on top before calling
// CreateAuthSession.
//
// Lockout (security audit 2026-05-27 A4): when the collaborator's
// auth_identities.locked_until is in the future, returns
// ErrAuthAccountLocked without checking the password (constant-time
// refuse). On a successful password verify, resets failed_attempts to
// 0. On a failed password verify (mismatch / corrupt hash), increments
// failed_attempts; once the count reaches loginFailureThreshold, sets
// locked_until to NOW()+loginLockDuration so the next attempt sees the
// lock.
//
// We do NOT increment failed_attempts when the collaborator is missing
// (would leak which emails are registered).
func VerifyPasswordCredential(
	ctx context.Context,
	db *sql.DB,
	req model.LoginWithPasswordRequest,
) (model.Collaborator, error) {
	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		return model.Collaborator{}, fmt.Errorf("identifier is required")
	}
	if strings.TrimSpace(req.Password) == "" {
		return model.Collaborator{}, fmt.Errorf("password is required")
	}

	collaborator, err := resolveCollaboratorForLogin(ctx, db, identifier)
	if err != nil {
		if errors.Is(err, ErrCollaboratorNotFound) {
			return model.Collaborator{}, ErrAuthInvalidCredentials
		}
		return model.Collaborator{}, err
	}
	if strings.ToLower(strings.TrimSpace(collaborator.Status)) != "active" {
		return model.Collaborator{}, ErrAuthInvalidCredentials
	}

	// Lockout check BEFORE password verify so we don't leak whether
	// the locked account's password is right.
	if locked, err := isAccountLocked(ctx, db, collaborator.ID); err == nil && locked {
		return model.Collaborator{}, ErrAuthAccountLocked
	}

	credential, passwordHash, err := getPasswordCredentialRow(ctx, db, collaborator.ID)
	if err != nil {
		if errors.Is(err, ErrPasswordCredentialNotFound) {
			return model.Collaborator{}, ErrAuthInvalidCredentials
		}
		return model.Collaborator{}, err
	}
	if strings.ToLower(strings.TrimSpace(credential.Status)) != "active" {
		return model.Collaborator{}, ErrAuthInvalidCredentials
	}

	// Dispatch pelo scheme armazenado no DB — handleSetupCommit e
	// handlePasswordChange escrevem via internal/auth/password (Argon2id),
	// enquanto coreauth.VerifyPassword só sabe PBKDF2-SHA256 (legacy).
	// O bridge (wiring.go) já faz o dispatch correto via password.Verify.
	scheme := credential.PasswordScheme
	if scheme == "" {
		// Backstop: rows sem scheme explícito assumem o legacy PBKDF2
		// pra preservar logins antigos. handleSetupCommit sempre seta.
		scheme = "pbkdf2_sha256"
	}
	if err := verifyPasswordBridge(scheme, passwordHash, req.Password); err != nil {
		// Erros de password mismatch + scheme/hash corruption todos viram
		// invalid_credentials pro user — o detalhe técnico vai pra
		// stderr (structured key=value, ops can grep) pra triagem,
		// especialmente hash corruption que indica data corruption no
		// banco.
		// Audit ref: B8/G2 — switched from fmt.Printf to structured log
		// so an aggregator like Loki can parse fields without regex.
		structuredLog("auth.password.verify_failed",
			"collaborator_id", collaborator.ID.String(),
			"scheme", scheme,
			"error", err.Error(),
		)
		// Record the failure (increment failed_attempts, set
		// locked_until on threshold). Best-effort: a DB hiccup here
		// must not change the 401 the user sees.
		if locked, recordErr := recordLoginFailure(ctx, db, collaborator.ID); recordErr == nil && locked {
			return model.Collaborator{}, ErrAuthAccountLocked
		}
		return model.Collaborator{}, ErrAuthInvalidCredentials
	}

	// Password matched — reset the failure counter so a streak of
	// typos doesn't tip a real user into the lockout window.
	_ = resetLoginFailures(ctx, db, collaborator.ID)
	return collaborator, nil
}

// isAccountLocked returns true when auth_identities.locked_until is
// non-NULL and in the future for this collaborator. Errors propagate
// to the caller; a missing row counts as "not locked" (false, nil) so
// freshly-onboarded accounts before their first auth_identities row
// exists don't get treated as locked.
func isAccountLocked(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (bool, error) {
	var lockedUntil sql.NullTime
	row := db.QueryRowContext(ctx, `
		SELECT locked_until
		FROM public.auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID)
	if err := row.Scan(&lockedUntil); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if !lockedUntil.Valid {
		return false, nil
	}
	return lockedUntil.Time.After(time.Now().UTC()), nil
}

// recordLoginFailure increments failed_attempts and, when the count
// crosses loginFailureThreshold, sets locked_until to NOW()+lockDuration.
// Returns (locked, err) where locked=true indicates the latest
// increment tripped the lockout (caller should surface that to the user
// instead of a plain "invalid credentials").
func recordLoginFailure(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (bool, error) {
	var failedAttempts int
	var lockedUntil sql.NullTime
	row := db.QueryRowContext(ctx, `
		UPDATE public.auth_identities
		SET
			failed_attempts = COALESCE(failed_attempts, 0) + 1,
			locked_until = CASE
				WHEN COALESCE(failed_attempts, 0) + 1 >= $2
				THEN NOW() + ($3 || ' milliseconds')::interval
				ELSE locked_until
			END,
			updated_at = NOW()
		WHERE collaborator_id = $1
		RETURNING failed_attempts, locked_until
	`, collaboratorID, loginFailureThreshold, fmt.Sprintf("%d", loginLockDuration.Milliseconds()))
	if err := row.Scan(&failedAttempts, &lockedUntil); err != nil {
		return false, err
	}
	if !lockedUntil.Valid {
		return false, nil
	}
	return lockedUntil.Time.After(time.Now().UTC()), nil
}

// resetLoginFailures zeroes failed_attempts and clears locked_until
// after a successful authentication.
func resetLoginFailures(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET
			failed_attempts = 0,
			locked_until = NULL,
			last_login_at = NOW(),
			updated_at = NOW()
		WHERE collaborator_id = $1
	`, collaboratorID)
	return err
}

// AuthenticateWithPassword validates one login and opens a new session.
func AuthenticateWithPassword(
	ctx context.Context,
	db *sql.DB,
	req model.LoginWithPasswordRequest,
	ttl time.Duration,
) (model.Collaborator, model.AuthSession, string, error) {
	collaborator, err := VerifyPasswordCredential(ctx, db, req)
	if err != nil {
		return model.Collaborator{}, model.AuthSession{}, "", err
	}

	// Universal MFA invariant: refuse session issuance if mfa not enrolled.
	if err := mfa.EnforceMFAEnrolled(ctx, db, collaborator.ID); err != nil {
		return collaborator, model.AuthSession{}, "", err
	}

	session, token, err := createAuthSession(ctx, db, collaborator.ID, req.Metadata, ttl)
	if err != nil {
		return model.Collaborator{}, model.AuthSession{}, "", err
	}

	return collaborator, session, token, nil
}

// CreateAuthSession opens a new authenticated session for a collaborator after
// the caller has completed every required authentication factor.
func CreateAuthSession(
	ctx context.Context,
	db *sql.DB,
	collaboratorID uuid.UUID,
	metadata map[string]any,
	ttl time.Duration,
) (model.AuthSession, string, error) {
	return createAuthSession(ctx, db, collaboratorID, metadata, ttl)
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

// ListActiveSessionsForCollaborator returns every status='active' AND
// non-expired session for one collaborator, ordered by created_at DESC
// (newest first).  Used by `GET /api/v1/me/sessions` so the user can
// review and revoke.
//
// Audit ref: C8 (no self-service listing).
func ListActiveSessionsForCollaborator(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) ([]model.AuthSessionView, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			id,
			collaborator_id,
			status,
			last_seen_at,
			expires_at,
			created_at,
			COALESCE(user_agent, '') AS user_agent,
			COALESCE(host(ip_address), '') AS ip_address,
			COALESCE(device_fingerprint, '') AS device_fingerprint
		FROM public.auth_sessions
		WHERE collaborator_id = $1
		  AND status = 'active'
		  AND expires_at > NOW()
		ORDER BY COALESCE(last_seen_at, created_at) DESC, created_at DESC
	`, collaboratorID)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()

	var out []model.AuthSessionView
	for rows.Next() {
		var v model.AuthSessionView
		if err := rows.Scan(
			&v.ID,
			&v.CollaboratorID,
			&v.Status,
			&v.LastSeenAt,
			&v.ExpiresAt,
			&v.CreatedAt,
			&v.UserAgent,
			&v.IPAddress,
			&v.DeviceFingerprint,
		); err != nil {
			return nil, fmt.Errorf("scan active session: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RevokeSessionByIDForCollaborator revokes ONE specific session by id,
// but only if it belongs to the supplied collaborator (defense in
// depth: the handler already checks ownership, but the SQL also
// constrains so an off-by-one in the handler can't escalate).
//
// Returns the revoked session row or nil if no matching row was
// found / already revoked. Returning nil + nil error is the canonical
// "not found" so the handler can emit 404.
//
// Audit ref: C8 (self-service revoke endpoint).
func RevokeSessionByIDForCollaborator(ctx context.Context, db *sql.DB, sessionID, collaboratorID uuid.UUID) (*model.AuthSession, error) {
	row := db.QueryRowContext(ctx, `
		UPDATE public.auth_sessions
		SET status = 'revoked',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id = $1
		  AND collaborator_id = $2
		  AND status = 'active'
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
	`, sessionID, collaboratorID)

	s, err := scanAuthSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
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
				version,
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
				password_scheme,
				password_hash,
				password_metadata,
				password_updated_at,
				created_at,
				updated_at
			FROM public.auth_identities
			WHERE collaborator_id = $1
			  AND password_hash IS NOT NULL
		`,
		collaboratorID,
	).Scan(
		&credential.CollaboratorID,
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
	// auth_identities has no status column; a row with password_hash IS NOT NULL is always "active".
	credential.Status = "active"

	credential.Metadata = map[string]any{}
	if len(metadataRaw) > 0 {
		if err := json.Unmarshal(metadataRaw, &credential.Metadata); err != nil {
			return model.PasswordCredential{}, "", err
		}
	}

	return credential, passwordHash, nil
}

// maxActiveSessionsPerCollaborator caps the number of simultaneously
// active `auth_sessions` rows for one collaborator. Above the cap, the
// oldest sessions (by created_at ASC) are LRU-evicted (marked revoked)
// in the same transaction as the new INSERT so the row count strictly
// equals the cap immediately after createAuthSession returns.
//
// Audit ref: C4 (42 active sessions for one user; no cap, no eviction).
// Override at boot via YGGDRASIL_AUTH_SESSION_CAP env (positive int);
// default 20 is enough for power users (laptop + desktop + 2 phones +
// 2 tablets + N CI/CLI tokens + headroom).
const maxActiveSessionsPerCollaborator = 20

func sessionCapForCollaborator() int {
	if v := os.Getenv("YGGDRASIL_AUTH_SESSION_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return maxActiveSessionsPerCollaborator
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

	// C4: LRU-evict the oldest sessions when this collaborator already
	// holds the cap. The eviction runs BEFORE the INSERT so the post-
	// insert row count is exactly the cap (no race). We revoke the
	// oldest N rows beyond `cap-1` so the new row brings us to exactly
	// `cap`. Best-effort: if eviction fails the auth still succeeds —
	// the cap is hygiene, not gating.
	cap := sessionCapForCollaborator()
	_, _ = db.ExecContext(ctx, `
		WITH excess AS (
			SELECT id FROM public.auth_sessions
			WHERE collaborator_id = $1
			  AND status = 'active'
			  AND expires_at > NOW()
			ORDER BY COALESCE(last_seen_at, created_at) ASC, created_at ASC
			OFFSET $2
		)
		UPDATE public.auth_sessions
		SET status = 'revoked',
		    revoked_at = NOW(),
		    updated_at = NOW()
		WHERE id IN (SELECT id FROM excess)
	`, collaboratorID, cap-1)

	token, tokenHash, err := coreauth.GenerateSessionToken()
	if err != nil {
		return model.AuthSession{}, "", err
	}

	metadataRaw, err := marshalJSONObject(metadata)
	if err != nil {
		return model.AuthSession{}, "", err
	}

	expiresAt := time.Now().UTC().Add(ttl)

	// Extract device columns from metadata (populated by HTTP layer via
	// mergeAuthMetadata). Fall back to empty so NOT-NULL DEFAULT '' columns
	// stay happy. ipAddress stays as *string so a missing/invalid value
	// becomes SQL NULL on the inet column.
	deviceFingerprint := metadataString(metadata, "device_fingerprint")
	userAgent := metadataString(metadata, "user_agent")
	var ipAddress sql.NullString
	if v := metadataString(metadata, "ip_address"); v != "" {
		ipAddress = sql.NullString{String: v, Valid: true}
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.auth_sessions (
				collaborator_id,
				status,
				token_hash,
				metadata,
				expires_at,
				device_fingerprint,
				user_agent,
				ip_address
			) VALUES (
				$1,
				'active',
				$2,
				$3::jsonb,
				$4,
				$5,
				$6,
				$7
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
		deviceFingerprint,
		userAgent,
		ipAddress,
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

	// auth_identities has no status column; a row with password_hash is always "active".
	credential.Status = "active"

	err := row.Scan(
		&credential.CollaboratorID,
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
