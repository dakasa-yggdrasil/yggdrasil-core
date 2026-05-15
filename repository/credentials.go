package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// DBExecer is the minimal interface for write-only DB operations.
type DBExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// DBQuerier is the minimal interface for read-only DB operations.
type DBQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// SetPasswordHash updates auth_identities with a fresh password hash.
// password_must_change becomes false; password_updated_at is set to NOW().
func SetPasswordHash(ctx context.Context, db DBExecer, collaboratorID uuid.UUID, hash, scheme string, expiresAt time.Time) error {
	res, err := db.ExecContext(ctx, `
		UPDATE auth_identities
		SET password_hash        = $2,
		    password_scheme      = $3,
		    password_updated_at  = NOW(),
		    password_expires_at  = $4,
		    password_must_change = false
		WHERE collaborator_id = $1
	`, collaboratorID, hash, scheme, expiresAt)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrPasswordCredentialNotFound
	}
	return nil
}

// GetPasswordCredentialState returns password-related fields from auth_identities.
// Only the password columns are fetched; MFA / WebAuthn columns are not scanned.
func GetPasswordCredentialState(ctx context.Context, db DBQuerier, collaboratorID uuid.UUID) (model.AuthIdentity, error) {
	var ai model.AuthIdentity
	row := db.QueryRowContext(ctx, `
		SELECT collaborator_id,
		       username,
		       password_hash,
		       password_scheme,
		       password_updated_at,
		       password_expires_at,
		       password_must_change,
		       password_metadata
		FROM auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID)

	var (
		hash      sql.NullString
		scheme    sql.NullString
		updatedAt sql.NullTime
		expiresAt sql.NullTime
		metaJSON  sql.NullString
	)
	if err := row.Scan(
		&ai.CollaboratorID,
		&ai.Username,
		&hash,
		&scheme,
		&updatedAt,
		&expiresAt,
		&ai.PasswordMustChange,
		&metaJSON,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ai, ErrPasswordCredentialNotFound
		}
		return ai, fmt.Errorf("scan password credential: %w", err)
	}

	if hash.Valid {
		ai.PasswordHash = &hash.String
	}
	if scheme.Valid {
		ai.PasswordScheme = &scheme.String
	}
	if updatedAt.Valid {
		t := updatedAt.Time
		ai.PasswordUpdatedAt = &t
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		ai.PasswordExpiresAt = &t
	}
	// JSONB arrives as text from lib/pq; decode only when non-trivial.
	if metaJSON.Valid && metaJSON.String != "" && metaJSON.String != "{}" {
		var meta map[string]any
		if err := json.Unmarshal([]byte(metaJSON.String), &meta); err == nil {
			ai.PasswordMetadata = meta
		}
		// On malformed JSON we leave PasswordMetadata nil rather than failing.
	}
	return ai, nil
}

// VerifyPassword compares plaintext against the stored hash for collaboratorID
// via the password package bridge (wired in wiring.go).
func VerifyPassword(ctx context.Context, db DBQuerier, collaboratorID uuid.UUID, plaintext string) error {
	ai, err := GetPasswordCredentialState(ctx, db, collaboratorID)
	if err != nil {
		return err
	}
	if ai.PasswordHash == nil || ai.PasswordScheme == nil {
		return ErrPasswordCredentialNotFound
	}
	return verifyPasswordBridge(*ai.PasswordScheme, *ai.PasswordHash, plaintext)
}

// verifyPasswordBridge is replaced at init time by wiring.go to avoid cyclic
// imports between the repository and password packages.
var verifyPasswordBridge = func(scheme, encoded, plaintext string) error {
	return errors.New("verifyPasswordBridge not wired")
}

// RevokeAllOtherSessions marks every active session for collaboratorID as
// revoked, except the session identified by exceptSessionID. Returns the
// count of revoked sessions.
func RevokeAllOtherSessions(ctx context.Context, db DBExecer, collaboratorID, exceptSessionID uuid.UUID) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE auth_sessions
		SET status     = 'revoked',
		    revoked_at = NOW()
		WHERE collaborator_id = $1
		  AND id           <> $2
		  AND revoked_at IS NULL
	`, collaboratorID, exceptSessionID)
	if err != nil {
		return 0, fmt.Errorf("revoke sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
