package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ErrAuthIdentityNotFound is returned when no auth_identities row matches the
// requested collaborator.
var ErrAuthIdentityNotFound = errors.New("auth identity not found")

// UpsertAuthIdentity creates or refreshes the identity row for collaboratorID.
// Username defaults to LOWER(primary_email) and is stored case-insensitively
// (CITEXT). Idempotent.
func UpsertAuthIdentity(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, username string) error {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" {
		return fmt.Errorf("auth identity username is required")
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO public.auth_identities (collaborator_id, username)
		VALUES ($1, $2)
		ON CONFLICT (collaborator_id) DO UPDATE
		SET username = EXCLUDED.username
	`, collaboratorID, username)
	if err != nil {
		return fmt.Errorf("upsert auth_identity: %w", err)
	}
	return nil
}

// GetAuthIdentityByCollaboratorID fetches one identity row, decrypting
// nothing — the caller decides which secrets it needs and uses the helpers
// below.
func GetAuthIdentityByCollaboratorID(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (model.AuthIdentity, error) {
	row := db.QueryRowContext(ctx, `
		SELECT
			collaborator_id,
			username,
			webauthn_credentials,
			(totp_secret_ciphertext IS NOT NULL AND totp_confirmed_at IS NOT NULL) AS has_totp,
			(array_length(recovery_codes_hashes, 1) > 0) AS has_recovery,
			mfa_enrolled_at,
			last_login_at,
			failed_attempts,
			locked_until,
			created_at,
			updated_at
		FROM public.auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID)

	var (
		id          model.AuthIdentity
		credBlob    []byte
		hasTOTP     sql.NullBool
		hasRecovery sql.NullBool
		mfaEnrolled sql.NullTime
		lastLogin   sql.NullTime
		lockedUntil sql.NullTime
	)
	err := row.Scan(
		&id.CollaboratorID,
		&id.Username,
		&credBlob,
		&hasTOTP,
		&hasRecovery,
		&mfaEnrolled,
		&lastLogin,
		&id.FailedAttempts,
		&lockedUntil,
		&id.CreatedAt,
		&id.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AuthIdentity{}, ErrAuthIdentityNotFound
	}
	if err != nil {
		return model.AuthIdentity{}, fmt.Errorf("scan auth_identity: %w", err)
	}

	id.HasTOTP = hasTOTP.Valid && hasTOTP.Bool
	id.HasRecoveryCodes = hasRecovery.Valid && hasRecovery.Bool
	if mfaEnrolled.Valid {
		t := mfaEnrolled.Time
		id.MFAEnrolledAt = &t
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		id.LastLoginAt = &t
	}
	if lockedUntil.Valid {
		t := lockedUntil.Time
		id.LockedUntil = &t
	}
	id.WebAuthnCredentials = decodeWebAuthnCredentials(credBlob)
	return id, nil
}

// SetTOTPSecret stores an envelope-encrypted pending seed and invalidates any
// old seed's confirmation. Only ConfirmTOTPEnrollment promotes the new seed.
func SetTOTPSecret(ctx context.Context, db *sql.DB, env *cryptoenvelope.Envelope, collaboratorID uuid.UUID, secret []byte) error {
	ct, dek, err := env.Seal(ctx, secret)
	if err != nil {
		return fmt.Errorf("seal totp secret: %w", err)
	}
	res, err := db.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET totp_secret_ciphertext = $1,
		    totp_secret_dek = $2,
		    totp_confirmed_at = NULL
		WHERE collaborator_id = $3
	`, ct, dek, collaboratorID)
	if err != nil {
		return fmt.Errorf("update totp_secret: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrAuthIdentityNotFound
	}
	return nil
}

// GetTOTPSecret reads a seed for setup compatibility, including pending state.
// Authentication must use GetConfirmedTOTPSecret. Never log returned bytes.
func GetTOTPSecret(ctx context.Context, db *sql.DB, env *cryptoenvelope.Envelope, collaboratorID uuid.UUID) ([]byte, error) {
	var ct, dek []byte
	err := db.QueryRowContext(ctx, `
		SELECT totp_secret_ciphertext, totp_secret_dek
		FROM public.auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID).Scan(&ct, &dek)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuthIdentityNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read totp_secret: %w", err)
	}
	if len(ct) == 0 {
		return nil, fmt.Errorf("totp not enrolled for collaborator %s", collaboratorID)
	}
	return env.Open(ctx, ct, dek)
}

// GetConfirmedTOTPSecret is the authentication-only seed reader. A pending
// begin/replacement cannot authenticate solely because another factor has
// already established the identity's global MFA posture.
func GetConfirmedTOTPSecret(ctx context.Context, db *sql.DB, env *cryptoenvelope.Envelope, id uuid.UUID) ([]byte, error) {
	if env == nil {
		return nil, mfa.ErrInvalidTOTP
	}
	var ct, dek []byte
	err := db.QueryRowContext(ctx, `SELECT totp_secret_ciphertext,totp_secret_dek FROM public.auth_identities WHERE collaborator_id=$1 AND totp_confirmed_at IS NOT NULL AND totp_secret_ciphertext IS NOT NULL`, id).Scan(&ct, &dek)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, mfa.ErrInvalidTOTP
	}
	if err != nil {
		return nil, fmt.Errorf("read confirmed TOTP seed: %w", err)
	}
	return env.Open(ctx, ct, dek)
}

// ConfirmTOTPEnrollment proves the currently stored seed and commits its own
// confirmation, global MFA posture, recovery vault and optional one-use link
// under the same lock boundary. A concurrent seed replacement cannot confirm
// an obsolete seed or return success with a seed cleared by contact login.
func ConfirmTOTPEnrollment(ctx context.Context, db *sql.DB, env *cryptoenvelope.Envelope, id uuid.UUID, code string, recoveryHashes []string, enrollTokenHash string) error {
	if env == nil || len(recoveryHashes) != mfa.RecoveryCodeCount {
		return mfa.ErrInvalidTOTP
	}
	for _, hash := range recoveryHashes {
		if len(hash) != 64 {
			return mfa.ErrInvalidTOTP
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin TOTP confirmation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockContactOwnerTx(ctx, tx, id); err != nil {
		return err
	}
	var ct, dek []byte
	if err := tx.QueryRowContext(ctx, `SELECT totp_secret_ciphertext,totp_secret_dek FROM public.auth_identities WHERE collaborator_id=$1`, id).Scan(&ct, &dek); err != nil {
		return fmt.Errorf("read locked pending TOTP seed: %w", err)
	}
	if len(ct) == 0 {
		return mfa.ErrInvalidTOTP
	}
	secret, err := env.Open(ctx, ct, dek)
	if err != nil {
		return mfa.ErrInvalidTOTP
	}
	defer clear(secret)
	if mfa.ValidateTOTP(string(secret), code) != nil {
		return mfa.ErrInvalidTOTP
	}
	if enrollTokenHash != "" {
		var consumed sql.NullTime
		var expired bool
		err := tx.QueryRowContext(ctx, `SELECT consumed_at,expires_at<=clock_timestamp() FROM public.mfa_enroll_tokens WHERE token_hash=$1 AND collaborator_id=$2 FOR UPDATE`, enrollTokenHash, id).Scan(&consumed, &expired)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMFAEnrollTokenNotFound
		}
		if err != nil {
			return fmt.Errorf("lock TOTP enrollment authority: %w", err)
		}
		if consumed.Valid {
			return ErrMFAEnrollTokenAlreadyConsumed
		}
		if expired {
			return ErrMFAEnrollTokenExpired
		}
		res, err := tx.ExecContext(ctx, `UPDATE public.mfa_enroll_tokens SET consumed_at=clock_timestamp() WHERE token_hash=$1 AND collaborator_id=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp()`, enrollTokenHash, id)
		if err != nil {
			return fmt.Errorf("consume TOTP enrollment authority: %w", err)
		}
		if count, err := res.RowsAffected(); err != nil || count != 1 {
			return ErrMFAEnrollTokenExpired
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.auth_identities SET totp_confirmed_at=clock_timestamp(),mfa_enrolled_at=COALESCE(mfa_enrolled_at,clock_timestamp()),recovery_codes_hashes=$2 WHERE collaborator_id=$1`, id, pgTextArray(recoveryHashes)); err != nil {
		return fmt.Errorf("persist confirmed TOTP enrollment: %w", err)
	}
	return tx.Commit()
}

// SetRecoveryCodesHashes replaces the recovery-codes vault with new hashes
// (one per code). Use VerifyAndInvalidateRecoveryCode to consume them.
func SetRecoveryCodesHashes(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, hashes []string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET recovery_codes_hashes = $1
		WHERE collaborator_id = $2
	`, pgTextArray(hashes), collaboratorID)
	if err != nil {
		return fmt.Errorf("update recovery_codes_hashes: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrAuthIdentityNotFound
	}
	return nil
}

// VerifyAndInvalidateRecoveryCode verifies a single-use recovery code and
// removes the matching hash from storage before the caller issues a session.
func VerifyAndInvalidateRecoveryCode(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return mfa.ErrInvalidRecoveryCode
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin recovery-code verification: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var hashes []string
	err = tx.QueryRowContext(ctx, `
		SELECT recovery_codes_hashes
		FROM public.auth_identities
		WHERE collaborator_id = $1
		FOR UPDATE
	`, collaboratorID).Scan(pq.Array(&hashes))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("read recovery codes: %w", err)
	}

	index, err := mfa.VerifyRecoveryCode(code, hashes)
	if err != nil {
		return err
	}

	remaining := make([]string, 0, len(hashes)-1)
	remaining = append(remaining, hashes[:index]...)
	remaining = append(remaining, hashes[index+1:]...)
	res, err := tx.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET recovery_codes_hashes = $1
		WHERE collaborator_id = $2
	`, pgTextArray(remaining), collaboratorID)
	if err != nil {
		return fmt.Errorf("invalidate recovery code: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrAuthIdentityNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recovery-code verification: %w", err)
	}
	return nil
}

// MarkMFAEnrolled stamps the row with enrollment time. Idempotent (re-enroll
// updates the timestamp).
func MarkMFAEnrolled(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID, when time.Time) error {
	res, err := db.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET mfa_enrolled_at = $1
		WHERE collaborator_id = $2
	`, when, collaboratorID)
	if err != nil {
		return fmt.Errorf("mark mfa_enrolled: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrAuthIdentityNotFound
	}
	return nil
}

// CountRecoveryCodesRemaining returns the number of unused recovery
// codes the user still has. Used by /me/mfa to surface "you have N
// codes left" + nudge the user to regenerate when N drops low.
//
// Returns 0 + nil error when the identity row is missing (no row =
// no codes — caller treats as "go enroll first"). Returns 0 + error
// on actual DB failure.
func CountRecoveryCodesRemaining(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (int, error) {
	var n sql.NullInt64
	err := db.QueryRowContext(ctx, `
		SELECT array_length(recovery_codes_hashes, 1)
		FROM public.auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("count recovery_codes_hashes: %w", err)
	}
	if !n.Valid {
		return 0, nil
	}
	return int(n.Int64), nil
}

// IsMFAEnrolled is the invariant gate used by the auth flow. Returns false for
// unknown identity (callers treat as "not enrolled").
func IsMFAEnrolled(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) (bool, error) {
	var enrolled sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT mfa_enrolled_at
		FROM public.auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID).Scan(&enrolled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read mfa_enrolled_at: %w", err)
	}
	return enrolled.Valid, nil
}
