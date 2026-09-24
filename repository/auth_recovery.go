package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// CredentialAccountState is what the recovery pages (setup link, password
// reset) need to know about an account before asking the person for
// anything: whether a password already exists (so a setup link is a
// re-access, not a first access) and which second factors can be proven
// inline.
type CredentialAccountState struct {
	HasPassword      bool
	MFAEnrolled      bool
	HasTOTP          bool
	HasRecoveryCodes bool
	PasskeyCount     int
}

// GetCredentialAccountState reads the credential posture of one
// collaborator. A missing auth_identities row is reported as the zero state
// (no password, no factors): provisioning has not finished, which the
// commit paths surface on their own.
func GetCredentialAccountState(ctx context.Context, db DBQuerier, collaboratorID uuid.UUID) (CredentialAccountState, error) {
	var st CredentialAccountState
	err := db.QueryRowContext(ctx, `
		SELECT
			COALESCE(password_hash, '') <> '',
			mfa_enrolled_at IS NOT NULL,
			totp_secret_ciphertext IS NOT NULL,
			COALESCE(array_length(recovery_codes_hashes, 1), 0) > 0,
			COALESCE(jsonb_array_length(webauthn_credentials), 0)
		FROM public.auth_identities
		WHERE collaborator_id = $1
	`, collaboratorID).Scan(&st.HasPassword, &st.MFAEnrolled, &st.HasTOTP, &st.HasRecoveryCodes, &st.PasskeyCount)
	if errors.Is(err, sql.ErrNoRows) {
		return CredentialAccountState{}, nil
	}
	if err != nil {
		return CredentialAccountState{}, fmt.Errorf("get credential account state: %w", err)
	}
	return st, nil
}

// ResetMFAFactors is the admin full recovery for someone who lost the
// second factor (with or without the password). It wipes every factor
// (TOTP secret, passkeys JSONB, recovery-code hashes; all of them live on
// auth_identities) AND the password, so the account is back to a first
// access that only the setup link issued in the same transaction can open.
//
// Keeping the old password valid here was an account takeover: with the
// factors gone, a password login answers 428 with an enroll link, so
// whoever held a leaked password could enroll their own authenticator
// before the owner opened the link. Without a password hash the login
// answers invalid_credentials instead.
//
// The lockout counters are reset too: the setup commit does not clear
// them, and with no password there is nothing left for them to protect.
// Outstanding enroll links are consumed so an old one cannot race the new
// enrollment. Sessions are revoked by the caller (it owns the §13 fan-out).
func ResetMFAFactors(ctx context.Context, tx DBExecer, collaboratorID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET webauthn_credentials   = '[]'::jsonb,
		    totp_secret_ciphertext = NULL,
		    totp_secret_dek        = NULL,
		    recovery_codes_hashes  = ARRAY[]::TEXT[],
		    mfa_enrolled_at        = NULL,
		    password_hash          = NULL,
		    password_scheme        = NULL,
		    password_updated_at    = NULL,
		    password_expires_at    = NULL,
		    password_must_change   = false,
		    failed_attempts        = 0,
		    locked_until           = NULL,
		    updated_at             = NOW()
		WHERE collaborator_id = $1
	`, collaboratorID); err != nil {
		return fmt.Errorf("reset mfa factors: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.mfa_enroll_tokens
		SET consumed_at = NOW()
		WHERE collaborator_id = $1 AND consumed_at IS NULL
	`, collaboratorID); err != nil {
		return fmt.Errorf("consume outstanding mfa enroll tokens: %w", err)
	}
	return nil
}

// RevokeAllAuthSessions revokes every live console session AND every live
// OIDC refresh token of a collaborator. Used whenever a credential is
// replaced through a link (setup, reset, MFA reset): nothing opened with
// the old credential may outlive it, including relying parties that only
// hold a refresh token. Returns how many console sessions were revoked.
func RevokeAllAuthSessions(ctx context.Context, tx DBExecer, collaboratorID uuid.UUID) (int64, error) {
	res, err := tx.ExecContext(ctx, `
		UPDATE public.auth_sessions
		SET status     = 'revoked',
		    revoked_at = NOW()
		WHERE collaborator_id = $1
		  AND revoked_at IS NULL
	`, collaboratorID)
	if err != nil {
		return 0, fmt.Errorf("revoke auth sessions: %w", err)
	}
	revoked, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.oidc_refresh_tokens
		SET revoked_at = NOW()
		WHERE collaborator_id = $1
		  AND revoked_at IS NULL
	`, collaboratorID); err != nil {
		return 0, fmt.Errorf("revoke oidc refresh tokens: %w", err)
	}
	return revoked, nil
}

// ErrResetAttemptsExhausted means a reset link has no second-factor
// attempt left (or is no longer usable) and must not be verified again.
var ErrResetAttemptsExhausted = errors.New("reset link has no attempts left")

// ReserveResetTokenMFAAttempt atomically takes one second-factor attempt
// from a reset link BEFORE the factor is verified, and returns how many
// attempts the link has used including this one. Counting after the check
// (the first version) let concurrent requests all pass the "fewer than N"
// test and guess far more than N codes. The row stays unconsumed so the
// last reserved attempt can still succeed; BurnCredentialToken closes the
// link when that attempt fails.
func ReserveResetTokenMFAAttempt(ctx context.Context, db *sql.DB, tokenID uuid.UUID, maxAttempts int) (int, error) {
	var attempts int
	err := db.QueryRowContext(ctx, `
		UPDATE public.auth_credential_tokens
		SET metadata = jsonb_set(
		        COALESCE(metadata, '{}'::jsonb),
		        '{mfa_attempts}',
		        to_jsonb(COALESCE((metadata->>'mfa_attempts')::int, 0) + 1)
		    )
		WHERE id = $1
		  AND purpose = 'reset'
		  AND consumed_at IS NULL
		  AND expires_at > NOW()
		  AND COALESCE((metadata->>'mfa_attempts')::int, 0) < $2
		RETURNING (metadata->>'mfa_attempts')::int
	`, tokenID, maxAttempts).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrResetAttemptsExhausted
	}
	if err != nil {
		return 0, fmt.Errorf("reserve reset attempt: %w", err)
	}
	return attempts, nil
}

// BurnCredentialToken marks one credential token consumed. Idempotent.
func BurnCredentialToken(ctx context.Context, db *sql.DB, tokenID uuid.UUID) error {
	if _, err := db.ExecContext(ctx, `
		UPDATE public.auth_credential_tokens
		SET consumed_at = NOW()
		WHERE id = $1 AND consumed_at IS NULL
	`, tokenID); err != nil {
		return fmt.Errorf("burn credential token: %w", err)
	}
	return nil
}
