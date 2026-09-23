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

// ResetMFAFactors wipes every enrolled second factor of a collaborator and
// revokes all of their sessions. Every factor lives on auth_identities
// (TOTP secret, passkeys JSONB, recovery-code hashes), so one UPDATE clears
// them together and the enrollment marker goes back to NULL: the next
// password login or setup commit answers 428 and walks the person through a
// fresh enrollment. Outstanding enroll links are consumed so an old link
// cannot race the new enrollment.
//
// Run it inside the caller's transaction together with the audit event.
func ResetMFAFactors(ctx context.Context, tx DBExecer, collaboratorID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET webauthn_credentials   = '[]'::jsonb,
		    totp_secret_ciphertext = NULL,
		    totp_secret_dek        = NULL,
		    recovery_codes_hashes  = ARRAY[]::TEXT[],
		    mfa_enrolled_at        = NULL,
		    failed_attempts        = 0,
		    locked_until           = NULL,
		    updated_at             = NOW()
		WHERE collaborator_id = $1
	`, collaboratorID); err != nil {
		return fmt.Errorf("reset mfa factors: %w", err)
	}
	if err := RevokeAllAuthSessions(ctx, tx, collaboratorID); err != nil {
		return err
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

// RevokeAllAuthSessions revokes every live session of a collaborator. Used
// whenever a credential is replaced through a link (setup, reset, MFA reset):
// sessions opened with the old credential must not outlive it.
func RevokeAllAuthSessions(ctx context.Context, tx DBExecer, collaboratorID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE public.auth_sessions
		SET status     = 'revoked',
		    revoked_at = NOW()
		WHERE collaborator_id = $1
		  AND revoked_at IS NULL
	`, collaboratorID); err != nil {
		return fmt.Errorf("revoke auth sessions: %w", err)
	}
	return nil
}

// RecordResetTokenMFAFailure counts one failed second-factor proof against a
// reset token and burns the token once maxFailures is reached. The reset
// page keeps the token alive across a mistyped code (the old flow consumed
// it first, so one typo cost a new email), and this counter is what keeps
// that from becoming an offline guessing oracle for the TOTP code.
//
// Returns how many attempts remain (0 means the token is now consumed).
func RecordResetTokenMFAFailure(ctx context.Context, db *sql.DB, tokenID uuid.UUID, maxFailures int) (int, error) {
	var failures int
	err := db.QueryRowContext(ctx, `
		UPDATE public.auth_credential_tokens
		SET metadata = jsonb_set(
		        COALESCE(metadata, '{}'::jsonb),
		        '{mfa_failures}',
		        to_jsonb(COALESCE((metadata->>'mfa_failures')::int, 0) + 1)
		    ),
		    consumed_at = CASE
		        WHEN COALESCE((metadata->>'mfa_failures')::int, 0) + 1 >= $2 THEN NOW()
		        ELSE consumed_at
		    END
		WHERE id = $1 AND consumed_at IS NULL
		RETURNING (metadata->>'mfa_failures')::int
	`, tokenID, maxFailures).Scan(&failures)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("record reset token mfa failure: %w", err)
	}
	remaining := maxFailures - failures
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}
