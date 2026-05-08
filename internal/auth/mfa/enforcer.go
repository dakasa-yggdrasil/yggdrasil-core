package mfa

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrMFANotEnrolled is returned when an authentication path tries to issue a
// session for a collaborator who has not finished MFA enroll. This is the
// project's universal MFA mandatory invariant — no opt-out by role.
var ErrMFANotEnrolled = errors.New("mfa not enrolled")

// EnforceMFAEnrolled queries auth_identities for the collaborator and returns
// ErrMFANotEnrolled if mfa_enrolled_at is NULL. Call this BEFORE handing back
// any session token (password login, OIDC auto-provision callback, magic-link
// completion). The enroll workflow itself bypasses this gate by design.
//
// Bootstrap exception: when there is no auth_identities row at all the
// collaborator is treated as freshly created, returning ErrMFANotEnrolled —
// callers should redirect to the enroll flow instead of issuing a session.
func EnforceMFAEnrolled(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) error {
	var enrolled sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT mfa_enrolled_at FROM public.auth_identities WHERE collaborator_id = $1
	`, collaboratorID).Scan(&enrolled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMFANotEnrolled
	}
	if err != nil {
		return fmt.Errorf("enforce mfa: %w", err)
	}
	if !enrolled.Valid {
		return ErrMFANotEnrolled
	}
	return nil
}

// MarkMFAEnrolled flips mfa_enrolled_at to NOW() the first time a collaborator
// completes the enroll flow (registers TOTP or first WebAuthn credential and
// downloads recovery codes). Idempotent — re-runs are no-ops.
func MarkMFAEnrolled(ctx context.Context, db *sql.DB, collaboratorID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE public.auth_identities
		SET mfa_enrolled_at = NOW()
		WHERE collaborator_id = $1 AND mfa_enrolled_at IS NULL
	`, collaboratorID)
	if err != nil {
		return fmt.Errorf("mark mfa enrolled: %w", err)
	}
	return nil
}
