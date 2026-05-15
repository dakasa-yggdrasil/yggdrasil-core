package model

import (
	"time"

	"github.com/google/uuid"
)

// AuthIdentity is the secrets+state companion record to a Collaborator,
// holding MFA factors and lockout counters. PII fields are encrypted at rest.
type AuthIdentity struct {
	CollaboratorID      uuid.UUID            `json:"collaborator_id"`
	Username            string               `json:"username"`
	WebAuthnCredentials []WebAuthnCredential `json:"webauthn_credentials"`
	HasTOTP             bool                 `json:"has_totp"`
	HasRecoveryCodes    bool                 `json:"has_recovery_codes"`
	MFAEnrolledAt       *time.Time           `json:"mfa_enrolled_at,omitempty"`
	LastLoginAt         *time.Time           `json:"last_login_at,omitempty"`
	FailedAttempts      int                  `json:"failed_attempts"`
	LockedUntil           *time.Time           `json:"locked_until,omitempty"`
	PasswordHash          *string              `json:"-"`
	PasswordScheme        *string              `json:"-"`
	PasswordUpdatedAt     *time.Time           `json:"password_updated_at,omitempty"`
	PasswordExpiresAt     *time.Time           `json:"password_expires_at,omitempty"`
	PasswordMustChange    bool                 `json:"password_must_change"`
	PasswordMetadata      map[string]any       `json:"password_metadata,omitempty"`
	CreatedAt             time.Time            `json:"created_at"`
	UpdatedAt             time.Time            `json:"updated_at"`
}

// WebAuthnCredential is one passkey/security-key registration.
type WebAuthnCredential struct {
	ID              string    `json:"id"`
	PublicKey       []byte    `json:"public_key"`
	AttestationType string    `json:"attestation_type"`
	AAGUID          string    `json:"aaguid"`
	SignCount       uint32    `json:"sign_count"`
	UserAgent       string    `json:"user_agent"`
	CreatedAt       time.Time `json:"created_at"`
}

// MFAEnrollToken is one signed magic-link issued during onboarding/recovery.
// TokenHash stays server-side only; the raw token leaves the service exactly
// once (in the email body).
type MFAEnrollToken struct {
	ID             uuid.UUID  `json:"id"`
	CollaboratorID uuid.UUID  `json:"collaborator_id"`
	TokenHash      string     `json:"-"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// UpsertAuthIdentityRequest creates or refreshes the identity row for one
// Collaborator. Username defaults to LOWER(primary_email) and is the SCIM/SAML
// principal.
type UpsertAuthIdentityRequest struct {
	CollaboratorID string `json:"collaborator_id"`
	Username       string `json:"username"`
}
