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

// WebAuthnCredential is one passkey/security-key registration. Persisted
// in auth_identities.webauthn_credentials (JSONB array). NEVER serialize
// PublicKey/Raw/AAGUID to the surface — those are at-rest material that
// the FE has no use for. Friendly fields (Name, DeviceKind, CreatedAt,
// LastUsedAt) are safe to surface.
//
// Multi-device support (2026-05-28): the auth_identities.webauthn_credentials
// column carries an array of these records — one per device the user
// enrolls. ID is the WebAuthn credential ID, base64url-encoded, used as
// the lookup key for rename/delete and as the device pivot in the login
// flow.
type WebAuthnCredential struct {
	// Wire identifier — WebAuthn credential ID, base64url-encoded. Used
	// as the lookup key for rename/delete + the device pivot during the
	// login ceremony.
	ID string `json:"id"`
	// Stable raw credential bytes (matching ID base64url-decoded). We
	// store it separately so the verifier doesn't have to base64-decode
	// on every login. NEVER returned to the FE.
	RawID []byte `json:"raw_id,omitempty"`
	// COSE-encoded public key. Used by go-webauthn for signature
	// verification. NEVER returned to the FE.
	PublicKey []byte `json:"public_key,omitempty"`
	// Attestation metadata — preserved for future re-verification via
	// the FIDO MDS (go-webauthn's Credential.Verify path).
	AttestationType   string `json:"attestation_type,omitempty"`
	AttestationFormat string `json:"attestation_format,omitempty"`
	// Raw attestation bytes — these MUST be preserved per
	// go-webauthn/webauthn/Credential.Attestation docs so the credential
	// can be re-verified against the FIDO Metadata Service at a later
	// date. NEVER returned to the FE.
	AttestationObject []byte `json:"attestation_object,omitempty"`
	AuthenticatorData []byte `json:"authenticator_data,omitempty"`
	ClientDataJSON    []byte `json:"client_data_json,omitempty"`
	PublicKeyAlgorithm int64 `json:"public_key_algorithm,omitempty"`
	// AAGUID identifies the authenticator model. Useful for device
	// fingerprinting in audit but not returned to the FE in list views.
	AAGUID string `json:"aaguid,omitempty"`
	// Sign counter — the WebAuthn anti-clone primitive. Each successful
	// login increments this; a value <= the stored value indicates a
	// cloned authenticator (replay) and we reject the login.
	SignCount uint32 `json:"sign_count"`
	// Transports the authenticator supports ("usb", "nfc", "ble",
	// "internal", "hybrid"). Surface uses this to render a hint.
	Transports []string `json:"transports,omitempty"`
	// BackupEligible / BackupState — surfaces use BackupEligible to
	// show "synced across devices" badge; BackupState whether the
	// authenticator currently has the credential backed up.
	BackupEligible bool `json:"backup_eligible,omitempty"`
	BackupState    bool `json:"backup_state,omitempty"`
	// Friendly name — user-supplied at enroll time + editable from the
	// /me/mfa page. Defaults to "Passkey 1", "Passkey 2" when the user
	// doesn't supply one. Surfaced to the FE.
	Name string `json:"name,omitempty"`
	// DeviceKind — "platform" (built-in, e.g. Touch ID, Windows Hello)
	// or "cross-platform" (roaming, e.g. YubiKey). Inferred from the
	// authenticator attachment at registration time. Surfaced to the FE.
	DeviceKind string `json:"device_kind,omitempty"`
	// User agent captured at registration. NOT returned to FE list view
	// (privacy: would leak device patterns); kept for forensics only.
	UserAgent string `json:"user_agent,omitempty"`
	// CreatedAt — when the credential was enrolled. Surfaced to the FE.
	CreatedAt time.Time `json:"created_at"`
	// LastUsedAt — most recent successful login with this credential.
	// nil when never used (just enrolled, never authenticated). Surfaced
	// to the FE so users can spot stale devices.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
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
