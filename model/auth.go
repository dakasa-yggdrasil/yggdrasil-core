package model

import (
	"time"

	"github.com/google/uuid"
)

// PasswordCredential stores one local password auth configuration for a collaborator.
type PasswordCredential struct {
	CollaboratorID    uuid.UUID      `json:"collaborator_id"`
	Status            string         `json:"status"`
	PasswordScheme    string         `json:"password_scheme"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	PasswordUpdatedAt time.Time      `json:"password_updated_at"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// AuthSession is the persisted session state stored by the core.
type AuthSession struct {
	ID             uuid.UUID      `json:"id"`
	CollaboratorID uuid.UUID      `json:"collaborator_id"`
	Status         string         `json:"status"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	LastSeenAt     *time.Time     `json:"last_seen_at,omitempty"`
	ExpiresAt      time.Time      `json:"expires_at"`
	RevokedAt      *time.Time     `json:"revoked_at,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// AuthSessionEnvelope is the normalized auth/session response shape returned by the HTTP API.
type AuthSessionEnvelope struct {
	Authenticated bool          `json:"authenticated"`
	Collaborator  *Collaborator `json:"collaborator,omitempty"`
	Session       *AuthSession  `json:"session,omitempty"`
}

// UpsertPasswordCredentialRequest configures one local password for an existing collaborator.
type UpsertPasswordCredentialRequest struct {
	CollaboratorID string         `json:"collaborator_id"`
	Password       string         `json:"password"`
	Status         string         `json:"status,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// LoginWithPasswordRequest validates local credentials. HTTP login callers
// receive mfa_required until a supported MFA factor is supplied for enrolled
// identities.
type LoginWithPasswordRequest struct {
	Identifier   string         `json:"identifier"`
	Password     string         `json:"password"`
	TOTPCode     string         `json:"totp_code,omitempty"`
	RecoveryCode string         `json:"recovery_code,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}
