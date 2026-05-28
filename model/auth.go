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

// AuthSessionView is the listing shape used by `GET /api/v1/me/sessions`
// — adds the device columns from the SQL row so a user can recognize
// "the laptop I left at the conference" by user_agent / IP.
//
// Token hashes are NEVER included. ID is opaque (UUID, not the token).
type AuthSessionView struct {
	ID                uuid.UUID  `json:"id"`
	CollaboratorID    uuid.UUID  `json:"collaborator_id"`
	Status            string     `json:"status"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	ExpiresAt         time.Time  `json:"expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UserAgent         string     `json:"user_agent,omitempty"`
	IPAddress         string     `json:"ip_address,omitempty"`
	DeviceFingerprint string     `json:"device_fingerprint,omitempty"`
}

// AuthSessionEnvelope is the normalized auth/session response shape returned by the HTTP API.
//
// MFAEnrolledAt is sourced from auth_identities.mfa_enrolled_at (which doesn't
// live on the Collaborator row) so that clients — like surface-console — can
// drive the MFA-enrollment guard without an extra round-trip. Nil = the user
// has never enrolled an MFA factor yet.
//
// Permissions é a lista resolvida de actions yggdrasil:* que o user pode
// executar, derivada de team_grants em instances do tipo yggdrasil-self pra
// os times ativos do user. Um único entry "yggdrasil:*" significa god-mode
// (grant wildcard OR traits.yggdrasil_admin=true). O FE (PermissionGate,
// usePermission) usa essas chaves pra esconder rotas e desabilitar ações.
type AuthSessionEnvelope struct {
	Authenticated bool          `json:"authenticated"`
	Collaborator  *Collaborator `json:"collaborator,omitempty"`
	Session       *AuthSession  `json:"session,omitempty"`
	MFAEnrolledAt *time.Time    `json:"mfa_enrolled_at,omitempty"`
	Permissions   []string      `json:"permissions,omitempty"`
	// CSRFToken is the per-session CSRF token derived deterministically
	// from session.id + a server-side HMAC secret (audit 2026-05-27 A7).
	// Frontend mirrors this value in the X-CSRF-Token request header on
	// every state-changing request (POST/PUT/DELETE/PATCH). The middleware
	// recomputes the HMAC server-side and rejects mismatches — defense in
	// depth on top of SameSite=Strict (A6).
	//
	// Emitted only when Authenticated=true.
	CSRFToken string `json:"csrf_token,omitempty"`
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
