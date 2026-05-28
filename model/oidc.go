package model

import (
	"time"

	"github.com/google/uuid"
)

type OIDCClient struct {
	ClientID               string    `json:"client_id"`
	ClientSecretHash       string    `json:"-"`
	RedirectURIs           []string  `json:"redirect_uris"`
	PostLogoutRedirectURIs []string  `json:"post_logout_redirect_uris"`
	Scopes                 []string  `json:"scopes"`
	GrantTypes             []string  `json:"grant_types"`
	PKCERequired           bool      `json:"pkce_required"`
	// BackchannelLogoutURI: HTTPS endpoint where yggdrasil-core POSTs a signed
	// logout_token (RFC 8417) when the user's session terminates server-side.
	// Empty when the client hasn't opted into back-channel logout — in that
	// case the client is expected to call /api/v1/oidc/introspect per request
	// (RFC 7662 fallback). §13 INTEGRATION_CONTRACT.
	BackchannelLogoutURI string    `json:"backchannel_logout_uri,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// OIDCSessionLink ties one yggdrasil auth_session to one OIDC client so the
// RFC 8417 back-channel dispatcher knows which clients to notify when the
// session terminates. The SID claim shipped in the logout_token comes from
// this row so clients can correlate the back-channel signal with their own
// local session record.
type OIDCSessionLink struct {
	ID             uuid.UUID  `json:"id"`
	CollaboratorID uuid.UUID  `json:"collaborator_id"`
	ClientID       string     `json:"client_id"`
	SessionID      *uuid.UUID `json:"session_id,omitempty"`
	SID            uuid.UUID  `json:"sid"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	TerminatedAt   *time.Time `json:"terminated_at,omitempty"`
}

// SessionRevocation records every session revocation event so introspection
// (§13 RFC 7662) and back-channel logout (§13 RFC 8417) can answer "is this
// token still valid?" with a single index lookup. See migration
// 00047_session_revocation.sql for the table contract.
type SessionRevocation struct {
	ID                   uuid.UUID      `json:"id"`
	CollaboratorID       uuid.UUID      `json:"collaborator_id"`
	SessionJTI           *uuid.UUID     `json:"session_jti,omitempty"`
	RevokedAt            time.Time      `json:"revoked_at"`
	Reason               string         `json:"reason"`
	BroadcastCompletedAt *time.Time     `json:"broadcast_completed_at,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
}

type OIDCAuthRequest struct {
	ID                  uuid.UUID
	ClientID            string
	CollaboratorID      *uuid.UUID
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Nonce               string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}

type OIDCAuthCode struct {
	Code          string
	AuthRequestID uuid.UUID
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	CreatedAt     time.Time
}

type OIDCRefreshToken struct {
	Token          string
	CollaboratorID uuid.UUID
	ClientID       string
	Scopes         []string
	ExpiresAt      time.Time
	RotatedFrom    *string
	RevokedAt      *time.Time
	CreatedAt      time.Time
}

type OIDCSigningKey struct {
	ID         uuid.UUID
	Algorithm  string
	PrivatePEM string
	PublicJWK  map[string]any
	CreatedAt  time.Time
	ActiveAt   time.Time
	RetireAt   *time.Time
}

type OIDCProviderSettings struct {
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	DefaultTeamSlug     string   `json:"default_team_slug"`
	AutoProvision       bool     `json:"auto_provision"`
}
