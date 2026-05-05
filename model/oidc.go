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
	CreatedAt              time.Time `json:"created_at"`
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
