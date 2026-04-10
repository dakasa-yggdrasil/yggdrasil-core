package model

import (
	"time"

	"github.com/google/uuid"
)

// ThirdPartyIdentity links one external identity provider account to one collaborator.
type ThirdPartyIdentity struct {
	ID                  uuid.UUID      `json:"id"`
	CollaboratorID      uuid.UUID      `json:"collaborator_id"`
	Provider            string         `json:"provider"`
	Subject             string         `json:"subject"`
	Status              string         `json:"status"`
	Login               string         `json:"login,omitempty"`
	Email               string         `json:"email,omitempty"`
	DisplayName         string         `json:"display_name,omitempty"`
	ProfileURL          string         `json:"profile_url,omitempty"`
	AvatarURL           string         `json:"avatar_url,omitempty"`
	Claims              map[string]any `json:"claims,omitempty"`
	Metadata            map[string]any `json:"metadata,omitempty"`
	LastAuthenticatedAt *time.Time     `json:"last_authenticated_at,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

// UpsertThirdPartyIdentityRequest creates or updates one linked third-party identity for one collaborator.
type UpsertThirdPartyIdentityRequest struct {
	CollaboratorID string         `json:"collaborator_id"`
	Provider       string         `json:"provider"`
	Subject        string         `json:"subject"`
	Status         string         `json:"status,omitempty"`
	Login          string         `json:"login,omitempty"`
	Email          string         `json:"email,omitempty"`
	DisplayName    string         `json:"display_name,omitempty"`
	ProfileURL     string         `json:"profile_url,omitempty"`
	AvatarURL      string         `json:"avatar_url,omitempty"`
	Claims         map[string]any `json:"claims,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// ListThirdPartyIdentitiesRequest filters linked third-party identities.
type ListThirdPartyIdentitiesRequest struct {
	CollaboratorID string `json:"collaborator_id,omitempty"`
	Provider       string `json:"provider,omitempty"`
	Status         string `json:"status,omitempty"`
}

// DeleteThirdPartyIdentityRequest removes one linked external identity.
type DeleteThirdPartyIdentityRequest struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

// LoginWithThirdPartyIdentityRequest starts a session from one externally verified identity.
type LoginWithThirdPartyIdentityRequest struct {
	Provider        string         `json:"provider"`
	Subject         string         `json:"subject"`
	Login           string         `json:"login,omitempty"`
	Email           string         `json:"email,omitempty"`
	DisplayName     string         `json:"display_name,omitempty"`
	ProfileURL      string         `json:"profile_url,omitempty"`
	AvatarURL       string         `json:"avatar_url,omitempty"`
	Claims          map[string]any `json:"claims,omitempty"`
	AutoLinkByEmail bool           `json:"auto_link_by_email,omitempty"`
	SessionMetadata map[string]any `json:"session_metadata,omitempty"`
}
