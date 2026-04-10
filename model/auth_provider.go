package model

import (
	"time"

	"github.com/google/uuid"
)

// ThirdPartyAuthProvider stores one core-owned OAuth/OIDC provider configuration.
type ThirdPartyAuthProvider struct {
	ID               uuid.UUID      `json:"id"`
	Name             string         `json:"name"`
	Type             string         `json:"type"`
	Status           string         `json:"status"`
	DisplayName      string         `json:"display_name,omitempty"`
	IssuerURL        string         `json:"issuer_url,omitempty"`
	AuthorizeURL     string         `json:"authorize_url,omitempty"`
	TokenURL         string         `json:"token_url,omitempty"`
	UserInfoURL      string         `json:"userinfo_url,omitempty"`
	ClientID         string         `json:"client_id,omitempty"`
	ClientSecretRef  string         `json:"client_secret_ref,omitempty"`
	Scopes           []string       `json:"scopes,omitempty"`
	AutoLinkByEmail  bool           `json:"auto_link_by_email,omitempty"`
	SubjectField     string         `json:"subject_field,omitempty"`
	LoginField       string         `json:"login_field,omitempty"`
	EmailField       string         `json:"email_field,omitempty"`
	DisplayNameField string         `json:"display_name_field,omitempty"`
	AvatarURLField   string         `json:"avatar_url_field,omitempty"`
	ProfileURLField  string         `json:"profile_url_field,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// UpsertThirdPartyAuthProviderRequest creates or updates one auth provider config.
type UpsertThirdPartyAuthProviderRequest struct {
	Name             string         `json:"name"`
	Type             string         `json:"type,omitempty"`
	Status           string         `json:"status,omitempty"`
	DisplayName      string         `json:"display_name,omitempty"`
	IssuerURL        string         `json:"issuer_url,omitempty"`
	AuthorizeURL     string         `json:"authorize_url,omitempty"`
	TokenURL         string         `json:"token_url,omitempty"`
	UserInfoURL      string         `json:"userinfo_url,omitempty"`
	ClientID         string         `json:"client_id,omitempty"`
	ClientSecret     string         `json:"client_secret,omitempty"`
	ClientSecretRef  string         `json:"client_secret_ref,omitempty"`
	Scopes           []string       `json:"scopes,omitempty"`
	AutoLinkByEmail  bool           `json:"auto_link_by_email,omitempty"`
	SubjectField     string         `json:"subject_field,omitempty"`
	LoginField       string         `json:"login_field,omitempty"`
	EmailField       string         `json:"email_field,omitempty"`
	DisplayNameField string         `json:"display_name_field,omitempty"`
	AvatarURLField   string         `json:"avatar_url_field,omitempty"`
	ProfileURLField  string         `json:"profile_url_field,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// ListThirdPartyAuthProvidersRequest filters auth providers.
type ListThirdPartyAuthProvidersRequest struct {
	Type   string `json:"type,omitempty"`
	Status string `json:"status,omitempty"`
}

// GetThirdPartyAuthProviderRequest resolves one provider by name.
type GetThirdPartyAuthProviderRequest struct {
	Name string `json:"name"`
}

// DeleteThirdPartyAuthProviderRequest removes one provider by name.
type DeleteThirdPartyAuthProviderRequest struct {
	Name string `json:"name"`
}
