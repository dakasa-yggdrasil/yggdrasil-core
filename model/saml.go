package model

import (
	"time"

	"github.com/google/uuid"
)

// SAMLServiceProvider is one external SP configured to federate via the
// Yggdrasil SAML 2.0 IdP. Slug is a stable id (e.g. "github-enterprise").
type SAMLServiceProvider struct {
	ID                 uuid.UUID              `json:"id"`
	Slug               string                 `json:"slug"`
	SPEntityID         string                 `json:"sp_entity_id"`
	ACSURL             string                 `json:"acs_url"`
	SLOURL             string                 `json:"slo_url,omitempty"`
	NameIDFormat       string                 `json:"name_id_format"`
	AttributeMapping   map[string]string      `json:"attribute_mapping"`
	SigningRequired    bool                   `json:"signing_required"`
	EncryptionRequired bool                   `json:"encryption_required"`
	SPX509Cert         string                 `json:"sp_x509_cert"`
	Status             string                 `json:"status"`
	Metadata           map[string]interface{} `json:"metadata"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// SAMLSigningKey is one IdP private/public keypair. Multiple keys may exist
// during rotation windows; only one row is `status='active'` at a time.
type SAMLSigningKey struct {
	ID                   uuid.UUID  `json:"id"`
	KeyID                string     `json:"key_id"`
	PrivateKeyCiphertext []byte     `json:"-"`
	PrivateKeyDEK        []byte     `json:"-"`
	X509CertPEM          string     `json:"x509_cert_pem"`
	Algorithm            string     `json:"algorithm"`
	Status               string     `json:"status"`
	ActivatedAt          *time.Time `json:"activated_at,omitempty"`
	RetiredAt            *time.Time `json:"retired_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

// SAMLSession captures a single SSO assertion's lifecycle for SLO bookkeeping.
type SAMLSession struct {
	SPSlug      string    `json:"sp_slug"`
	SessionID   string    `json:"session_id"`
	NameID      string    `json:"name_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LogoutAtURL string    `json:"logout_at_url,omitempty"`
}

// RegisterSAMLServiceProviderRequest is the admin request to register one SP.
type RegisterSAMLServiceProviderRequest struct {
	Slug               string            `json:"slug"`
	SPEntityID         string            `json:"sp_entity_id"`
	ACSURL             string            `json:"acs_url"`
	SLOURL             string            `json:"slo_url,omitempty"`
	NameIDFormat       string            `json:"name_id_format,omitempty"`
	AttributeMapping   map[string]string `json:"attribute_mapping,omitempty"`
	SigningRequired    *bool             `json:"signing_required,omitempty"`
	EncryptionRequired *bool             `json:"encryption_required,omitempty"`
	SPX509Cert         string            `json:"sp_x509_cert,omitempty"`
}
