// Package saml hosts the read-side SAML 2.0 Identity Provider used to federate
// downstream Service Providers (GitHub Enterprise SSO, AWS Identity Center,
// Slack Enterprise, Google Workspace) onto Yggdrasil collaborators.
//
// Yggdrasil owns the assertions: each AuthnRequest from a registered SP
// resolves to a Collaborator via the active session cookie, and Yggdrasil
// emits a signed Response with attribute_mapping-driven claims.
package saml

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"

	cjsaml "github.com/crewjam/saml"
)

// Config is the minimum binding the host app provides to construct an IdP.
type Config struct {
	BaseURL    *url.URL  // e.g. https://yggdrasil.dakasa.me
	IDPEntityID string   // e.g. https://yggdrasil.dakasa.me/saml/metadata
}

// IdP wraps crewjam/saml's identity-provider with a DB-backed signing-key and
// SP-registry adapter. Construct via Build().
type IdP struct {
	Cfg     Config
	IDP     *cjsaml.IdentityProvider
	DB      *sql.DB
}

// ErrIdPNotInitialized is returned by handlers when Build was never called.
var ErrIdPNotInitialized = errors.New("saml IdP not initialized")

// Build wires DB-backed signing key and SP registry into an IdP. The active
// signing key must already exist (rotate via the trust workflow); this just
// loads the current one.
func Build(ctx context.Context, cfg Config, db *sql.DB, decryptDEK func(encDEK []byte) ([]byte, error)) (*IdP, error) {
	if cfg.BaseURL == nil {
		return nil, fmt.Errorf("BaseURL required")
	}
	if cfg.IDPEntityID == "" {
		return nil, fmt.Errorf("IDPEntityID required")
	}
	if db == nil {
		return nil, fmt.Errorf("db required")
	}
	if decryptDEK == nil {
		return nil, fmt.Errorf("decryptDEK required")
	}

	key, err := repository.GetActiveSAMLSigningKey(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("get active signing key: %w", err)
	}
	priv, cert, err := materializeSigningKey(key, decryptDEK)
	if err != nil {
		return nil, fmt.Errorf("materialize signing key: %w", err)
	}

	idp := &cjsaml.IdentityProvider{
		Key:         priv,
		Certificate: cert,
		MetadataURL: *cfg.BaseURL.JoinPath("saml", "metadata"),
		SSOURL:      *cfg.BaseURL.JoinPath("saml", "sso"),
		LogoutURL:   *cfg.BaseURL.JoinPath("saml", "slo"),
		ServiceProviderProvider: &dbSPRegistry{db: db},
		AssertionMaker:          dbAssertionMaker{db: db},
	}
	return &IdP{Cfg: cfg, IDP: idp, DB: db}, nil
}

func materializeSigningKey(k model.SAMLSigningKey, decryptDEK func([]byte) ([]byte, error)) (*rsa.PrivateKey, *x509.Certificate, error) {
	if len(k.PrivateKeyDEK) == 0 || len(k.PrivateKeyCiphertext) == 0 {
		return nil, nil, fmt.Errorf("signing key missing ciphertext or DEK")
	}
	dek, err := decryptDEK(k.PrivateKeyDEK)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt DEK: %w", err)
	}
	pkBytes, err := openPrivateKey(k.PrivateKeyCiphertext, dek)
	if err != nil {
		return nil, nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(pkBytes)
	if err != nil {
		// fall back to PKCS1
		rsaKey, err1 := x509.ParsePKCS1PrivateKey(pkBytes)
		if err1 != nil {
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}
		priv = rsaKey
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("signing key is not RSA")
	}
	cert, err := parseCertPEM(k.X509CertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert: %w", err)
	}
	return rsaKey, cert, nil
}

// MetadataDescriptor returns the IdP metadata document tree, ready to be
// marshalled to XML by the metadata handler.
func (i *IdP) MetadataDescriptor() *cjsaml.EntityDescriptor {
	if i == nil || i.IDP == nil {
		return nil
	}
	d := i.IDP.Metadata()
	d.EntityID = i.Cfg.IDPEntityID
	d.ValidUntil = time.Now().Add(24 * time.Hour)
	return d
}
