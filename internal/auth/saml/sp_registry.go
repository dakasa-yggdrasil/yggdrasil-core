package saml

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	cjsaml "github.com/crewjam/saml"
)

// ErrSPNotFound mirrors cjsaml's missing-entity error using a sentinel value
// so the IdP returns the expected SAML status to clients.
var ErrSPNotFound = errors.New("saml service provider not found")

// dbSPRegistry adapts repository.SAMLServiceProviders to the
// cjsaml.ServiceProviderProvider interface used by the IdP.
type dbSPRegistry struct {
	db *sql.DB
}

// GetServiceProvider resolves a registered SP from its EntityID, then loads
// the trust metadata used to verify AuthnRequest signatures.
func (r *dbSPRegistry) GetServiceProvider(req *http.Request, serviceProviderID string) (*cjsaml.EntityDescriptor, error) {
	sp, err := repository.GetSAMLServiceProviderByEntityID(req.Context(), r.db, serviceProviderID)
	if err != nil {
		if errors.Is(err, repository.ErrSAMLServiceProviderNotFound) {
			return nil, ErrSPNotFound
		}
		return nil, fmt.Errorf("load sp: %w", err)
	}
	return descriptorFromModel(sp)
}

func descriptorFromModel(sp model.SAMLServiceProvider) (*cjsaml.EntityDescriptor, error) {
	desc := &cjsaml.EntityDescriptor{
		EntityID: sp.SPEntityID,
		SPSSODescriptors: []cjsaml.SPSSODescriptor{
			{
				AssertionConsumerServices: []cjsaml.IndexedEndpoint{
					{
						Binding:  cjsaml.HTTPPostBinding,
						Location: sp.ACSURL,
						Index:    0,
					},
				},
				AuthnRequestsSigned: &sp.SigningRequired,
				WantAssertionsSigned: &sp.SigningRequired,
			},
		},
	}
	if sp.SLOURL != "" {
		desc.SPSSODescriptors[0].SingleLogoutServices = []cjsaml.Endpoint{{
			Binding:  cjsaml.HTTPRedirectBinding,
			Location: sp.SLOURL,
		}}
	}
	if sp.SPX509Cert != "" {
		cert, err := parseCertPEM(sp.SPX509Cert)
		if err != nil {
			return nil, fmt.Errorf("parse sp cert: %w", err)
		}
		desc.SPSSODescriptors[0].KeyDescriptors = []cjsaml.KeyDescriptor{{
			Use: "signing",
			KeyInfo: cjsaml.KeyInfo{
				X509Data: cjsaml.X509Data{
					X509Certificates: []cjsaml.X509Certificate{{Data: certBase64(cert)}},
				},
			},
		}}
	}
	return desc, nil
}

func parseCertPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certBase64(cert *x509.Certificate) string {
	// crewjam/saml expects raw base64 (no PEM headers) inside X509Certificate.
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	body := []byte{}
	for _, line := range splitLines(string(out)) {
		if line == "-----BEGIN CERTIFICATE-----" || line == "-----END CERTIFICATE-----" || line == "" {
			continue
		}
		body = append(body, []byte(line)...)
	}
	return string(body)
}

func splitLines(s string) []string {
	out := []string{}
	start := 0
	for i, c := range s {
		if c == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
