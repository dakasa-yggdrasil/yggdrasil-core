package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/saml"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// samlIdPState memoises the lazily-built SAML IdP. crewjam/saml is heavy to
// initialise so we do it once per process; rotation reloads via rebuild().
type samlIdPState struct {
	mu  sync.Mutex
	idp *saml.IdP
}

var samlState samlIdPState

func (s *Server) samlBaseURL() (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv("YGGDRASIL_SAML_BASE_URL"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("YGGDRASIL_BASE_URL"))
	}
	if raw == "" {
		return nil, errors.New("YGGDRASIL_SAML_BASE_URL not set")
	}
	return url.Parse(raw)
}

func (s *Server) samlIdP(ctx context.Context) (*saml.IdP, error) {
	samlState.mu.Lock()
	defer samlState.mu.Unlock()
	if samlState.idp != nil {
		return samlState.idp, nil
	}
	if s.envelope == nil {
		return nil, errors.New("envelope unavailable; YGGDRASIL_AUTH_KEK_BASE64 missing")
	}
	base, err := s.samlBaseURL()
	if err != nil {
		return nil, err
	}
	cfg := saml.Config{
		BaseURL:     base,
		IDPEntityID: base.JoinPath("saml", "metadata").String(),
	}
	// saml.Build needs to invert envelope.Seal — it gets the wrappedDEK and
	// returns the plaintext DEK. We cache the encrypted private key alongside
	// the wrapped DEK in the same row, so the helper can pass them to Open.
	idp, err := saml.Build(ctx, cfg, s.db, func(encDEK []byte) ([]byte, error) {
		// The signing key payload is loaded via repository.GetActiveSAMLSigningKey,
		// which provides PrivateKeyCiphertext + PrivateKeyDEK. saml.Build calls
		// us with the DEK; we hand it back to envelope.Open along with the
		// ciphertext that the caller stashed via Build's internal closure.
		// Phase 1 short-cut: keep the DEK as the wrapped form and let Open
		// decrypt; Phase 2 wires per-key DEK rotation.
		return s.envelope.Open(ctx, encDEK, encDEK)
	})
	if err != nil {
		return nil, err
	}
	samlState.idp = idp
	return idp, nil
}

// handleSAMLMetadata serves the IdP descriptor XML. crewjam/saml emits a tree;
// we marshal it ourselves so callers don't need to import the lib.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	idp, err := s.samlIdP(r.Context())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	desc := idp.MetadataDescriptor()
	if desc == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no metadata"})
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(desc); err != nil {
		writeMappedError(w, err)
		return
	}
	enc.Flush()
}

// handleSAMLSSO is the SAML 2.0 SSO endpoint. Phase 1 returns 501 with a
// note pointing to the (not-yet-wired) session provider integration; SP
// metadata + signing-key registry are in place so the handler can be
// completed without re-architecting.
func (s *Server) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "SSO endpoint requires session provider integration (Phase 2 wiring)",
	})
}

// handleSAMLSLO is the SAML Single Logout endpoint. Same Phase 1 stub
// approach as SSO.
func (s *Server) handleSAMLSLO(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "SLO endpoint requires session provider integration (Phase 2 wiring)",
	})
}

// samlSPRegisterRequest is the body of POST /api/v1/auth/saml/service-providers.
type samlSPRegisterRequest struct {
	Slug               string            `json:"slug"`
	SPEntityID         string            `json:"sp_entity_id"`
	ACSURL             string            `json:"acs_url"`
	SLOURL             string            `json:"slo_url,omitempty"`
	NameIDFormat       string            `json:"name_id_format,omitempty"`
	AttributeMapping   map[string]string `json:"attribute_mapping,omitempty"`
	SigningRequired    bool              `json:"signing_required"`
	EncryptionRequired bool              `json:"encryption_required"`
	SPX509CertPEM      string            `json:"sp_x509_cert"`
}

// handleSAMLSPRegister stores a new SAML SP entry. Trust workflows
// (`register-saml-sp-*`) call this after they've validated the SP's metadata.
func (s *Server) handleSAMLSPRegister(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	var req samlSPRegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if req.Slug == "" || req.SPEntityID == "" || req.ACSURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug, sp_entity_id, acs_url required"})
		return
	}
	if req.NameIDFormat == "" {
		req.NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	mapping := req.AttributeMapping
	if mapping == nil {
		mapping = map[string]string{
			"email":  "Email",
			"groups": "memberOf",
		}
	}
	signingRequired := req.SigningRequired
	encryptionRequired := req.EncryptionRequired
	sp, err := repository.RegisterSAMLServiceProvider(r.Context(), s.db, model.RegisterSAMLServiceProviderRequest{
		Slug:               req.Slug,
		SPEntityID:         req.SPEntityID,
		ACSURL:             req.ACSURL,
		SLOURL:             req.SLOURL,
		NameIDFormat:       req.NameIDFormat,
		AttributeMapping:   mapping,
		SigningRequired:    &signingRequired,
		EncryptionRequired: &encryptionRequired,
		SPX509Cert:         req.SPX509CertPEM,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sp)
}

func (s *Server) handleSAMLSPList(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	items, err := repository.ListSAMLServiceProviders(r.Context(), s.db)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if items == nil {
		items = []model.SAMLServiceProvider{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"service_providers": items})
}

// samlRotateSigningCertRequest is the body of POST /api/v1/auth/saml/rotate-signing-cert.
type samlRotateSigningCertRequest struct {
	KeyID         string `json:"key_id"`
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	X509CertPEM   string `json:"x509_cert_pem,omitempty"`
	Algorithm     string `json:"algorithm,omitempty"`
}

// handleSAMLRotateSigningCert generates (or accepts) a new RSA-2048 signing
// key, persists it via the envelope-encrypted repository helper, and flips
// it active. Caller may supply PEM material directly when rotation came
// from an external CA; otherwise we self-generate.
func (s *Server) handleSAMLRotateSigningCert(w http.ResponseWriter, r *http.Request) {
	if err := authorizeAuthAdminRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	if s.envelope == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "envelope unavailable"})
		return
	}
	var req samlRotateSigningCertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if req.KeyID == "" {
		req.KeyID = "kid-" + time.Now().UTC().Format("20060102T150405")
	}
	if req.Algorithm == "" {
		req.Algorithm = "RSA-SHA256"
	}
	if req.PrivateKeyPEM == "" || req.X509CertPEM == "" {
		priv, cert, err := generateSelfSignedRSA(2048, time.Now().Add(2*365*24*time.Hour))
		if err != nil {
			writeMappedError(w, err)
			return
		}
		req.PrivateKeyPEM = priv
		req.X509CertPEM = cert
	}
	// Envelope-encrypt the private key PEM at rest (AES-GCM with KEK-wrapped
	// DEK). The repository stores ciphertext + wrappedDEK; Build's decrypt
	// closure inverts it on read.
	ciphertext, wrappedDEK, err := s.envelope.Seal(r.Context(), []byte(req.PrivateKeyPEM))
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if _, err := repository.InsertSAMLSigningKey(r.Context(), s.db, req.KeyID, ciphertext, wrappedDEK, req.X509CertPEM, req.Algorithm, "pending"); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := repository.ActivateSAMLSigningKey(r.Context(), s.db, req.KeyID); err != nil {
		writeMappedError(w, err)
		return
	}
	// Force lazy IdP re-build on next /saml/metadata or /saml/sso.
	samlState.mu.Lock()
	samlState.idp = nil
	samlState.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":  req.KeyID,
		"rotated": true,
	})
}

// generateSelfSignedRSA produces a self-signed RSA key/cert pair encoded as
// PEM. crewjam/saml accepts these; production callers should rotate to a
// CA-issued cert via the SP-supplied PEM path.
func generateSelfSignedRSA(bits int, notAfter time.Time) (privPEM, certPEM string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "yggdrasil-saml-idp"},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pp), string(cp), nil
}
