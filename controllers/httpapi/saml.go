package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	cjsaml "github.com/crewjam/saml"
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
	idp, err := saml.Build(ctx, cfg, s.db, func(ciphertext, wrappedDEK []byte) ([]byte, error) {
		return s.envelope.Open(ctx, ciphertext, wrappedDEK)
	})
	if err != nil {
		return nil, err
	}
	idp.IDP.SessionProvider = samlSessionProvider{db: s.db}
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

// handleSAMLSSO is the SAML 2.0 SSO endpoint. The active Yggdrasil session is
// the only authority: if no session cookie exists, the browser is sent to
// /login with the full SAMLRequest/RelayState preserved in return_to.
func (s *Server) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	idp, err := s.samlIdP(r.Context())
	if err != nil {
		writeMappedError(w, err)
		return
	}
	idp.IDP.SessionProvider = samlSessionProvider{db: s.db}
	idp.IDP.ServeSSO(w, r)
}

// handleSAMLSLO clears the local session cookie. Full SP-initiated logout
// response signing can be layered onto this later without changing the source
// of truth: Yggdrasil owns the session.
func (s *Server) handleSAMLSLO(w http.ResponseWriter, r *http.Request) {
	clearAuthCookie(w)
	if r.Method == http.MethodGet {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
}

type samlSessionProvider struct {
	db *sql.DB
}

func (p samlSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, _ *cjsaml.IdpAuthnRequest) *cjsaml.Session {
	token, ok := extractAuthToken(r)
	if !ok {
		redirectToSAMLLogin(w, r)
		return nil
	}
	session, collaborator, err := repository.ResolveAuthSession(r.Context(), p.db, token)
	if err != nil {
		if isAuthUnauthorizedError(err) {
			clearAuthCookie(w)
			redirectToSAMLLogin(w, r)
			return nil
		}
		writeMappedError(w, err)
		return nil
	}

	return buildSAMLSession(r.Context(), p.db, session, collaborator)
}

func redirectToSAMLLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.RequestURI()
	if strings.TrimSpace(returnTo) == "" {
		returnTo = "/saml/sso"
	}
	http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
}

func buildSAMLSession(ctx context.Context, db *sql.DB, session model.AuthSession, collaborator model.Collaborator) *cjsaml.Session {
	email := strings.TrimSpace(collaborator.PrimaryEmail)
	username := strings.ToLower(email)
	if username == "" {
		username = collaborator.Slug
	}
	fullName, givenName, familyName, preferredName := samlCollaboratorNames(collaborator)
	if fullName == "" {
		fullName = collaborator.DisplayName
	}
	if preferredName == "" {
		preferredName = fullName
	}

	custom := []cjsaml.Attribute{}
	custom = appendSAMLAttribute(custom, "email", email)
	custom = appendSAMLAttribute(custom, "primary_email", email)
	custom = appendSAMLAttribute(custom, "display_name", collaborator.DisplayName)
	custom = appendSAMLAttribute(custom, "preferred_name", preferredName)
	custom = appendSAMLAttribute(custom, "title", firstNonEmptyString(
		stringValue(collaborator.EmploymentData["title"]),
		stringValue(collaborator.EmploymentData["role"]),
	))
	custom = appendSAMLAttribute(custom, "department", stringValue(collaborator.EmploymentData["department"]))
	custom = appendSAMLAttribute(custom, "cost_center", stringValue(collaborator.EmploymentData["cost_center"]))
	custom = appendSAMLAttribute(custom, "yggdrasil_slug", collaborator.Slug)
	custom = appendSAMLAttribute(custom, "avatar_url", firstNonEmptyString(
		stringValue(mapValue(collaborator.PersonalData["profile"])["avatar_url"]),
		stringValue(collaborator.PersonalData["avatar_url"]),
	))

	return &cjsaml.Session{
		ID:               session.ID.String(),
		CreateTime:       session.CreatedAt,
		ExpireTime:       session.ExpiresAt,
		Index:            session.ID.String(),
		NameID:           username,
		NameIDFormat:     "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		SubjectID:        username,
		Groups:           samlGroupsForCollaborator(ctx, db, collaborator),
		UserName:         username,
		UserEmail:        email,
		UserCommonName:   fullName,
		UserSurname:      familyName,
		UserGivenName:    givenName,
		CustomAttributes: custom,
	}
}

func samlCollaboratorNames(collaborator model.Collaborator) (fullName, givenName, familyName, preferredName string) {
	profile := mapValue(collaborator.PersonalData["profile"])
	givenName = firstNonEmptyString(
		stringValue(profile["given_name"]),
		stringValue(collaborator.PersonalData["given_name"]),
		stringValue(collaborator.PersonalData["first_name"]),
	)
	familyName = firstNonEmptyString(
		stringValue(profile["family_name"]),
		stringValue(collaborator.PersonalData["family_name"]),
		stringValue(collaborator.PersonalData["last_name"]),
	)
	preferredName = firstNonEmptyString(
		stringValue(collaborator.PersonalData["preferred_name"]),
		stringValue(profile["preferred_name"]),
		stringValue(collaborator.Traits["preferred_name"]),
	)
	fullName = firstNonEmptyString(
		stringValue(profile["full_name"]),
		stringValue(collaborator.PersonalData["full_name"]),
		strings.TrimSpace(givenName+" "+familyName),
		preferredName,
		strings.TrimSpace(collaborator.DisplayName),
	)
	if givenName == "" || familyName == "" {
		splitGiven, splitFamily := splitHumanName(fullName)
		if givenName == "" {
			givenName = splitGiven
		}
		if familyName == "" {
			familyName = splitFamily
		}
	}
	return fullName, givenName, familyName, preferredName
}

func samlGroupsForCollaborator(ctx context.Context, db *sql.DB, collaborator model.Collaborator) []string {
	seen := map[string]bool{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = true
		}
	}
	if memberships, err := repository.ListTeamMemberships(ctx, db, model.ListTeamMembershipsRequest{
		CollaboratorID: collaborator.ID.String(),
		ActiveOnly:     true,
	}); err == nil {
		for _, membership := range memberships {
			add("team:" + membership.TeamSlug)
			if role := strings.TrimSpace(membership.Role); role != "" {
				add("team:" + membership.TeamSlug + ":" + role)
			}
		}
	}
	if role := strings.TrimSpace(stringValue(collaborator.EmploymentData["role"])); role != "" {
		add("role:" + role)
	}
	out := make([]string, 0, len(seen))
	for group := range seen {
		out = append(out, group)
	}
	sort.Strings(out)
	return out
}

func appendSAMLAttribute(attrs []cjsaml.Attribute, name string, values ...string) []cjsaml.Attribute {
	filtered := make([]cjsaml.AttributeValue, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		filtered = append(filtered, cjsaml.AttributeValue{Type: "xs:string", Value: value})
	}
	if len(filtered) == 0 {
		return attrs
	}
	return append(attrs, cjsaml.Attribute{
		FriendlyName: name,
		Name:         name,
		NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		Values:       filtered,
	})
}

func splitHumanName(displayName string) (string, string) {
	parts := strings.Fields(strings.TrimSpace(displayName))
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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
