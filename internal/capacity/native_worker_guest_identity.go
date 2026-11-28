package capacity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const NativeWorkerGuestIdentityVersion = "native_worker_guest_read_identity_v1"
const NativeWorkerGuestWitnessPath = "/native-worker/network-witness"
const nativeWorkerGuestWitnessPort = "9445"

var errNativeGuestRead = errors.New("HOLD: protected Native guest witness is unavailable")

// This optional protected Go configuration has no manifest/RPC decoder. Its
// versioned files must be retained for every live Attempt of this execution
// binding. The public master proof is a purpose-separated public key, never a
// hash of private bootstrap material. It detects a replaced master at restart.
// CertificateValiditySeconds has no default and cannot exceed the pinned CA.
type NativeWorkerGuestReadConfig struct {
	Version                    string
	MasterVersion              string
	MasterFile                 string
	MasterPublicKey            string
	IssuerCAFile               string
	IssuerCASHA256             string
	IssuerKeyFile              string
	CertificateValiditySeconds int64
	NetworkTemplateFile        string
	NetworkTemplateSHA256      string
	MaxReadAgeSeconds          int
}

type nativeGuestReadIdentity struct {
	config       NativeWorkerGuestReadConfig
	master       []byte
	issuer       *x509.Certificate
	issuerKey    ed25519.PrivateKey
	issuerPEM    []byte
	policySHA256 string
	network      model.CapacityNativeWorkerNetworkTemplate
}

func nativeGuestHMAC(master []byte, purpose string, raw []byte) []byte {
	h := hmac.New(sha256.New, master)
	_, _ = h.Write([]byte(purpose))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(raw)
	return h.Sum(nil)
}

func nativeGuestMasterPublic(master []byte, version string) string {
	seed := nativeGuestHMAC(master, "dakasa.native-worker.guest-read.master-proof.v1", []byte(version))
	defer nativePrivateWipe(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer nativePrivateWipe(key)
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func newNativeGuestReadIdentity(c NativeWorkerGuestReadConfig) (*nativeGuestReadIdentity, error) {
	if c.Version != NativeWorkerGuestIdentityVersion || !marketID.MatchString(c.MasterVersion) || c.MaxReadAgeSeconds < 1 || c.MaxReadAgeSeconds > 120 || c.CertificateValiditySeconds < 1 || c.CertificateValiditySeconds > math.MaxInt64/int64(time.Second) ||
		!marketSHA.MatchString(c.IssuerCASHA256) || !marketSHA.MatchString(c.NetworkTemplateSHA256) {
		return nil, errNativeGuestRead
	}
	g := &nativeGuestReadIdentity{config: c}
	ok := false
	defer func() {
		if !ok {
			g.close()
		}
	}()
	var err error
	g.master, err = nativePrivateReadFile(c.MasterFile, 32, true)
	if err != nil || len(g.master) != 32 || bytes.Equal(g.master, make([]byte, 32)) || nativeGuestMasterPublic(g.master, c.MasterVersion) != c.MasterPublicKey {
		return nil, errNativeGuestRead
	}
	g.issuerPEM, err = nativePrivateReadFile(c.IssuerCAFile, 65536, false)
	if err != nil || nativePrivateSHA(g.issuerPEM) != c.IssuerCASHA256 {
		return nil, errNativeGuestRead
	}
	block, rest := pem.Decode(g.issuerPEM)
	if !bytes.HasPrefix(bytes.TrimSpace(g.issuerPEM), []byte("-----BEGIN CERTIFICATE-----")) || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errNativeGuestRead
	}
	g.issuer, err = x509.ParseCertificate(block.Bytes)
	if err != nil || !g.issuer.IsCA || !g.issuer.BasicConstraintsValid || g.issuer.KeyUsage&x509.KeyUsageCertSign == 0 || g.issuer.PublicKeyAlgorithm != x509.Ed25519 || !nativeGuestIssuerAllowsBothRoles(g.issuer) {
		return nil, errNativeGuestRead
	}
	keyRaw, err := nativePrivateReadFile(c.IssuerKeyFile, 32768, true)
	if err != nil {
		return nil, errNativeGuestRead
	}
	defer nativePrivateWipe(keyRaw)
	keyBlock, keyRest := pem.Decode(keyRaw)
	if !bytes.HasPrefix(bytes.TrimSpace(keyRaw), []byte("-----BEGIN PRIVATE KEY-----")) || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(keyBlock.Headers) != 0 || len(bytes.TrimSpace(keyRest)) != 0 {
		return nil, errNativeGuestRead
	}
	defer nativePrivateWipe(keyBlock.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errNativeGuestRead
	}
	key, valid := parsed.(ed25519.PrivateKey)
	if !valid || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), g.issuer.PublicKey.(ed25519.PublicKey)) {
		return nil, errNativeGuestRead
	}
	g.issuerKey = append(ed25519.PrivateKey(nil), key...)
	nativePrivateWipe(key)
	rawTemplate, err := nativePrivateReadFile(c.NetworkTemplateFile, 32768, false)
	if err != nil || nativePrivateSHA(rawTemplate) != c.NetworkTemplateSHA256 || nativeWorkerNetworkRPCDecode(rawTemplate, &g.network) != nil || NativeWorkerNetworkTemplateSHA256(g.network) != c.NetworkTemplateSHA256 {
		return nil, errNativeGuestRead
	}
	g.policySHA256 = NativeWorkerGuestIdentityPolicySHA256(c)
	ok = true
	return g, nil
}

// A CA EKU restriction applies to the whole chain. Both deterministic leaf
// roles must be usable before any private bootstrap is rendered.
func nativeGuestIssuerAllowsBothRoles(issuer *x509.Certificate) bool {
	if issuer == nil {
		return false
	}
	if len(issuer.ExtKeyUsage) == 0 && len(issuer.UnknownExtKeyUsage) == 0 {
		return true
	}
	server, client := false, false
	for _, usage := range issuer.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			return true
		case x509.ExtKeyUsageServerAuth:
			server = true
		case x509.ExtKeyUsageClientAuth:
			client = true
		}
	}
	return server && client
}

// Only public issuance declarations enter this durable Execution pin. Paths,
// raw keys, bootstrap material and response bodies never enter a public hash.
// The factory requires this value in the already immutable Attempt Execution.
func NativeWorkerGuestIdentityPolicySHA256(c NativeWorkerGuestReadConfig) string {
	raw, _ := json.Marshal(struct {
		Version           string `json:"version"`
		MasterVersion     string `json:"master_version"`
		MasterPublicKey   string `json:"master_public_key"`
		IssuerCA          string `json:"issuer_ca_sha256"`
		NetworkTemplate   string `json:"network_template_sha256"`
		ValiditySeconds   int64  `json:"certificate_validity_seconds"`
		MaxReadAgeSeconds int    `json:"max_read_age_seconds"`
	}{c.Version, c.MasterVersion, c.MasterPublicKey, c.IssuerCASHA256, c.NetworkTemplateSHA256, c.CertificateValiditySeconds, c.MaxReadAgeSeconds})
	return nativePrivateSHA(raw)
}

func (g *nativeGuestReadIdentity) close() {
	if g == nil {
		return
	}
	nativePrivateWipe(g.master)
	nativePrivateWipe(g.issuerKey)
	g.master, g.issuerKey = nil, nil
}

type nativeGuestReadCertificate struct {
	certificateDER, privateKeyDER []byte
	certificatePEM, privateKeyPEM []byte
	fingerprint                   string
	uri                           string
	notAfter                      time.Time
}

func (nativeGuestReadCertificate) String() string     { return "[private Native guest read certificate]" }
func (c nativeGuestReadCertificate) GoString() string { return c.String() }
func (nativeGuestReadCertificate) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_guest_read_certificate":"redacted"}`), nil
}

func (c *nativeGuestReadCertificate) close() {
	if c != nil {
		nativePrivateWipe(c.privateKeyDER)
		nativePrivateWipe(c.privateKeyPEM)
	}
}

func nativeGuestReadURI(pool, attempt, launch string) string {
	return "spiffe://dakasa/native-worker/" + pool + "/" + attempt + "/" + launch
}

// All identity bytes come from immutable Attempt/Launch plus versioned private
// configuration. No clock, random seed, provider response or S3 URL participates.
func (g *nativeGuestReadIdentity) derive(a model.CapacityNativeWorkerAttempt, launch []byte, source string) (nativeGuestReadCertificate, error) {
	return g.deriveRole(a, launch, source, "server")
}
func (g *nativeGuestReadIdentity) deriveClient(a model.CapacityNativeWorkerAttempt, launch []byte, source string) (nativeGuestReadCertificate, error) {
	return g.deriveRole(a, launch, source, "client")
}

func (g *nativeGuestReadIdentity) deriveRole(a model.CapacityNativeWorkerAttempt, launch []byte, systemSource, role string) (nativeGuestReadCertificate, error) {
	var out nativeGuestReadCertificate
	if (role != "server" && role != "client") || g == nil || len(g.master) != 32 || len(g.issuerKey) != ed25519.PrivateKeySize || !nativeGuestIssuerAllowsBothRoles(g.issuer) || a.CreatedAt.IsZero() || a.Execution.GuestIdentityPolicySHA256 != g.policySHA256 {
		return out, errNativeGuestRead
	}
	var l nativePrivateLaunch
	if DecodeNativeCapacity(json.RawMessage(launch), &l) != nil || l.SourceCommit != systemSource || nativePrivateSHA(launch) != a.LaunchSHA256 {
		return out, errNativeGuestRead
	}
	canonical, err := json.Marshal(l)
	if err != nil || !bytes.Equal(canonical, launch) || ValidateNativeWorkerLaunch(a, model.CapacityNativeWorkerLaunch{AttemptID: a.ID, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, Generation: a.Generation, FencingToken: a.FencingToken, OverlayIPv4: a.OverlayIPv4, TemplateSHA256: a.Execution.LaunchTemplateSHA256, PublicJSON: launch}) != nil {
		return out, errNativeGuestRead
	}
	ip, err := netip.ParseAddr(a.OverlayIPv4)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != a.OverlayIPv4 {
		return out, errNativeGuestRead
	}
	created := a.CreatedAt.UTC().Truncate(time.Second)
	expires := created.Add(time.Duration(g.config.CertificateValiditySeconds) * time.Second)
	if created.Before(g.issuer.NotBefore) || expires.After(g.issuer.NotAfter) || !expires.After(created) {
		return out, errNativeGuestRead
	}
	frame, err := json.Marshal(struct{ Version, Policy, Domain, Namespace, Binding, Scope, Pool, Attempt, Launch, Worker, Created, SystemSource string }{g.config.Version, g.policySHA256, a.Domain, a.Namespace, a.Execution.BindingName, a.Execution.ScopeSHA256, a.PoolUID, a.ID.String(), a.LaunchSHA256, a.OverlayIPv4, created.Format(time.RFC3339), systemSource})
	if err != nil {
		return out, errNativeGuestRead
	}
	seed := nativeGuestHMAC(g.master, "dakasa.native-worker.guest-read."+role+".key.v1", frame)
	defer nativePrivateWipe(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer nativePrivateWipe(private)
	serialRaw := nativeGuestHMAC(g.master, "dakasa.native-worker.guest-read."+role+".serial.v1", frame)
	defer nativePrivateWipe(serialRaw)
	serialRaw[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialRaw[:20])
	if serial.Sign() <= 0 {
		return out, errNativeGuestRead
	}
	uri := nativeGuestReadURI(a.PoolUID, a.ID.String(), a.LaunchSHA256)
	usage := x509.ExtKeyUsageServerAuth
	if role == "client" {
		uri += "/core-read"
		usage = x509.ExtKeyUsageClientAuth
	}
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return out, errNativeGuestRead
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "native-worker-" + a.ID.String()}, NotBefore: created, NotAfter: expires, SignatureAlgorithm: x509.PureEd25519, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.IP(ip.AsSlice())}, URIs: []*url.URL{parsedURI}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(nil, template, g.issuer, private.Public(), g.issuerKey)
	if err != nil {
		return out, errNativeGuestRead
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return out, errNativeGuestRead
	}
	return nativeGuestReadCertificate{certificateDER: der, privateKeyDER: keyDER, certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), privateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), fingerprint: nativePrivateSHA(der), uri: uri, notAfter: expires}, nil
}
