package repository

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
	"github.com/google/uuid"
)

const nativeReadinessSeedCount = 8

// Fresh per-run secrets are generated once, encrypted by the original journal
// transaction and resumed byte-for-byte. No Guest/WireGuard/issuer key is used.
// Slots: CA, Core client, floor/server, candidate/server, two signing keys,
// public diagnostic nonce, and the separate localhost admission bearer.
func nativeReadinessGenerateKeys(uuid.UUID, time.Time, time.Time) ([]byte, error) {
	raw := make([]byte, nativeReadinessSeedCount*ed25519.SeedSize)
	if _, err := rand.Read(raw); err != nil {
		clear(raw)
		return nil, errNativeReadinessRun
	}
	return raw, nil
}

type nativeReadinessKeys struct {
	seeds []byte
}

func newNativeReadinessKeys(raw []byte) (*nativeReadinessKeys, error) {
	if len(raw) != nativeReadinessSeedCount*ed25519.SeedSize {
		return nil, errNativeReadinessRun
	}
	return &nativeReadinessKeys{seeds: append([]byte(nil), raw...)}, nil
}

func (nativeReadinessKeys) String() string     { return "[private Native readiness run keys]" }
func (k nativeReadinessKeys) GoString() string { return k.String() }
func (nativeReadinessKeys) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_native_readiness_keys":"redacted"}`), nil
}

func (k *nativeReadinessKeys) close() {
	if k != nil {
		clear(k.seeds)
		k.seeds = nil
	}
}

func (k *nativeReadinessKeys) key(index int) (ed25519.PrivateKey, error) {
	if k == nil || len(k.seeds) != nativeReadinessSeedCount*ed25519.SeedSize || index < 0 || index >= 6 {
		return nil, errNativeReadinessRun
	}
	return ed25519.NewKeyFromSeed(k.seeds[index*ed25519.SeedSize : (index+1)*ed25519.SeedSize]), nil
}

func nativeReadinessCertificateEnd(end time.Time) time.Time {
	// DER timestamps have second precision. The independent exact HardNotAfter
	// remains the operation/proof deadline; a rounded certificate cannot renew it.
	ceil := end.UTC().Truncate(time.Second)
	if ceil.Before(end) {
		ceil = ceil.Add(time.Second)
	}
	return ceil
}

func nativeReadinessSerial(r nativeReadinessRun, purpose string) *big.Int {
	sum := sha256.Sum256([]byte(r.ID.String() + "/" + purpose))
	// Unique purpose/run identity, positive at most 159 bits, without depending
	// on a fresh random serial during retries of the same retained keys.
	sum[0] &= 0x7f
	sum[0] |= 1
	return new(big.Int).SetBytes(sum[:20])
}

func (k *nativeReadinessKeys) ca(r nativeReadinessRun) (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	key, err := k.key(0)
	if err != nil || r.ID == uuid.Nil || r.CreatedAt.IsZero() || !r.NotAfter.After(r.CreatedAt) {
		clear(key)
		return nil, nil, nil, errNativeReadinessRun
	}
	template := &x509.Certificate{SerialNumber: nativeReadinessSerial(r, "ca"), Subject: pkix.Name{CommonName: "Native readiness run " + r.ID.String()},
		NotBefore: r.CreatedAt.Add(-time.Second), NotAfter: nativeReadinessCertificateEnd(r.NotAfter), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		clear(key)
		return nil, nil, nil, errNativeReadinessRun
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		clear(key)
		return nil, nil, nil, errNativeReadinessRun
	}
	return parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (k *nativeReadinessKeys) leaf(r nativeReadinessRun, index int, role, ipv4 string) ([]byte, []byte, []byte, error) {
	if role != "controller" && role != "floor" && role != "candidate" || role == "controller" && index != 1 || role == "floor" && index != 2 || role == "candidate" && index != 3 {
		return nil, nil, nil, errNativeReadinessRun
	}
	ca, caKey, caPEM, err := k.ca(r)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(caKey)
	key, err := k.key(index)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(key)
	usage := x509.ExtKeyUsageClientAuth
	template := &x509.Certificate{SerialNumber: nativeReadinessSerial(r, role), Subject: pkix.Name{CommonName: "Native readiness " + role},
		NotBefore: r.CreatedAt.Add(-time.Second), NotAfter: nativeReadinessCertificateEnd(r.NotAfter), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if role != "controller" {
		ip := net.ParseIP(ipv4)
		if ip == nil || ip.To4() == nil || ip.String() != ipv4 {
			return nil, nil, nil, errNativeReadinessRun
		}
		template.IPAddresses, usage = []net.IP{ip}, x509.ExtKeyUsageServerAuth
	} else if ipv4 != "" {
		return nil, nil, nil, errNativeReadinessRun
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		return nil, nil, nil, errNativeReadinessRun
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, errNativeReadinessRun
	}
	defer clear(private)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), caPEM, nil
}

func nativeReadinessPEMFingerprint(raw []byte) (string, error) {
	b, tail := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" || len(tail) != 0 {
		return "", errNativeReadinessRun
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// Config contains only public identity. admission.key is projected separately
// from the original admission Secret; it is not duplicated in this Secret.
func (k *nativeReadinessKeys) secret(r nativeReadinessRun, c nativeworkerprobe.Config) (map[string][]byte, string, error) {
	if c.Identity.RunID != r.ID.String() || c.Identity.AttemptID != r.Identity.AttemptID.String() || c.Identity.BirthSHA256 != r.Identity.BirthSHA256 || c.Identity.PoolUID != r.Identity.PoolUID || !c.NotBefore.Equal(r.CreatedAt) || !c.HardNotAfter.Equal(r.NotAfter) {
		return nil, "", errNativeReadinessRun
	}
	server, ownSigning, peerSigning := 2, 4, 5
	if c.Identity.Role == "candidate" {
		server, ownSigning, peerSigning = 3, 5, 4
	} else if c.Identity.Role != "floor" {
		return nil, "", errNativeReadinessRun
	}
	controller, clientKey, _, err := k.leaf(r, 1, "controller", "")
	clear(clientKey)
	if err != nil {
		return nil, "", err
	}
	controllerSHA, err := nativeReadinessPEMFingerprint(controller)
	if err != nil || c.ControllerLeafSHA256 != controllerSHA {
		return nil, "", errNativeReadinessRun
	}
	cert, key, ca, err := k.leaf(r, server, c.Identity.Role, c.Identity.PodIPv4)
	if err != nil {
		return nil, "", err
	}
	signing, err := k.key(ownSigning)
	if err != nil {
		clear(key)
		return nil, "", err
	}
	peer, err := k.key(peerSigning)
	if err != nil {
		clear(key)
		clear(signing)
		return nil, "", err
	}
	defer clear(peer)
	c.Nonce = base64.StdEncoding.EncodeToString(k.seeds[6*ed25519.SeedSize : 7*ed25519.SeedSize])
	raw, err := json.Marshal(c)
	if err != nil {
		clear(key)
		clear(signing)
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return map[string][]byte{"config.json": raw, "server.crt": cert, "server.key": key, "controller-ca.crt": ca, "signing.key": signing, "peer-signing.pub": append([]byte(nil), peer.Public().(ed25519.PublicKey)...)}, hex.EncodeToString(sum[:]), nil
}

func (k *nativeReadinessKeys) admissionKey() ([]byte, error) {
	if k == nil || len(k.seeds) != nativeReadinessSeedCount*ed25519.SeedSize {
		return nil, errNativeReadinessRun
	}
	return []byte(base64.RawURLEncoding.EncodeToString(k.seeds[7*ed25519.SeedSize:])), nil
}

// Control uses the exact per-run leaf and CA, no proxy/redirect/environment
// authority, normal IP SAN validation, and only the fixed PodIP/9446 endpoint.
func (k *nativeReadinessKeys) client(ctx context.Context, r nativeReadinessRun, role, ip string) (*http.Client, func(), error) {
	if ctx == nil || ctx.Err() != nil || (role != "floor" && role != "candidate") {
		return nil, nil, errNativeReadinessRun
	}
	cert, private, ca, err := k.leaf(r, 1, "controller", "")
	if err != nil {
		return nil, nil, err
	}
	defer clear(private)
	pair, err := tls.X509KeyPair(cert, private)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			if key, valid := pair.PrivateKey.(ed25519.PrivateKey); valid {
				clear(key)
			}
		}
	}()
	index := 2
	if role == "candidate" {
		index = 3
	}
	server, serverKey, _, err := k.leaf(r, index, role, ip)
	clear(serverKey)
	want, fe := nativeReadinessPEMFingerprint(server)
	pool := x509.NewCertPool()
	if err != nil || fe != nil || !pool.AppendCertsFromPEM(ca) {
		return nil, nil, errNativeReadinessRun
	}
	endpoint := net.JoinHostPort(ip, strconv.Itoa(nativeworkerprobe.Port))
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(call context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != endpoint {
				return nil, errNativeReadinessRun
			}
			return dialer.DialContext(call, network, address)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair}, VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
				return errNativeReadinessRun
			}
			sum := sha256.Sum256(s.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != want {
				return errNativeReadinessRun
			}
			return nil
		}}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errNativeReadinessRun }}
	close := func() {
		transport.CloseIdleConnections()
		if key, ok := pair.PrivateKey.(ed25519.PrivateKey); ok {
			clear(key)
		}
	}
	ok = true
	return client, close, nil
}
