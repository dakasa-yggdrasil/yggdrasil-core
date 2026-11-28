package nativeworkerprobe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func secretStatAllowed(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1 && (s.Uid == 0 || s.Uid == uint32(os.Geteuid())) && (info.Mode().Perm()&0040 == 0 || s.Gid == uint32(os.Getegid()))
}

func secretStatEqual(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, valid := b.Sys().(*syscall.Stat_t)
	return ok && valid && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func singleCertificate(raw []byte) (*x509.Certificate, bool) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, false
	}
	c, err := x509.ParseCertificate(b.Bytes)
	return c, err == nil
}

func leafRole(c *x509.Certificate, role x509.ExtKeyUsage, now time.Time) bool {
	if c == nil || c.IsCA || now.Before(c.NotBefore) || !now.Before(c.NotAfter) || c.PublicKeyAlgorithm != x509.Ed25519 || c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	for _, usage := range c.ExtKeyUsage {
		if usage == role {
			return true
		}
	}
	return false
}

func issuerBothRoles(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	server, client := false, false
	for _, role := range c.ExtKeyUsage {
		switch role {
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

// One immutable projected Secret revision supplies the public config and all
// private sibling files. A rotation during loading refuses the whole process.
func loadMaterial(dir, source string, now time.Time) (*material, error) {
	m := &material{}
	ok := false
	defer func() {
		if !ok {
			m.close()
		}
	}()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	revision, err := filepath.EvalSymlinks(filepath.Join(dir, "..data"))
	if err != nil || !strings.HasPrefix(revision, dir+string(filepath.Separator)) {
		return nil, ErrUnavailable
	}
	raw, err := readSecret(revision, "config.json", 16384)
	if err != nil || decodeClosed(raw, &m.config) != nil || !validConfig(m.config, source, now) {
		return nil, ErrUnavailable
	}
	m.scope = sha(raw)
	certRaw, err := readSecret(revision, "server.crt", 16384)
	if err != nil {
		return nil, ErrUnavailable
	}
	keyRaw, err := readSecret(revision, "server.key", 16384)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer wipe(keyRaw)
	m.server, err = tls.X509KeyPair(certRaw, keyRaw)
	if err != nil || len(m.server.Certificate) != 1 {
		return nil, ErrUnavailable
	}
	leaf, valid := singleCertificate(certRaw)
	if !valid || !leafRole(leaf, x509.ExtKeyUsageServerAuth, now) || leaf.NotAfter.Before(m.config.HardNotAfter) || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != m.config.Identity.PodIPv4 || len(leaf.DNSNames) != 0 {
		return nil, ErrUnavailable
	}
	caRaw, err := readSecret(revision, "controller-ca.crt", 16384)
	if err != nil {
		return nil, ErrUnavailable
	}
	ca, valid := singleCertificate(caRaw)
	if !valid || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(ca.NotBefore) || ca.NotAfter.Before(m.config.HardNotAfter) || !issuerBothRoles(ca) {
		return nil, ErrUnavailable
	}
	m.clientCA = x509.NewCertPool()
	m.clientCA.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: m.clientCA, CurrentTime: now, DNSName: m.config.Identity.PodIPv4, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, ErrUnavailable
	}
	signing, err := readSecret(revision, "signing.key", ed25519.PrivateKeySize)
	if err != nil || len(signing) != ed25519.PrivateKeySize {
		wipe(signing)
		return nil, ErrUnavailable
	}
	m.signing = ed25519.PrivateKey(signing)
	derived := ed25519.NewKeyFromSeed(signing[:ed25519.SeedSize])
	valid = bytes.Equal(derived, signing)
	wipe(derived)
	if !valid {
		return nil, ErrUnavailable
	}
	peer, err := readSecret(revision, "peer-signing.pub", ed25519.PublicKeySize)
	if err != nil || len(peer) != ed25519.PublicKeySize || bytes.Equal(peer, signing[ed25519.SeedSize:]) {
		return nil, ErrUnavailable
	}
	m.peer = ed25519.PublicKey(peer)
	if m.config.Startup != nil {
		m.startup, err = readSecret(revision, "admission.key", 512)
		if err != nil || len(m.startup) < 32 || bytes.ContainsAny(m.startup, "\x00\r\n") {
			return nil, ErrUnavailable
		}
	}
	after, err := filepath.EvalSymlinks(filepath.Join(dir, "..data"))
	if err != nil || after != revision {
		return nil, ErrUnavailable
	}
	ok = true
	return m, nil
}
