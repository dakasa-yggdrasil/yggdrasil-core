package nativeworkerprobe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureSource = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testUUID(n int) string {
	const alphabet = "0123456789abcdef"
	return "12345678-1234-4234-8234-123456789ab" + string(alphabet[n%16])
}

func testConfig(role string) Config {
	now := time.Now().UTC()
	i := Identity{RunID: testUUID(0), AttemptID: testUUID(1), BirthSHA256: strings.Repeat("b", 64), PoolUID: testUUID(2), Role: role, Namespace: "diagnostic", NamespaceUID: testUUID(3), PodName: "probe-floor", PodUID: testUUID(4), PodIPv4: "10.89.0.2", NodeName: "floor", NodeUID: testUUID(5), ServiceUID: testUUID(6), ServiceClusterIPv4: "10.90.0.2"}
	c := Config{Schema: ConfigSchema, SourceCommit: fixtureSource, Identity: i, Peer: Peer{PodUID: testUUID(7), NodeUID: testUUID(8), PodIPv4: "10.89.0.3", ServiceUID: testUUID(9), ServiceClusterIPv4: "10.90.0.3"}, PodCIDR: "10.89.0.0/24", ServiceCIDR: "10.90.0.0/24", Nonce: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), NotBefore: now.Add(-time.Second), HardNotAfter: now.Add(2 * time.Minute), ControllerLeafSHA256: strings.Repeat("c", 64)}
	if role == "candidate" {
		c.Identity.PodName, c.Identity.NodeName = "probe-candidate", "candidate"
		c.Startup = &StartupConfig{CoreSourceCommit: fixtureSource, ImageDigest: "sha256:" + strings.Repeat("d", 64), WorkloadUID: testUUID(10), ContainerName: "api", LaneRosterSHA256: strings.Repeat("e", 64)}
	}
	return c
}

type probeTLSFixture struct {
	ca           *x509.Certificate
	caKey        ed25519.PrivateKey
	caPEM        []byte
	server       tls.Certificate
	serverPEM    []byte
	serverKeyPEM []byte
	client       tls.Certificate
	clientDER    []byte
}

func tlsFixture(t *testing.T, ip string) probeTLSFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe-only-ci"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := probeTLSFixture{ca: ca, caKey: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	issue := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte, []byte) {
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP(ip)}}
		d, err := x509.CreateCertificate(rand.Reader, leaf, ca, p, key)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM, keyPEM, d
	}
	f.server, f.serverPEM, f.serverKeyPEM, _ = issue(2, x509.ExtKeyUsageServerAuth)
	f.client, _, _, f.clientDER = issue(3, x509.ExtKeyUsageClientAuth)
	return f
}

func projectedMaterial(t *testing.T, c Config) (string, probeTLSFixture) {
	t.Helper()
	f := tlsFixture(t, c.Identity.PodIPv4)
	c.ControllerLeafSHA256 = sha(f.clientDER)
	dir := t.TempDir()
	revision := filepath.Join(dir, "revision")
	if err := os.Mkdir(revision, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("revision", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	_, own, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"config.json": raw, "server.crt": f.serverPEM, "server.key": f.serverKeyPEM, "controller-ca.crt": f.caPEM, "signing.key": own, "peer-signing.pub": peer}
	if c.Startup != nil {
		files["admission.key"] = bytes.Repeat([]byte{'k'}, 32)
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(revision, name), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, f
}

func TestProbeClosedConfigRejectsAliasesNullAndWrongAuthority(t *testing.T) {
	c := testConfig("candidate")
	raw, _ := json.Marshal(c)
	var decoded Config
	if decodeClosed(raw, &decoded) != nil || !validConfig(decoded, fixtureSource, time.Now()) {
		t.Fatal("valid closed configuration refused")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1),
		bytes.Replace(raw, []byte(`"schema"`), []byte(`"ſchema"`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		bytes.Replace(raw, []byte(`"startup":{`), []byte(`"unreviewed":{},"startup":{`), 1),
		append(append([]byte{}, raw...), []byte(` {}`)...),
		[]byte(`null`),
	} {
		if decodeClosed(bad, &Config{}) == nil {
			t.Fatal("alias/duplicate/null/unknown/trailing accepted")
		}
	}
	for _, change := range []func(*Config){
		func(v *Config) { v.SourceCommit = strings.Repeat("b", 40) },
		func(v *Config) { v.HardNotAfter = time.Now().Add(-time.Second) },
		func(v *Config) { v.Identity.Role = "authority" },
		func(v *Config) { v.Startup = nil },
		func(v *Config) { v.Identity.NodeUID = v.Peer.NodeUID },
		func(v *Config) { v.Identity.PodUID = "00000000-0000-0000-0000-000000000000" },
		func(v *Config) { v.Peer.PodIPv4 = "127.0.0.1" },
		func(v *Config) { v.Peer.ServiceClusterIPv4 = v.Identity.ServiceClusterIPv4 },
		func(v *Config) { v.ServiceCIDR = v.PodCIDR },
	} {
		v := c
		change(&v)
		if validConfig(v, fixtureSource, time.Now()) {
			t.Fatal("changed scope/role/lifetime/endpoint accepted")
		}
	}
	floor := c
	floor.Identity.Role = "floor"
	if validConfig(floor, fixtureSource, time.Now()) {
		t.Fatal("floor gained candidate startup")
	}
}

func TestProbeLoadsOneActualProtectedSecretRevisionAndRefusesDrift(t *testing.T) {
	c := testConfig("candidate")
	dir, _ := projectedMaterial(t, c)
	m, err := loadMaterial(dir, fixtureSource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	if m.scope == "" || len(m.signing) != 64 || len(m.peer) != 32 || len(m.startup) != 32 {
		t.Fatal("original material missing")
	}
	for _, name := range []string{"config.json", "server.key", "signing.key", "peer-signing.pub", "admission.key"} {
		p := filepath.Join(dir, "revision", name)
		if err := os.Chmod(p, 0644); err != nil {
			t.Fatal(err)
		}
		if got, err := loadMaterial(dir, fixtureSource, time.Now()); err == nil {
			got.close()
			t.Fatal("world-readable material accepted", name)
		}
		if err := os.Chmod(p, 0600); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "revision", "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "revision", "signing.key"), bytes.Repeat([]byte{9}, 64), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, "revision", "signing.key"), info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(dir, "revision", "signing.key"))
	if err != nil || secretStatEqual(info, after) {
		t.Fatal("restoring mtime hid actual secret rewrite", err)
	}
	if got, err := loadMaterial(dir, fixtureSource, time.Now()); err == nil {
		got.close()
		t.Fatal("incoherent signing key accepted")
	}
}

func TestProbePrivateMaterialRepresentationsAndSymlinksCannotExposeKeys(t *testing.T) {
	c := testConfig("candidate")
	dir, _ := projectedMaterial(t, c)
	m, err := loadMaterial(dir, fixtureSource, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer m.close()
	m.startup = []byte("private-startup-marker-never-public")
	for _, value := range []any{m, *m} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, projection := range []string{string(raw), fmt.Sprintf("%v %+v %#v", value, value, value)} {
			if strings.Contains(projection, string(m.startup)) || strings.Contains(projection, base64.StdEncoding.EncodeToString(m.signing)) {
				t.Fatal("private material escaped a normal representation")
			}
		}
	}
	p := filepath.Join(dir, "revision", "admission.key")
	outside := filepath.Join(dir, "outside-key")
	if err := os.Rename(p, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}
	if got, err := loadMaterial(dir, fixtureSource, time.Now()); err == nil {
		got.close()
		t.Fatal("symlink inside the protected revision followed")
	}
}

func TestProbeTLSMaterialRequiresActualServerLifetimeSANAndBothCARoles(t *testing.T) {
	for _, item := range []struct {
		name  string
		roles []x509.ExtKeyUsage
		ok    bool
	}{{"unrestricted", nil, true}, {"any", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, true}, {"both", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, true}, {"client_only", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false}, {"server_only", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false}} {
		t.Run(item.name, func(t *testing.T) {
			dir, f := projectedMaterial(t, testConfig("floor"))
			ca := *f.ca
			ca.ExtKeyUsage = item.roles
			der, err := x509.CreateCertificate(rand.Reader, &ca, &ca, ca.PublicKey, f.caKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "revision", "controller-ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			m, err := loadMaterial(dir, fixtureSource, time.Now())
			if (err == nil) != item.ok {
				t.Fatal("actual CA contract", item.name, err)
			}
			if m != nil {
				m.close()
			}
		})
	}
	for _, item := range []struct {
		name   string
		change func(*x509.Certificate)
	}{{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }}, {"too_short", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(time.Minute) }}, {"client_only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }}, {"wrong_san", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("10.89.0.99")} }}, {"CA_leaf", func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }}} {
		t.Run(item.name, func(t *testing.T) {
			dir, f := projectedMaterial(t, testConfig("floor"))
			leaf, err := x509.ParseCertificate(f.server.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			item.change(leaf)
			der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, leaf.PublicKey, f.caKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "revision", "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			if m, err := loadMaterial(dir, fixtureSource, time.Now()); err == nil {
				m.close()
				t.Fatal("invalid actual leaf accepted")
			}
		})
	}
}
