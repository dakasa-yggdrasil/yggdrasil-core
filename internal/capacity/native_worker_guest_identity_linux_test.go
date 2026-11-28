//go:build linux

package capacity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func nativeGuestIdentityFixture(t *testing.T, sources ...string) (*NativeWorkerPrivateFactory, model.CapacityNativeWorkerAttempt, []byte) {
	t.Helper()
	source := strings.Repeat("a", 40)
	if len(sources) > 1 {
		t.Fatal("single System Source required")
	}
	if len(sources) == 1 {
		source = sources[0]
	}
	f, a := nativePrivateFactoryFixture(t, source)
	t.Cleanup(func() { _ = f.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	issuer := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "synthetic-ci-guest-issuer"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(nil, issuer, issuer, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	n := model.CapacityNativeWorkerNetworkTemplate{Schema: 1, GuestSystemSourceCommit: f.config.SystemBuildSource, Interface: "wg-dakasa", MTU: 1380, TransportCIDR: f.template.Network.TransportCIDR, FloorPeerIPv4: f.template.Network.FloorPeerIPv4, FloorPublicKey: f.template.Network.FloorPeerPublicKey, ListenPort: 51820, FirewallChain: "DAKASA_NATIVE", PodCIDR: f.template.Network.PodCIDR, ServiceCIDR: f.template.Network.ServiceCIDR, ClusterDNSIPv4: "10.83.0.10", DNSName: "kubernetes.default.svc.cluster.local"}
	network, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	master := bytes.Repeat([]byte{9}, 32)
	c := NativeWorkerGuestReadConfig{Version: NativeWorkerGuestIdentityVersion, MasterVersion: "ci-v1", MasterFile: write("master", master), MasterPublicKey: nativeGuestMasterPublic(master, "ci-v1"), IssuerCAFile: write("ca.pem", ca), IssuerCASHA256: nativePrivateSHA(ca), IssuerKeyFile: write("ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), CertificateValiditySeconds: 3600, NetworkTemplateFile: write("network.json", network), NetworkTemplateSHA256: nativePrivateSHA(network), MaxReadAgeSeconds: 30}
	f.guest, err = newNativeGuestReadIdentity(c)
	if err != nil {
		t.Fatal("real protected CI files refused", err)
	}
	f.config.GuestRead = &c
	f.config.Execution.GuestIdentityPolicySHA256 = NativeWorkerGuestIdentityPolicySHA256(c)
	a.Execution = f.config.Execution
	a.CreatedAt = now.Add(-time.Minute)
	prepared, err := f.Prepare(a)
	if err != nil {
		t.Fatal(err)
	}
	a.LaunchSHA256 = nativePrivateSHA(prepared.PublicJSON)
	a.PhysicalSpecSHA256 = strings.Repeat("d", 64)
	a.ProviderIDPrefix = "aws:///"
	a.BirthSHA256 = strings.Repeat("e", 64)
	a.NodeUID = "88888888-8888-4888-8888-888888888888"
	a.State = "registered"
	a.Physical = &model.CapacityNativeWorkerPhysical{ResourceID: "i-11111111111111111", ProviderID: "aws:///us-east-1a/i-11111111111111111", AccountID: "153828470928", InstanceType: "m6i.large", NetworkID: "subnet-11111111111111111", CreatedAt: a.CreatedAt, ImageID: f.template.Provider.ImageID, Region: a.Region, Zone: "us-east-1a", NativeIPv4: "10.90.0.2", MACAddress: "02:11:22:33:44:55", PhysicalSpecSHA256: a.PhysicalSpecSHA256, PhysicalBindingSHA256: strings.Repeat("f", 64), LaunchSHA256: a.LaunchSHA256}
	return f, a, prepared.PublicJSON
}

func TestNativeGuestIdentityRecreatesBothRolesWithoutClockRandomnessOrPrivateHash(t *testing.T) {
	f, a, launch := nativeGuestIdentityFixture(t)
	first, err := f.guest.derive(a, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	client, err := f.guest.deriveClient(a, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	restarted, err := newNativeGuestReadIdentity(*f.config.GuestRead)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	// After construction neither role may reread protected paths or mint a
	// random replacement. The retained generation recreates exactly both DERs.
	for _, path := range []string{f.config.GuestRead.MasterFile, f.config.GuestRead.IssuerCAFile, f.config.GuestRead.IssuerKeyFile, f.config.GuestRead.NetworkTemplateFile} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	second, err := restarted.derive(a, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	client2, err := restarted.deriveClient(a, launch, f.config.SystemBuildSource)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.close()
	if !bytes.Equal(first.certificateDER, second.certificateDER) || !bytes.Equal(first.privateKeyDER, second.privateKeyDER) || !bytes.Equal(client.certificateDER, client2.certificateDER) || !bytes.Equal(client.privateKeyDER, client2.privateKeyDER) || bytes.Equal(first.privateKeyDER, client.privateKeyDER) {
		t.Fatal("restarted role identity changed or server/client key reused")
	}
	serverLeaf, err := x509.ParseCertificate(first.certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(client.certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if serverLeaf.CheckSignatureFrom(f.guest.issuer) != nil || clientLeaf.CheckSignatureFrom(f.guest.issuer) != nil || serverLeaf.SerialNumber.Cmp(clientLeaf.SerialNumber) == 0 || serverLeaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || clientLeaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || serverLeaf.URIs[0].String()+"/core-read" != clientLeaf.URIs[0].String() || !serverLeaf.NotBefore.Equal(a.CreatedAt.Truncate(time.Second)) || !serverLeaf.NotAfter.Equal(serverLeaf.NotBefore.Add(time.Hour)) {
		t.Fatal("role/URI/immutable validity/signature contract drift")
	}
	for _, c := range []nativeGuestReadCertificate{first, client} {
		wire, _ := json.Marshal(c)
		printed := fmt.Sprintf("%v %#v %s", c, c, wire)
		if strings.Contains(printed, string(c.privateKeyPEM)) || strings.Contains(printed, c.fingerprint) {
			t.Fatal("opaque identity revealed private material or perAttempt pin")
		}
	}
}

func TestNativeGuestIdentityImmutablePolicyAndGenerationRejectSubstitution(t *testing.T) {
	f, a, launch := nativeGuestIdentityFixture(t)
	for _, fault := range []string{"no-pin", "wrong-pin", "zero-created", "different-source", "changed-launch", "changed-policy"} {
		t.Run(fault, func(t *testing.T) {
			copy := a
			raw := bytes.Clone(launch)
			source := f.config.SystemBuildSource
			switch fault {
			case "no-pin":
				copy.Execution.GuestIdentityPolicySHA256 = ""
			case "wrong-pin":
				copy.Execution.GuestIdentityPolicySHA256 = strings.Repeat("0", 64)
			case "zero-created":
				copy.CreatedAt = time.Time{}
			case "different-source":
				source = strings.Repeat("b", 40)
			case "changed-launch":
				raw = append(raw, ' ')
			case "changed-policy":
				copy.PolicyID[0] ^= 1
			}
			if c, err := f.guest.derive(copy, raw, source); err == nil {
				c.close()
				t.Fatal("unbound identity derived")
			}
		})
	}
	for _, fault := range []string{"ttl-default", "ttl-outside-ca", "ca-replaced", "master-replaced", "network-replaced"} {
		t.Run(fault, func(t *testing.T) {
			c := *f.config.GuestRead
			switch fault {
			case "ttl-default":
				c.CertificateValiditySeconds = 0
			case "ttl-outside-ca":
				c.CertificateValiditySeconds = 7 * 24 * 3600
			case "ca-replaced":
				c.IssuerCASHA256 = strings.Repeat("0", 64)
			case "master-replaced":
				c.MasterPublicKey = "changed"
			case "network-replaced":
				c.NetworkTemplateSHA256 = strings.Repeat("0", 64)
			}
			g, err := newNativeGuestReadIdentity(c)
			if fault == "ttl-outside-ca" && err == nil {
				defer g.close()
				copy := a
				copy.Execution.GuestIdentityPolicySHA256 = g.policySHA256
				_, err = g.derive(copy, launch, f.config.SystemBuildSource)
			}
			if err == nil {
				g.close()
				t.Fatal("invalid/default/replaced generation accepted")
			}
		})
	}
}

func TestNativeGuestPolicyPinAbsentPreservesLegacyExecutionBytes(t *testing.T) {
	f, a := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer f.Close()
	raw, err := json.Marshal(a.Execution)
	if err != nil || bytes.Contains(raw, []byte("guest_identity_policy_sha256")) {
		t.Fatal("optional absent field changed legacy bytes", err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if len(fields) != 13 {
		t.Fatal("legacy execution fields changed", len(fields))
	}
	// Frozen pre-guest wire declaration, independent of the extended model.
	x := a.Execution
	legacy, _ := json.Marshal(struct {
		Profile               string                             `json:"profile"`
		Adapter               model.CapacityMarketAdapterBinding `json:"adapter"`
		BindingName           string                             `json:"binding_name"`
		SDKSourceCommit       string                             `json:"sdk_source_commit"`
		ScopeSHA256           string                             `json:"scope_sha256"`
		EnsureCapability      string                             `json:"ensure_capability"`
		ObserveCapability     string                             `json:"observe_capability"`
		DestroyCapability     string                             `json:"destroy_capability"`
		LaunchTemplateSHA256  string                             `json:"launch_template_sha256"`
		BootstrapSourceCommit string                             `json:"bootstrap_source_commit"`
		IPAMScope             string                             `json:"ipam_scope"`
		OverlayCIDR           string                             `json:"overlay_cidr"`
		ExcludedIPv4          []string                           `json:"excluded_ipv4"`
	}{x.Profile, x.Adapter, x.BindingName, x.SDKSourceCommit, x.ScopeSHA256, x.EnsureCapability, x.ObserveCapability, x.DestroyCapability, x.LaunchTemplateSHA256, x.BootstrapSourceCommit, x.IPAMScope, x.OverlayCIDR, x.ExcludedIPv4})
	if !bytes.Equal(legacy, raw) {
		t.Fatal("legacy Execution wire is not byte exact")
	}
	a.Execution.GuestIdentityPolicySHA256 = strings.Repeat("a", 64)
	present, _ := json.Marshal(a.Execution)
	expected := append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"guest_identity_policy_sha256":"`+a.Execution.GuestIdentityPolicySHA256+`"}`)...)
	if !bytes.Equal(present, expected) {
		t.Fatal("optional identity pin was not appended last")
	}
	var decoded model.CapacityNativeWorkerExecutionProfile
	if DecodeNativeCapacity(json.RawMessage(present), &decoded) != nil || decoded.GuestIdentityPolicySHA256 != a.Execution.GuestIdentityPolicySHA256 {
		t.Fatal("durable optional policy pin lost")
	}
}

func TestNativeGuestIdentityIssuerMustAuthorizeBothTLSRolesBeforeRendering(t *testing.T) {
	f, a, launch := nativeGuestIdentityFixture(t)
	for _, tc := range []struct {
		name    string
		usages  []x509.ExtKeyUsage
		unknown []asn1.ObjectIdentifier
		allow   bool
	}{
		{name: "unrestricted", allow: true},
		{name: "any", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, allow: true},
		{name: "both", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, allow: true},
		{name: "client-only", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{name: "server-only", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "other", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}},
		{name: "unknown-only", unknown: []asn1.ObjectIdentifier{{1, 2, 3, 4}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := *f.guest.issuer
			issuer.ExtKeyUsage = tc.usages
			issuer.UnknownExtKeyUsage = tc.unknown
			der, err := x509.CreateCertificate(nil, &issuer, &issuer, f.guest.issuerKey.Public(), f.guest.issuerKey)
			if err != nil {
				t.Fatal(err)
			}
			raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			config := *f.config.GuestRead
			config.IssuerCAFile = filepath.Join(t.TempDir(), "issuer.pem")
			config.IssuerCASHA256 = nativePrivateSHA(raw)
			if err := os.WriteFile(config.IssuerCAFile, raw, 0600); err != nil {
				t.Fatal(err)
			}
			identity, err := newNativeGuestReadIdentity(config)
			if !tc.allow {
				if err == nil {
					identity.close()
					t.Fatal("CA incapable of both TLS roles accepted before rendering")
				}
				// The derivation guard also refuses an unusable retained issuer.
				retained := *f.guest
				retained.issuer = &issuer
				for _, role := range []string{"server", "client"} {
					cert, err := retained.deriveRole(a, launch, f.config.SystemBuildSource, role)
					if err == nil {
						cert.close()
						t.Fatal("unusable retained CA derived a TLS role", role)
					}
				}
				return
			}
			if err != nil {
				t.Fatal("CA authorizing both TLS roles refused", err)
			}
			defer identity.close()
			attempt := a
			attempt.Execution.GuestIdentityPolicySHA256 = identity.policySHA256
			roots := x509.NewCertPool()
			roots.AddCert(identity.issuer)
			for role, usage := range map[string]x509.ExtKeyUsage{"server": x509.ExtKeyUsageServerAuth, "client": x509.ExtKeyUsageClientAuth} {
				cert, err := identity.deriveRole(attempt, launch, f.config.SystemBuildSource, role)
				if err != nil {
					t.Fatal(err)
				}
				defer cert.close()
				leaf, err := x509.ParseCertificate(cert.certificateDER)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: attempt.CreatedAt.Add(time.Second), DNSName: attempt.OverlayIPv4, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
					t.Fatal("accepted issuer cannot authenticate derived TLS role", role, err)
				}
			}
		})
	}
}
