//go:build linux && nativefactoryqualification

package capacity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"gopkg.in/yaml.v3"
)

// The separate v2 job must consume an actual normally published System build.
// Legacy v1 artifact pins/job and its original three roots remain unchanged.
func TestNativeGuestPrivateFactoryPublishedV2RendererAndStableIdentity(t *testing.T) {
	source, binary, sha := os.Getenv("NATIVE_GUEST_SYSTEM_SOURCE"), os.Getenv("NATIVE_GUEST_SYSTEM_CLI"), os.Getenv("NATIVE_GUEST_SYSTEM_SHA256")
	size, err := strconv.ParseInt(os.Getenv("NATIVE_GUEST_SYSTEM_BYTES"), 10, 64)
	if !marketCommit.MatchString(source) || !filepath.IsAbs(binary) || !marketSHA.MatchString(sha) || err != nil || size < 1 {
		t.Fatal("actual new System v2 artifact Source/digest/size required; no skip or replacement")
	}
	f, a, _ := nativeGuestIdentityFixture(t, source)
	// This qualification stops before provider send. It carries no birth/Node.
	a.State, a.BirthSHA256, a.NodeUID = "reserved", "", ""
	a.Physical = nil
	f.template.Operator.SHA256 = sha
	f.template.Operator.Bytes = size
	template, err := json.Marshal(f.template)
	if err != nil {
		t.Fatal(err)
	}
	c := f.config
	c.TemplateSHA256 = nativePrivateSHA(template)
	c.CLISHA256 = sha
	c.CLIBytes = size
	c.Execution.LaunchTemplateSHA256 = c.TemplateSHA256
	dir := t.TempDir()
	write := func(name string, raw []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	c.TemplateFile = write("template.json", template, 0600)
	c.AgentTokenFile = write("agent-token", f.token, 0600)
	c.CAFile = write("floor-ca.pem", f.ca, 0644)
	c.WireGuardMasterFile = write("wg-master", f.master, 0600)
	c.CLIFile = filepath.Join(dir, "actual-published-v2-System")
	in, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(c.CLIFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		in.Close()
		t.Fatal(err)
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, size+1))
	closeIn, closeOut := in.Close(), out.Close()
	if copyErr != nil || closeIn != nil || closeOut != nil || n != size {
		t.Fatal("original published artifact copy incomplete")
	}
	provider := &nativePrivateCredentialsFixture{value: aws.Credentials{AccessKeyID: "CI_GUEST_PRIVATE_FACTORY", SecretAccessKey: "CI_EXPLICIT_SYNTHETIC_KEY"}}
	real, err := NewNativeWorkerPrivateFactory(c, provider)
	if err != nil {
		t.Fatal("actual paired v2 factory refused", err)
	}
	defer real.Close()
	a.Execution = c.Execution
	prepared, err := real.Prepare(a)
	if err != nil {
		t.Fatal(err)
	}
	a.LaunchSHA256 = nativePrivateSHA(prepared.PublicJSON)
	server, err := real.guest.derive(a, prepared.PublicJSON, source)
	if err != nil {
		t.Fatal(err)
	}
	defer server.close()
	client, err := real.guest.deriveClient(a, prepared.PublicJSON, source)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	if !real.MatchesGuestNetwork(real.guest.network, real.guest.config.NetworkTemplateSHA256) {
		t.Fatal("factory detached its policy network template")
	}
	for _, path := range []string{c.TemplateFile, c.AgentTokenFile, c.CAFile, c.WireGuardMasterFile, c.GuestRead.MasterFile, c.GuestRead.IssuerCAFile, c.GuestRead.IssuerKeyFile, c.GuestRead.NetworkTemplateFile} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	a.State = "reserved"
	body, err := real.RenderNativeWorkerPrivateBootstrap(t.Context(), a, prepared.PublicJSON, time.Now().Add(90*time.Second))
	if err != nil || len(body) == 0 || len(body) > 16384 {
		t.Fatal("actual v2 renderer failed", err)
	}
	defer nativePrivateWipe(body)
	var document struct {
		Files []struct{ Path, Owner, Permissions, Encoding, Content string } `yaml:"write_files"`
		Run   [][]string                                                     `yaml:"runcmd"`
	}
	if yaml.Unmarshal(body, &document) != nil || len(document.Files) != 7 || len(document.Run) != 2 {
		t.Fatal("actual private v2 cloud-init shape changed")
	}
	var networkFound, tlsFound bool
	for _, file := range document.Files {
		if file.Path != "/etc/dakasa-native-worker/network-template.json" && file.Path != "/etc/dakasa-native-worker/guest-read.json" {
			continue
		}
		if file.Owner != "root:root" || file.Permissions != "0600" || file.Encoding != "b64" {
			t.Fatal("private modes changed")
		}
		raw, err := base64.StdEncoding.DecodeString(file.Content)
		if err != nil {
			t.Fatal(err)
		}
		if file.Path == "/etc/dakasa-native-worker/network-template.json" {
			networkFound = true
			canonical, _ := json.Marshal(real.guest.network)
			if !bytes.Equal(raw, canonical) {
				t.Fatal("delivered network differs from immutable policy")
			}
			continue
		}
		tlsFound = true
		var material struct {
			ServerCertificatePEM        string `json:"server_certificate_pem"`
			ServerPrivateKeyPEM         string `json:"server_private_key_pem"`
			CoreClientCAPEM             string `json:"core_client_ca_pem"`
			CoreClientCertificateSHA256 string `json:"core_client_certificate_sha256"`
		}
		if nativeWorkerNetworkRPCDecode(raw, &material) != nil || material.CoreClientCertificateSHA256 != client.fingerprint || !bytes.Equal([]byte(material.CoreClientCAPEM), real.guest.issuerPEM) || bytes.Contains(raw, client.privateKeyPEM) {
			t.Fatal("perAttempt client public pin lost or its private key was delivered")
		}
		pair, err := tls.X509KeyPair([]byte(material.ServerCertificatePEM), []byte(material.ServerPrivateKeyPEM))
		if err != nil || len(pair.Certificate) != 1 || !bytes.Equal(pair.Certificate[0], server.certificateDER) {
			t.Fatal("actual child reminted server identity", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || leaf.URIs[0].String() != server.uri || leaf.CheckSignatureFrom(real.guest.issuer) != nil {
			t.Fatal("actual delivered certificate context/signature changed", err)
		}
	}
	if !networkFound || !tlsFound || provider.calls != 1 {
		t.Fatal("v2 delivery or exact single capability signing absent")
	}
	copy := *real
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := real.ReadGuestWitness(context.Background(), a, prepared.PublicJSON); err == nil {
		t.Fatal("copied Close reopened guest channel")
	}
	if real.MatchesGuestNetwork(f.guest.network, f.guest.config.NetworkTemplateSHA256) {
		t.Fatal("closed guest factory retained authorization")
	}
}
