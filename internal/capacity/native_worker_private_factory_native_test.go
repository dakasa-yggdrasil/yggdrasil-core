//go:build linux && nativefactoryqualification

package capacity

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"gopkg.in/yaml.v3"
)

// CI must supply the independently qualified, actually published System CLI.
// A synthetic executable or a skipped test is not this integration evidence.
func TestNativePrivateFactoryPublishedSystemCLI(t *testing.T) {
	source := os.Getenv("NATIVE_FACTORY_SYSTEM_SOURCE")
	path := os.Getenv("NATIVE_FACTORY_SYSTEM_CLI")
	sha := os.Getenv("NATIVE_FACTORY_SYSTEM_SHA256")
	size, e := strconv.ParseInt(os.Getenv("NATIVE_FACTORY_SYSTEM_BYTES"), 10, 64)
	if !marketCommit.MatchString(source) || !filepath.IsAbs(path) || !marketSHA.MatchString(sha) || e != nil || size < 1 {
		t.Fatal("actual published System CLI source/hash/size required")
	}
	f, a := nativePrivateFactoryFixture(t, source)
	f.template.Operator.SHA256 = sha
	f.template.Operator.Bytes = size
	template, e := json.Marshal(f.template)
	if e != nil {
		t.Fatal(e)
	}
	c := f.config
	c.TemplateSHA256 = nativePrivateSHA(template)
	c.CLISHA256 = sha
	c.CLIBytes = size
	c.Execution.LaunchTemplateSHA256 = c.TemplateSHA256
	dir := t.TempDir()
	write := func(name string, body []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, body, mode); e != nil {
			t.Fatal(e)
		}
		return p
	}
	c.TemplateFile = write("template.json", template, 0600)
	c.AgentTokenFile = write("agent-token", f.token, 0600)
	c.CAFile = write("floor-ca.pem", f.ca, 0644)
	c.WireGuardMasterFile = write("wireguard-master", f.master, 0600)
	c.CLIFile = filepath.Join(dir, "pinned-System-CLI")
	in, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	out, e := os.OpenFile(c.CLIFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if e != nil {
		in.Close()
		t.Fatal(e)
	}
	n, e := io.Copy(out, io.LimitReader(in, size+1))
	in.Close()
	closeErr := out.Close()
	if e != nil || closeErr != nil || n != size {
		t.Fatal("actual artifact copy incomplete")
	}
	provider := &nativePrivateCredentialsFixture{value: aws.Credentials{AccessKeyID: "CI_EXPLICIT_ACCESS", SecretAccessKey: "CI_EXPLICIT_PRIVATE"}}
	real, e := NewNativeWorkerPrivateFactory(c, provider)
	if e != nil {
		t.Fatal("actual pinned executable/configuration refused", e)
	}
	defer real.Close()
	defer f.Close()
	a.Execution = c.Execution
	prepared, e := real.Prepare(a)
	if e != nil {
		t.Fatal(e)
	}
	a.LaunchSHA256 = nativePrivateSHA(prepared.PublicJSON)
	// Remove every original material pathname. Prepare must use only constructor
	// memory, while executable path replacement must not select another program.
	for _, p := range []string{c.TemplateFile, c.AgentTokenFile, c.CAFile, c.WireGuardMasterFile} {
		if e := os.Remove(p); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Rename(c.CLIFile, c.CLIFile+".original"); e != nil {
		t.Fatal(e)
	}
	write(filepath.Base(c.CLIFile), []byte("unqualified replacement must never execute"), 0755)
	second, e := real.Prepare(a)
	if e != nil || !bytes.Equal(prepared.PublicJSON, second.PublicJSON) || provider.calls != 0 {
		t.Fatal("Prepare performed I/O or signing", e)
	}
	expires := time.Now().Add(90 * time.Second)
	body, e := real.RenderNativeWorkerPrivateBootstrap(t.Context(), a, prepared.PublicJSON, expires)
	if e != nil || len(body) < 1 || len(body) > 16384 || provider.calls != 1 {
		t.Fatal("actual System renderer through pinned FD failed", e)
	}
	defer nativePrivateWipe(body)
	var document struct {
		Files []struct {
			Path        string `yaml:"path"`
			Encoding    string `yaml:"encoding"`
			Content     string `yaml:"content"`
			Permissions string `yaml:"permissions"`
		} `yaml:"write_files"`
	}
	if yaml.Unmarshal(body, &document) != nil || len(document.Files) != 4 {
		t.Fatal("actual rendered YAML is invalid")
	}
	var material struct {
		Schema int    `json:"schema"`
		Token  string `json:"agent_token"`
		Key    string `json:"wireguard_private_key"`
		CA     string `json:"ca_pem"`
	}
	var launch nativePrivateLaunch
	if json.Unmarshal(prepared.PublicJSON, &launch) != nil {
		t.Fatal("prepared public launch invalid")
	}
	for i, want := range []string{"/etc/dakasa-native-worker/launch.json", "/etc/dakasa-native-worker/bootstrap.json", "/etc/dakasa-native-worker/operator.curl"} {
		file := document.Files[i]
		decoded, e := base64.StdEncoding.DecodeString(file.Content)
		if e != nil || file.Path != want || file.Encoding != "b64" || file.Permissions != "0600" {
			t.Fatal("private file/mode changed")
		}
		switch i {
		case 0:
			if !bytes.Equal(decoded, prepared.PublicJSON) {
				t.Fatal("stored canonical launch changed in actual CLI")
			}
		case 1:
			if json.Unmarshal(decoded, &material) != nil || material.Schema != 1 || material.Token != string(real.token) || material.CA != string(real.ca) {
				t.Fatal("real private file material changed")
			}
		case 2:
			lines := strings.Split(strings.TrimSuffix(string(decoded), "\n"), "\n")
			if len(lines) != 2 || lines[1] != `header = "x-amz-expected-bucket-owner: 153828470928"` {
				t.Fatal("operator capability protocol changed")
			}
			cap, e := strconv.Unquote(strings.TrimPrefix(lines[0], "url = "))
			u, pe := url.Parse(cap)
			if e != nil || pe != nil || u.Host != launch.Operator.ExpectedHostname || u.Query().Get("versionId") != c.ArtifactVersionID || u.Query().Get("X-Amz-SignedHeaders") != "host;x-amz-expected-bucket-owner" {
				t.Fatal("exact private signed version/owner changed")
			}
		}
		nativePrivateWipe(decoded)
	}
	private, e := base64.StdEncoding.DecodeString(material.Key)
	if e != nil {
		t.Fatal("private key invalid")
	}
	defer nativePrivateWipe(private)
	key, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil || base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) != launch.Network.WorkerPublicKey {
		t.Fatal("actual private/public key relation changed")
	}
	if _, e = real.RenderNativeWorkerPrivateBootstrap(t.Context(), a, append([]byte(" "), prepared.PublicJSON...), expires); e == nil {
		t.Fatal("nonexact stored launch accepted")
	}
	if _, e = real.RenderNativeWorkerPrivateBootstrap(t.Context(), a, prepared.PublicJSON, time.Now().Add(-time.Second)); e == nil {
		t.Fatal("expired command rendered bootstrap")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = real.RenderNativeWorkerPrivateBootstrap(ctx, a, prepared.PublicJSON, expires); e == nil {
		t.Fatal("cancelled parent executed bootstrap")
	}
	if _, e = nativePrivateExecute(t.Context(), real.binary, c, []byte(`{"unknown":"private invalid input"}`), expires); e == nil {
		t.Fatal("failed actual CLI leaked a successful body")
	}
}
