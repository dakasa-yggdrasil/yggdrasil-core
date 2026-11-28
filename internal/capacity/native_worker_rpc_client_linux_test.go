//go:build linux

package capacity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeRPCTestPKI struct {
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	caPEM []byte
}

func nativeRPCPKI(t *testing.T) nativeRPCTestPKI {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-ci-native-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	actual, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return nativeRPCTestPKI{actual, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p nativeRPCTestPKI) leaf(t *testing.T, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "isolated-ci-native-leaf"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, p.ca, key.Public(), p.key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	return pair, certPEM, keyPEM
}

func nativeRPCClientFixture(t *testing.T, handler http.Handler, operation ...string) (*NativeWorkerRPCClient, NativeWorkerRPCConfig, *httptest.Server, []byte) {
	t.Helper()
	pki := nativeRPCPKI(t)
	serverCert, _, _ := pki.leaf(t, x509.ExtKeyUsageServerAuth)
	_, clientCert, clientKey := pki.leaf(t, x509.ExtKeyUsageClientAuth)
	pool := x509.NewCertPool()
	pool.AddCert(pki.ca)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.TLS != nil {
			t.Error("private RPC credentials reached public diagnostic health")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(health.Close)
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	config := NativeWorkerRPCConfig{Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 3, Checksum: strings.Repeat("a", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("b", 64)}, Profile: "aws-ci", BindingName: "independent-read", SDKSourceCommit: strings.Repeat("c", 40), ScopeSHA256: strings.Repeat("d", 64), BaseURL: server.URL, HealthURL: health.URL + "/healthz", ServerCAFile: write("ca.pem", pki.caPEM), ServerCASHA256: nativeRPCHash(pki.caPEM), ServerCertificateSHA256: nativeRPCHash(serverCert.Certificate[0]), ClientCertificateFile: write("client.pem", clientCert), ClientKeyFile: write("client.key", clientKey), AllowedCapabilities: []string{"observe_native_worker"}}
	capability := "observe_native_worker"
	if len(operation) != 0 {
		if len(operation) != 1 {
			t.Fatal("exactly one fixture role required")
		}
		capability = operation[0]
		config.AllowedCapabilities = []string{capability}
	}
	client, e := NewNativeWorkerRPCClient(config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = client.Close() })
	request := model.AdapterExecuteIntegrationRequest{Operation: capability, Capability: capability, Input: map[string]any{"binding_name": config.BindingName}, Integration: model.AdapterExecuteIntegrationContext{Instance: model.ManifestReference{ID: uuid.MustParse(config.Adapter.ManifestID), Kind: "integration_instance", Version: 3}, Type: model.ManifestReference{ID: uuid.MustParse(config.Adapter.IntegrationTypeID), Kind: "integration_type", Version: 1}}}
	raw, e := json.Marshal(request)
	if e != nil {
		t.Fatal(e)
	}
	return client, config, server, raw
}

func nativeRPCTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestNativeWorkerRPCRealMTLSAndSeparatePublicHealth(t *testing.T) {
	var sends atomic.Int32
	client, c, _, raw := nativeRPCClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		if r.TLS == nil || len(r.TLS.VerifiedChains) != 1 || len(r.TLS.PeerCertificates) != 1 || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
			t.Error("original native RPC was not authenticated solely by actual client certificate")
		}
		w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("c", 40))
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	ctx := nativeRPCTestContext(t)
	got, e := client.Call(ctx, c.BaseURL+"/rpc/execute", raw, 4096)
	if e != nil || string(got) != `{"ok":true}` || sends.Load() != 1 {
		t.Fatal("exact original TLS RPC rejected", e)
	}
	describe, _ := json.Marshal(model.AdapterDescribeRequest{Provider: "aws", ExpectedVersion: "1.64.1"})
	if _, e = client.Call(ctx, c.BaseURL+"/rpc/describe", describe, 4096); e != nil || sends.Load() != 2 {
		t.Fatal("original Describe did not use same private authenticated transport", e)
	}
	if e = client.Probe(ctx); e != nil || sends.Load() != 2 {
		t.Fatal("fixed public health crossed private RPC", e)
	}
	if !client.Matches(c.Adapter, c.Profile, c.BindingName, c.SDKSourceCommit, c.ScopeSHA256, "observe_native_worker") || client.Matches(c.Adapter, c.Profile, c.BindingName, c.SDKSourceCommit, c.ScopeSHA256, "ensure_native_worker") {
		t.Fatal("reader TLS handle acquired creator role")
	}
	copy := *client
	_ = copy.Close()
	if _, e = client.Call(ctx, c.BaseURL+"/rpc/execute", raw, 4096); e == nil || sends.Load() != 2 || client.ScopeValid(c.Adapter, c.BaseURL) {
		t.Fatal("copied handle reopened closed private client")
	}
	for _, v := range []any{copy, &copy} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, c.ClientKeyFile) || !strings.Contains(s, "private Native RPC client") {
				t.Fatal("private TLS state appeared in representation")
			}
		}
		wire, _ := json.Marshal(v)
		if string(wire) != `{"private_native_rpc":"redacted"}` {
			t.Fatal("private TLS state appeared in JSON")
		}
	}
}

func TestNativeWorkerRPCRejectsTargetRoleWireAndScopeSubstitutionBeforeSend(t *testing.T) {
	var sends atomic.Int32
	client, c, _, raw := nativeRPCClientFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sends.Add(1) }))
	for _, fault := range []string{"path", "query", "fragment", "plainHTTP", "wrongRole", "duplicate", "alias", "extraAuth", "foreignInstance", "wrongBinding", "noDeadline"} {
		t.Run(fault, func(t *testing.T) {
			target, body, ctx := c.BaseURL+"/rpc/execute", append([]byte(nil), raw...), nativeRPCTestContext(t)
			switch fault {
			case "path":
				target = c.BaseURL + "/rpc/other"
			case "query":
				target += "?target=foreign"
			case "fragment":
				target += "#foreign"
			case "plainHTTP":
				target = strings.Replace(target, "https:", "http:", 1)
			case "wrongRole":
				body = bytes.ReplaceAll(body, []byte("observe_native_worker"), []byte("destroy_native_worker"))
			case "duplicate":
				body = bytes.Replace(body, []byte(`"operation":`), []byte(`"operation":"ensure_native_worker","operation":`), 1)
			case "alias":
				body = bytes.Replace(body, []byte(`"operation":`), []byte(`"Operation":`), 1)
			case "extraAuth":
				body = bytes.Replace(body, []byte(`"input":`), []byte(`"auth":{"bearer":"invented"},"input":`), 1)
			case "foreignInstance":
				body = bytes.ReplaceAll(body, []byte(c.Adapter.ManifestID), []byte(uuid.NewString()))
			case "wrongBinding":
				body = bytes.ReplaceAll(body, []byte(c.BindingName), []byte("foreign"))
			case "noDeadline":
				ctx = t.Context()
			}
			if _, e := client.Call(ctx, target, body, 4096); e == nil {
				t.Fatal("unbound request reached native private transport")
			}
		})
	}
	if sends.Load() != 0 {
		t.Fatal("an invalid request reached the actual TLS server")
	}
	changed := c.Adapter
	changed.Version++
	if client.ScopeValid(changed, c.BaseURL) || client.ScopeValid(c.Adapter, c.BaseURL+"/foreign") || client.Matches(c.Adapter, c.Profile, c.BindingName, strings.Repeat("e", 40), c.ScopeSHA256, "observe_native_worker") {
		t.Fatal("protected context accepted substituted adapter/source/target")
	}
}

func TestNativeWorkerRPCRequiresExactOriginalServerSourceAndBoundedCompleteReturn(t *testing.T) {
	for _, fault := range []string{"missingSource", "duplicateSource", "foreignSource", "largeBody", "redirect", "wrongServerLeaf", "wrongCA"} {
		t.Run(fault, func(t *testing.T) {
			var sends atomic.Int32
			client, c, _, raw := nativeRPCClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("c", 40))
				switch fault {
				case "missingSource":
					w.Header().Del("X-Yggdrasil-Source-Commit")
				case "duplicateSource":
					w.Header().Add("X-Yggdrasil-Source-Commit", strings.Repeat("c", 40))
				case "foreignSource":
					w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("e", 40))
				case "redirect":
					http.Redirect(w, r, "https://unowned.invalid/rpc/execute", http.StatusTemporaryRedirect)
					return
				}
				_, _ = io.WriteString(w, strings.Repeat("x", 65))
			}))
			if fault == "wrongServerLeaf" {
				c.ServerCertificateSHA256 = strings.Repeat("e", 64)
				var e error
				client, e = NewNativeWorkerRPCClient(c)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { _ = client.Close() })
			}
			if fault == "wrongCA" {
				other := nativeRPCPKI(t)
				if e := os.WriteFile(c.ServerCAFile, other.caPEM, 0600); e != nil {
					t.Fatal(e)
				}
				c.ServerCASHA256 = nativeRPCHash(other.caPEM)
				var e error
				client, e = NewNativeWorkerRPCClient(c)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { _ = client.Close() })
			}
			limit := int64(4096)
			if fault == "largeBody" {
				limit = 64
			}
			if body, e := client.Call(nativeRPCTestContext(t), c.BaseURL+"/rpc/execute", raw, limit); e == nil || body != nil || strings.Contains(fmt.Sprint(e), "unowned.invalid") {
				t.Fatal("incomplete or unbound original server return accepted or leaked", e)
			}
			if sends.Load() > 1 || (fault == "wrongServerLeaf" || fault == "wrongCA") && sends.Load() != 0 {
				t.Fatal("failed qualification replayed or sent before TLS verification", sends.Load())
			}
		})
	}
}

type nativeRPCRoundTripFunc func(*http.Request) (*http.Response, error)

func (f nativeRPCRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type nativeRPCCloseFault struct {
	io.Reader
	closed *atomic.Int32
}

func (b nativeRPCCloseFault) Close() error {
	b.closed.Add(1)
	return errors.New("private close failure")
}

func TestNativeWorkerRPCOriginalCloseFailureDoesNotBecomeCompleteOrReplay(t *testing.T) {
	client, c, _, raw := nativeRPCClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("fake original should not dial fixture")
		w.WriteHeader(500)
	}))
	var sends, closed atomic.Int32
	client.tlsClient.Transport = nativeRPCRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		sends.Add(1)
		if r.GetBody != nil {
			t.Fatal("original request is replayable")
		}
		return &http.Response{StatusCode: 200, Request: r, Header: http.Header{"X-Yggdrasil-Source-Commit": []string{c.SDKSourceCommit}}, TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{client.leaf}}}, Body: nativeRPCCloseFault{strings.NewReader(`{"ok":true}`), &closed}}, nil
	})
	if body, e := client.Call(nativeRPCTestContext(t), c.BaseURL+"/rpc/execute", raw, 4096); e == nil || body != nil || sends.Load() != 1 || closed.Load() != 1 {
		t.Fatal("original Close failure became a qualified response", e)
	}
}

func TestNativeWorkerRPCProtectedFilesAndRoleCannotBeReplaced(t *testing.T) {
	for _, fault := range []string{"mixedRole", "duplicateRole", "foreignCapability", "invalidSource", "wrongCAHash", "unsafeKeyMode", "symlinkKey", "certificateContainsPrivateKey", "wrongClientPurpose", "baseUser", "missingHealth"} {
		t.Run(fault, func(t *testing.T) {
			_, c, _, _ := nativeRPCClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("constructor must never dial")
				w.WriteHeader(500)
			}))
			switch fault {
			case "mixedRole":
				c.AllowedCapabilities = []string{"observe_native_worker", "ensure_native_worker"}
			case "duplicateRole":
				c.AllowedCapabilities = []string{"observe_native_worker", "observe_native_worker"}
			case "foreignCapability":
				c.AllowedCapabilities = []string{"destroy_anything"}
			case "invalidSource":
				c.SDKSourceCommit = "caller-invented-source"
			case "wrongCAHash":
				c.ServerCASHA256 = strings.Repeat("e", 64)
			case "unsafeKeyMode":
				if e := os.Chmod(c.ClientKeyFile, 0644); e != nil {
					t.Fatal(e)
				}
			case "symlinkKey":
				target := c.ClientKeyFile + ".link"
				if e := os.Symlink(c.ClientKeyFile, target); e != nil {
					t.Fatal(e)
				}
				c.ClientKeyFile = target
			case "certificateContainsPrivateKey":
				key, e := os.ReadFile(c.ClientKeyFile)
				if e != nil {
					t.Fatal(e)
				}
				f, e := os.OpenFile(c.ClientCertificateFile, os.O_APPEND|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.Write(key)
				closeErr := f.Close()
				if e != nil || closeErr != nil {
					t.Fatal(e, closeErr)
				}
			case "wrongClientPurpose":
				pki := nativeRPCPKI(t)
				_, cert, key := pki.leaf(t, x509.ExtKeyUsageServerAuth)
				if e := os.WriteFile(c.ClientCertificateFile, cert, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(c.ClientKeyFile, key, 0600); e != nil {
					t.Fatal(e)
				}
			case "baseUser":
				c.BaseURL = strings.Replace(c.BaseURL, "https://", "https://caller@", 1)
			case "missingHealth":
				c.HealthURL = ""
			}
			if client, e := NewNativeWorkerRPCClient(c); e == nil {
				_ = client.Close()
				t.Fatal("unqualified protected role/material accepted")
			}
		})
	}
}
