//go:build linux

package message

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeRPCMessageFixture struct {
	client                      *capacity.NativeWorkerRPCClient
	ctx                         context.Context
	instance, typ               model.Manifest
	is                          model.IntegrationInstanceManifestSpec
	ts                          model.IntegrationTypeManifestSpec
	describes, executes, health atomic.Int32
}

func nativeRPCMessage(t *testing.T) *nativeRPCMessageFixture {
	t.Helper()
	f := &nativeRPCMessageFixture{}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-ci-rpc-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	actualCA, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leaf := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		t.Helper()
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		d, e := x509.CreateCertificate(rand.Reader, tmpl, actualCA, k.Public(), key)
		if e != nil {
			t.Fatal(e)
		}
		kd, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		cp, kp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
		pair, e := tls.X509KeyPair(cp, kp)
		if e != nil {
			t.Fatal(e)
		}
		return pair, cp, kp
	}
	serverPair, _, _ := leaf(2, x509.ExtKeyUsageServerAuth)
	_, clientPEM, keyPEM := leaf(3, x509.ExtKeyUsageClientAuth)
	if e = json.Unmarshal([]byte(canonicalNativeDescribeJSON), &f.ts); e != nil {
		t.Fatal(e)
	}
	f.ts.Adapter.Transport = "http_json"
	f.ts.Adapter.Queues = model.IntegrationAdapterQueue{}
	f.ts.Adapter.Endpoints = model.IntegrationAdapterRoute{Describe: "/rpc/describe", Execute: "/rpc/execute"}
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.health.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			t.Error("private header reached public health")
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(health.Close)
	// Actual HCloud HTTP Describe advertises no health endpoint; its health
	// listener is separate. A protected URL must not alter that public catalog.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.Method != http.MethodPost {
			t.Error("resolver did not use actual original mTLS")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("X-Yggdrasil-Source-Commit", strings.Repeat("c", 40))
		switch r.URL.Path {
		case "/rpc/describe":
			f.describes.Add(1)
			_ = json.NewEncoder(w).Encode(f.ts)
		case "/rpc/execute":
			f.executes.Add(1)
			var req model.AdapterExecuteIntegrationRequest
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.Capability != "observe_native_worker" {
				t.Error("wrong fixed reader operation")
			}
			_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: req.Operation, Capability: req.Capability, Status: "observed", Output: map[string]any{"complete": true}})
		default:
			w.WriteHeader(404)
		}
	}))
	pool := x509.NewCertPool()
	pool.AddCert(actualCA)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.instance = model.Manifest{ID: uuid.New(), Kind: "integration_instance", Version: 3, Checksum: strings.Repeat("a", 64), Metadata: model.ManifestMetadata{Namespace: "ci", Name: "reader", Active: true}}
	f.typ = model.Manifest{ID: uuid.New(), Kind: "integration_type", Version: 1, Checksum: strings.Repeat("b", 64), Metadata: model.ManifestMetadata{Namespace: "ci", Name: "native", Active: true}}
	f.is = model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: f.typ.ID.String()}, Config: map[string]any{"base_url": server.URL}, Status: "active"}
	f.instance.Spec, _ = json.Marshal(f.is)
	f.typ.Spec, _ = json.Marshal(f.ts)
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	adapter := model.CapacityMarketAdapterBinding{ManifestID: f.instance.ID.String(), Version: 3, Checksum: f.instance.Checksum, IntegrationTypeID: f.typ.ID.String(), TypeChecksum: f.typ.Checksum}
	f.client, e = capacity.NewNativeWorkerRPCClient(capacity.NativeWorkerRPCConfig{Adapter: adapter, Profile: "aws-ci", BindingName: "reader", SDKSourceCommit: strings.Repeat("c", 40), ScopeSHA256: strings.Repeat("d", 64), BaseURL: server.URL, HealthURL: health.URL + "/healthz", ServerCAFile: write("ca.pem", caPEM), ServerCASHA256: fmt.Sprintf("%x", sha256.Sum256(caPEM)), ServerCertificateSHA256: fmt.Sprintf("%x", sha256.Sum256(serverPair.Certificate[0])), ClientCertificateFile: write("client.pem", clientPEM), ClientKeyFile: write("client.key", keyPEM), AllowedCapabilities: []string{"observe_native_worker"}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	f.ctx, e = WithNativeWorkerRPCClient(ctx, f.client, adapter)
	if e != nil {
		t.Fatal(e)
	}
	return f
}

func TestNativeWorkerRPCProtectedContextReachesOriginalDescribeExecuteAndHealth(t *testing.T) {
	f := nativeRPCMessage(t)
	if e := validateNativeWorkerRPCScope(f.ctx, f.instance, f.is, f.typ, f.ts); e != nil {
		t.Fatal(e)
	}
	if _, _, e := checkHTTPJSONTransportConnectivity(f.ctx, f.is, f.ts); e != nil || f.health.Load() != 1 {
		t.Fatal("separate actual health refused", e)
	}
	var desc model.AdapterDescribeResponse
	transport := newAdapterTransportClient(nil)
	if e := transport.Call(f.ctx, integrationDescribeContract, f.ts, f.is, "describe", model.AdapterDescribeRequest{Provider: f.ts.Provider, ExpectedVersion: f.ts.Adapter.Version}, &desc); e != nil || f.describes.Load() != 1 {
		t.Fatal("original Describe bypassed or lost private client context", e)
	}
	// Explicit execution policy has a fresh native HTTP projection. The separate
	// protected context must survive it, instead of losing the client identity.
	result, e := executeIntegrationThroughResolvedWithPolicy(f.ctx, nil, model.ExecuteIntegrationRequest{Operation: "observe_native_worker", Capability: "observe_native_worker", Input: map[string]any{"binding_name": "reader"}}, f.instance, f.is, f.typ, f.ts, 5*time.Second, integrationExecutionPolicy{detailFreeErrors: true, requireExplicitResponse: true, nativeHTTP: &nativeAdapterHTTPPolicy{limit: 4096, parent: f.ctx}})
	if e != nil || result.Status != "observed" || f.executes.Load() != 1 {
		t.Fatal("actual original execution lost protected TLS composition", e)
	}
	bad := f.ts
	bad.Adapter.Transport = "rabbitmq"
	if e = transport.Call(f.ctx, integrationDescribeContract, bad, f.is, "describe", model.AdapterDescribeRequest{Provider: f.ts.Provider, ExpectedVersion: f.ts.Adapter.Version}, &desc); e == nil {
		t.Fatal("private native principal escaped to broker")
	}
	if f.describes.Load() != 1 || f.executes.Load() != 1 {
		t.Fatal("a refused broker path retried HTTP")
	}
}

func TestNativeWorkerRPCScopeRefusesCredentialHydrationOnOriginalRowDrift(t *testing.T) {
	f := nativeRPCMessage(t)
	for _, fault := range []string{"instanceChecksum", "instanceVersion", "typeChecksum", "target"} {
		t.Run(fault, func(t *testing.T) {
			db, mock, e := sqlmock.New()
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			im, tm, spec := f.instance, f.typ, f.is
			spec.CredentialsRef = "secret://ci/must-never-be-read"
			if fault == "target" {
				spec.Config = map[string]any{"base_url": "https://unowned.invalid"}
			}
			im.Spec, _ = json.Marshal(spec)
			switch fault {
			case "instanceChecksum":
				im.Checksum = strings.Repeat("e", 64)
			case "instanceVersion":
				im.Version++
			case "typeChecksum":
				tm.Checksum = strings.Repeat("e", 64)
			}
			row := func(m model.Manifest) *sqlmock.Rows {
				return sqlmock.NewRows([]string{"id", "api_version", "kind", "namespace", "name", "version", "active", "description", "labels", "spec", "checksum", "created_at", "updated_at"}).AddRow(m.ID, "yggdrasil.io/v1alpha1", m.Kind, m.Metadata.Namespace, m.Metadata.Name, m.Version, true, "", []byte(`{}`), []byte(m.Spec), m.Checksum, time.Now(), time.Now())
			}
			mock.ExpectQuery(`SELECT[\s\S]*FROM public.manifests[\s\S]*WHERE id = \$1`).WithArgs(im.ID).WillReturnRows(row(im))
			mock.ExpectQuery(`SELECT[\s\S]*FROM public.manifests[\s\S]*WHERE id = \$1`).WithArgs(tm.ID).WillReturnRows(row(tm))
			_, _, _, _, e = resolveIntegrationInstance(f.ctx, nil, db, model.ManifestSelector{ManifestID: im.ID.String()})
			if e != errCapacityBoundAssessment {
				t.Fatal("row drift reached secret hydration or a later transport stage", e)
			}
			if e = mock.ExpectationsWereMet(); e != nil {
				t.Fatal(e)
			}
		})
	}
	if f.health.Load() != 0 || f.describes.Load() != 0 || f.executes.Load() != 0 {
		t.Fatal("row drift reached a live endpoint before credential qualification")
	}
	if _, e := NewProtectedNativeWorkerPhysicalReadFunc(nil, nil, nil)(f.ctx, model.CapacityNativeWorkerPhysicalReadBinding{}, model.CapacityNativeWorkerObservationRequest{}); e == nil {
		t.Fatal("uninstalled private read client became callable")
	}
}
