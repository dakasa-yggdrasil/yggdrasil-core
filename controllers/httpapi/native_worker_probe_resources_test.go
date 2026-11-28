package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const nativeProbeListenerTestSource = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const nativeProbeListenerTestToken = "ci-only-native-probe-private-token-000000000000"

// These callbacks are explicitly transport fixtures, not a journal, Kubernetes
// creation, a Store redeem, or independently qualified readiness evidence.
type nativeProbeListenerBackendFixture struct {
	mu               sync.Mutex
	config           NativeWorkerProbeResourceListenerConfig
	calls            map[string]int
	received         model.NativeWorkerProbeResourceReceive
	fail             bool
	ignoreCancel     bool
	bootstrapVariant string
	entered          chan struct{}
	release          <-chan struct{}
}

func (b *nativeProbeListenerBackendFixture) touch(ctx context.Context, action string) error {
	b.mu.Lock()
	b.calls[action]++
	fail, entered, release, ignoreCancel := b.fail, b.entered, b.release, b.ignoreCancel
	b.mu.Unlock()
	if action == "read" && entered != nil {
		close(entered)
		if ignoreCancel {
			<-release
		} else {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if fail {
		return errors.New("private-callback-diagnostic-never-return")
	}
	return nil
}
func (b *nativeProbeListenerBackendFixture) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, v := range b.calls {
		n += v
	}
	return n
}
func (b *nativeProbeListenerBackendFixture) record(in model.NativeWorkerProbeResourceInput) model.NativeWorkerProbeResourceContext {
	kind := "Pod"
	if strings.HasSuffix(in.Slot, "_secret") {
		kind = "Secret"
	}
	out := model.NativeWorkerProbeResourceContext{Schema: model.NativeWorkerProbeResourceContextSchema, BindingName: in.BindingName, RunID: in.RunID, AttemptID: "12345678-1234-4234-8234-123456789abd", Slot: in.Slot, CoreSourceCommit: b.config.CoreSourceCommit, SDKSourceCommit: b.config.SDKSourceCommit, SDKScopeSHA256: b.config.SDKScopeSHA256, Namespace: "probe-ci", NamespaceUID: "12345678-1234-4234-8234-123456789abe", APIVersion: "v1", Kind: kind, Name: "source-fixed-object", PublicTemplateSHA256: strings.Repeat("e", 64), State: "requested", NotAfter: time.Now().Add(time.Minute), Op: "create"}
	if in.Slot == "startup_challenge" {
		out.Op = "startup_patch"
		out.ExpectedUID = "12345678-1234-4234-8234-123456789abf"
		out.ExpectedResourceVersion = "7"
	}
	return out
}
func (b *nativeProbeListenerBackendFixture) Read(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceContext, error) {
	err := b.touch(ctx, "read")
	return b.record(in), err
}
func (b *nativeProbeListenerBackendFixture) Bootstrap(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceBootstrap, error) {
	err := b.touch(ctx, "bootstrap")
	b.mu.Lock()
	variant := b.bootstrapVariant
	b.mu.Unlock()
	out := model.NativeWorkerProbeResourceBootstrap{Schema: model.NativeWorkerProbeResourceBootstrapSchema, Context: b.record(in), ObjectJSON: json.RawMessage(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"source-fixed-object","namespace":"probe-ci"},"data":{"fixture":"cHJpdmF0ZS1ib290c3RyYXAtb25seS1jaQ=="}}`)}
	patch := json.RawMessage(`[{"op":"test","path":"/metadata/uid","value":"12345678-1234-4234-8234-123456789abf"},{"op":"test","path":"/metadata/resourceVersion","value":"7"},{"op":"add","path":"/metadata/annotations/yggdrasil.io~1native-admission-v2","value":"ci-only-private-startup"}]`)
	if in.Slot == "startup_challenge" {
		out.ObjectJSON = patch
	}
	switch variant {
	case "startup_object":
		out.ObjectJSON = json.RawMessage(`{"unexpected":"object"}`)
	case "startup_short_patch":
		out.ObjectJSON = json.RawMessage(`[{"op":"test"},{"op":"test"}]`)
	case "startup_create_op":
		out.Context.Op = "create"
	case "startup_delete_op":
		out.Context.Op = "delete"
	case "foreign_slot_patch":
		out.Context.Op = "startup_patch"
		out.ObjectJSON = patch
	case "create_array":
		out.ObjectJSON = patch
	}
	return out, err
}
func (b *nativeProbeListenerBackendFixture) Redeem(ctx context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourcePermit, error) {
	err := b.touch(ctx, "redeem")
	return model.NativeWorkerProbeResourcePermit{Schema: model.NativeWorkerProbeResourcePermitSchema, Context: b.record(in), SettlementToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}, err
}
func (b *nativeProbeListenerBackendFixture) Receive(ctx context.Context, in model.NativeWorkerProbeResourceReceive) error {
	if err := b.touch(ctx, "receive"); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.received = in
	b.received.OriginalReturn = bytes.Clone(in.OriginalReturn)
	return nil
}

type nativeProbeListenerTLSFixture struct {
	config            NativeWorkerProbeResourceListenerConfig
	client, wrongLeaf tls.Certificate
	roots             *x509.CertPool
	ca                *x509.Certificate
	caKey             ed25519.PrivateKey
}

func nativeProbeListenerTLS(t *testing.T) nativeProbeListenerTLSFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ci-probe-callback-only"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, role x509.ExtKeyUsage, identity string) tls.Certificate {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		uri, e := url.Parse(identity)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}, URIs: []*url.URL{uri}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, ca, p, key)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := x509.ParseCertificate(raw)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: k, Leaf: parsed}
	}
	server := issue(2, x509.ExtKeyUsageServerAuth, "spiffe://native.test/core/probe")
	client := issue(3, x509.ExtKeyUsageClientAuth, "spiffe://native.test/sdk/probe")
	wrong := issue(4, x509.ExtKeyUsageClientAuth, "spiffe://native.test/sdk/foreign")
	c := NativeWorkerProbeResourceListenerConfig{ListenAddr: "127.0.0.1:0", ServerName: "127.0.0.1", CoreSourceCommit: nativeProbeListenerTestSource, BindingName: "source-owned-probe", SDKSourceCommit: strings.Repeat("b", 40), SDKScopeSHA256: strings.Repeat("c", 64), ServerLeafSHA256: nativeProbeResourceDigest(server.Certificate[0]), ServerURI: server.Leaf.URIs[0].String(), ClientLeafSHA256: nativeProbeResourceDigest(client.Certificate[0]), ClientURI: client.Leaf.URIs[0].String(), BearerTokenSHA256: nativeProbeResourceDigest([]byte(nativeProbeListenerTestToken)), ServerCertificate: server, ClientCAs: roots}
	return nativeProbeListenerTLSFixture{c, client, wrong, roots, ca, key}
}
func nativeProbeListenerNew(t *testing.T, f nativeProbeListenerTLSFixture) (*NativeWorkerProbeResourceListener, *nativeProbeListenerBackendFixture) {
	t.Helper()
	b := &nativeProbeListenerBackendFixture{config: f.config, calls: map[string]int{}}
	l, err := newNativeWorkerProbeResourceListener(f.config, b, nativeProbeListenerTestSource)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Error("private listener did not join")
		}
	})
	return l, b
}
func nativeProbeListenerClient(t *testing.T, f nativeProbeListenerTLSFixture, certificate *tls.Certificate) *http.Client {
	t.Helper()
	c := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.roots.Clone()}
	if certificate != nil {
		c.Certificates = []tls.Certificate{*certificate}
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: c, DisableKeepAlives: true}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	return client
}
func nativeProbeListenerInput() model.NativeWorkerProbeResourceInput {
	return model.NativeWorkerProbeResourceInput{BindingName: "source-owned-probe", RunID: "12345678-1234-4234-8234-123456789abc", Slot: "floor_pod"}
}
func nativeProbeListenerRequest(t *testing.T, address, action string, body []byte) *http.Request {
	t.Helper()
	method := http.MethodPost
	u := "https://" + address + nativeProbeResourceBase + action
	if action == "read" || action == "bootstrap" {
		method = http.MethodGet
		in := nativeProbeListenerInput()
		q := url.Values{"binding_name": {in.BindingName}, "run_id": {in.RunID}, "slot": {in.Slot}}
		u += "?" + q.Encode()
	}
	r, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+nativeProbeListenerTestToken)
	r.Header.Set(nativeWorkerPhaseAdapterSourceHeader, strings.Repeat("b", 40))
	r.Header.Set(nativeProbeResourceScopeHeader, strings.Repeat("c", 64))
	return r
}
func nativeProbeListenerResponse(t *testing.T, c *http.Client, r *http.Request, status int) []byte {
	t.Helper()
	out, err := c.Do(r)
	if err != nil {
		t.Fatal("actual TLS callback failed", err)
	}
	raw, readErr := io.ReadAll(out.Body)
	closeErr := out.Body.Close()
	if readErr != nil || closeErr != nil || out.StatusCode != status || len(out.Header.Values("X-Yggdrasil-Source-Commit")) != 1 || out.Header.Get("X-Yggdrasil-Source-Commit") != nativeProbeListenerTestSource || out.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("original callback status/Source/completion", out.StatusCode, status, readErr, closeErr)
	}
	return raw
}

func TestNativeProbeListenerClosedTLSConfigurationAndOwnedMaterial(t *testing.T) {
	f := nativeProbeListenerTLS(t)
	l, _ := nativeProbeListenerNew(t, f)
	original := bytes.Clone(f.config.ServerCertificate.PrivateKey.(ed25519.PrivateKey))
	owned := l.state.config.ServerCertificate.PrivateKey.(ed25519.PrivateKey)
	if &owned[0] == &f.config.ServerCertificate.PrivateKey.(ed25519.PrivateKey)[0] || l.state.config.ClientCAs == f.config.ClientCAs {
		t.Fatal("listener borrowed mutable caller TLS material")
	}
	clear(f.config.ServerCertificate.PrivateKey.(ed25519.PrivateKey))
	if !bytes.Equal(owned, original) {
		t.Fatal("caller key mutation changed listener key")
	}
	copy(f.config.ServerCertificate.PrivateKey.(ed25519.PrivateKey), original)
	for _, v := range []any{f.config, &f.config, l, *l} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		formatted := fmt.Sprintf("%v %+v %#v", v, v, v)
		if strings.Count(formatted, "[private native probe") != 3 || !bytes.Contains(raw, []byte("redacted")) {
			t.Fatal("ordinary private representations were not closed redactions")
		}
		for _, out := range []string{string(raw), formatted} {
			if strings.Contains(out, base64.StdEncoding.EncodeToString(original)) || strings.Contains(out, nativeProbeListenerTestToken) {
				t.Fatal("private listener representation exposed material")
			}
		}
	}
	for _, item := range []struct {
		name   string
		change func(*NativeWorkerProbeResourceListenerConfig)
	}{
		{"source", func(c *NativeWorkerProbeResourceListenerConfig) { c.CoreSourceCommit = strings.Repeat("d", 40) }}, {"sdk", func(c *NativeWorkerProbeResourceListenerConfig) { c.SDKSourceCommit = "" }}, {"scope", func(c *NativeWorkerProbeResourceListenerConfig) { c.SDKScopeSHA256 = "" }}, {"binding", func(c *NativeWorkerProbeResourceListenerConfig) { c.BindingName = "" }}, {"hostname", func(c *NativeWorkerProbeResourceListenerConfig) { c.ServerName = "foreign.example" }}, {"uri", func(c *NativeWorkerProbeResourceListenerConfig) { c.ServerURI = "spiffe://native.test/foreign" }}, {"leaf", func(c *NativeWorkerProbeResourceListenerConfig) { c.ServerLeafSHA256 = strings.Repeat("d", 64) }}, {"client_uri", func(c *NativeWorkerProbeResourceListenerConfig) { c.ClientURI = "https://native.test/foreign" }}, {"empty_ca", func(c *NativeWorkerProbeResourceListenerConfig) { c.ClientCAs = x509.NewCertPool() }}, {"dns_bind", func(c *NativeWorkerProbeResourceListenerConfig) { c.ListenAddr = "ambient.example:9447" }}, {"wrong_eku", func(c *NativeWorkerProbeResourceListenerConfig) {
			c.ServerCertificate = f.client
			c.ServerURI = f.client.Leaf.URIs[0].String()
			c.ServerLeafSHA256 = nativeProbeResourceDigest(f.client.Certificate[0])
		}}, {"key", func(c *NativeWorkerProbeResourceListenerConfig) { c.ServerCertificate.PrivateKey = f.client.PrivateKey }},
	} {
		t.Run(item.name, func(t *testing.T) {
			c := f.config
			item.change(&c)
			if got, err := newNativeWorkerProbeResourceListener(c, &nativeProbeListenerBackendFixture{}, nativeProbeListenerTestSource); err == nil {
				_ = got.Close()
				t.Fatal("invalid protected configuration accepted")
			}
		})
	}
	for _, item := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }},
		{"future", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{"ca_leaf", func(c *x509.Certificate) { c.IsCA = true; c.BasicConstraintsValid = true }},
		{"duplicate_uri", func(c *x509.Certificate) { c.URIs = append(c.URIs, c.URIs[0]) }},
	} {
		t.Run(item.name, func(t *testing.T) {
			c := f.config
			leaf := *c.ServerCertificate.Leaf
			item.change(&leaf)
			raw, err := x509.CreateCertificate(rand.Reader, &leaf, f.ca, leaf.PublicKey, f.caKey)
			if err != nil {
				t.Fatal(err)
			}
			c.ServerCertificate.Certificate = [][]byte{raw}
			c.ServerLeafSHA256 = nativeProbeResourceDigest(raw)
			if got, err := newNativeWorkerProbeResourceListener(c, &nativeProbeListenerBackendFixture{}, nativeProbeListenerTestSource); err == nil {
				_ = got.Close()
				t.Fatal("coherent pin hid invalid actual leaf")
			}
		})
	}
	if _, err := newNativeWorkerProbeResourceListener(f.config, (*nativeProbeListenerBackendFixture)(nil), nativeProbeListenerTestSource); err == nil {
		t.Fatal("typed nil backend accepted")
	}
	var zero NativeWorkerProbeResourceListener
	if zero.Start(context.Background()) == nil || zero.Address() != "" || zero.Close() != nil {
		t.Fatal("zero listener gained authority")
	}
	var absent *NativeWorkerProbeResourceListener
	if absent.Start(context.Background()) == nil || absent.Address() != "" || absent.Close() != nil {
		t.Fatal("nil listener gained authority")
	}
}

func TestNativeProbeListenerRealMTLSAndExactHeadersBeforeBody(t *testing.T) {
	f := nativeProbeListenerTLS(t)
	l, b := nativeProbeListenerNew(t, f)
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name string
		cert *tls.Certificate
	}{{"missing", nil}, {"foreign_ca", func() *tls.Certificate { x := nativeProbeListenerTLS(t).client; return &x }()}} {
		t.Run(item.name, func(t *testing.T) {
			client := nativeProbeListenerClient(t, f, item.cert)
			r := nativeProbeListenerRequest(t, l.Address(), "read", nil)
			if response, err := client.Do(r); err == nil {
				_ = response.Body.Close()
				t.Fatal("unverified peer reached HTTP")
			}
		})
	}
	wrong := nativeProbeListenerClient(t, f, &f.wrongLeaf)
	nativeProbeListenerResponse(t, wrong, nativeProbeListenerRequest(t, l.Address(), "redeem", []byte("private-body-never-read")), http.StatusForbidden)
	client := nativeProbeListenerClient(t, f, &f.client)
	for _, item := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer wrong-token-that-is-long-enough-000000") }}, {"duplicate_bearer", func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+nativeProbeListenerTestToken) }}, {"sdk_source", func(r *http.Request) { r.Header.Set(nativeWorkerPhaseAdapterSourceHeader, strings.Repeat("f", 40)) }}, {"duplicate_source", func(r *http.Request) { r.Header.Add(nativeWorkerPhaseAdapterSourceHeader, strings.Repeat("b", 40)) }}, {"scope", func(r *http.Request) { r.Header.Set(nativeProbeResourceScopeHeader, strings.Repeat("d", 64)) }}, {"duplicate_scope", func(r *http.Request) { r.Header.Add(nativeProbeResourceScopeHeader, strings.Repeat("c", 64)) }},
	} {
		t.Run(item.name, func(t *testing.T) {
			r := nativeProbeListenerRequest(t, l.Address(), "redeem", []byte("private-body"))
			item.change(r)
			nativeProbeListenerResponse(t, client, r, http.StatusForbidden)
		})
	}
	if b.count() != 0 {
		t.Fatal("failed authenticated TLS/header checks reached backend")
	}
	body := &nativeProbeListenerRequestBody{}
	r := nativeProbeListenerDirectRequest(t, f, body)
	r.Header.Add(nativeProbeResourceScopeHeader, f.config.SDKScopeSHA256)
	w := httptest.NewRecorder()
	l.state.handle(w, r)
	if body.reads != 0 || body.closes != 0 || b.count() != 0 {
		t.Fatal("authorization consumed body or journal")
	}
}

type nativeProbeListenerRequestBody struct {
	raw               []byte
	reads, closes     int
	readErr, closeErr error
	onClose           func()
}

func (b *nativeProbeListenerRequestBody) Read(p []byte) (int, error) {
	b.reads++
	if b.readErr != nil {
		return 0, b.readErr
	}
	if len(b.raw) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.raw)
	b.raw = b.raw[n:]
	return n, nil
}
func (b *nativeProbeListenerRequestBody) Close() error {
	b.closes++
	if b.onClose != nil {
		b.onClose()
	}
	return b.closeErr
}
func nativeProbeListenerDirectRequest(t *testing.T, f nativeProbeListenerTLSFixture, body io.ReadCloser) *http.Request {
	t.Helper()
	r := nativeProbeListenerRequest(t, "127.0.0.1:9447", "redeem", nil)
	r.Body = body
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{f.client.Leaf}, VerifiedChains: [][]*x509.Certificate{{f.client.Leaf}}}
	return r
}
func TestNativeProbeListenerOriginalCloseCancelLimitsAndClosedSelectors(t *testing.T) {
	f := nativeProbeListenerTLS(t)
	l, b := nativeProbeListenerNew(t, f)
	good, _ := json.Marshal(nativeProbeListenerInput())
	for _, fault := range []string{"read", "close", "cancel", "limit", "duplicate", "case", "unknown", "wrong_binding", "noncanonical_uuid", "wrong_slot", "null"} {
		t.Run(fault, func(t *testing.T) {
			body := &nativeProbeListenerRequestBody{raw: bytes.Clone(good)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "read":
				body.readErr = errors.New("private-read-error")
			case "close":
				body.closeErr = errors.New("private-close-error")
			case "cancel":
				body.onClose = cancel
			case "limit":
				body.raw = bytes.Repeat([]byte{'x'}, (2<<20)+1)
			case "duplicate":
				body.raw = bytes.Replace(good, []byte(`"run_id":`), []byte(`"run_id":"duplicate","run_id":`), 1)
			case "case":
				body.raw = bytes.Replace(good, []byte(`"run_id"`), []byte(`"Run_ID"`), 1)
			case "unknown":
				body.raw = bytes.Replace(good, []byte(`"slot":`), []byte(`"endpoint":"never-used","slot":`), 1)
			case "wrong_binding":
				body.raw = bytes.Replace(good, []byte("source-owned-probe"), []byte("other-probe"), 1)
			case "noncanonical_uuid":
				body.raw = bytes.Replace(good, []byte("12345678-1234-4234-8234-123456789abc"), []byte("12345678-1234-4234-8234-123456789ABC"), 1)
			case "wrong_slot":
				body.raw = bytes.Replace(good, []byte("floor_pod"), []byte("floor_initial"), 1)
			case "null":
				body.raw = []byte("null")
			}
			r := nativeProbeListenerDirectRequest(t, f, body).WithContext(ctx)
			w := httptest.NewRecorder()
			l.state.handle(w, r)
			if w.Code != 400 || body.closes != 1 || b.count() != 0 || strings.Contains(w.Body.String(), "private-") {
				t.Fatal("incomplete/foreign original reached journal or leaked diagnosis", w.Code)
			}
		})
	}
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := nativeProbeListenerClient(t, f, &f.client)
	for _, fault := range []string{"query_duplicate", "query_unknown", "get_body", "raw_path", "wrong_method", "public_fallback"} {
		r := nativeProbeListenerRequest(t, l.Address(), "read", nil)
		status := 400
		switch fault {
		case "query_duplicate":
			r.URL.RawQuery += "&slot=floor_pod"
		case "query_unknown":
			r.URL.RawQuery += "&url=never"
		case "get_body":
			r.Body = io.NopCloser(strings.NewReader("x"))
			r.ContentLength = 1
		case "raw_path":
			r.URL.RawPath = strings.Replace(r.URL.Path, "read", "%72ead", 1)
			status = 404
		case "wrong_method":
			r.Method = http.MethodPost
			status = 404
		case "public_fallback":
			r.URL.Path = "/healthz"
			status = 404
		}
		nativeProbeListenerResponse(t, client, r, status)
	}
	if b.count() != 0 {
		t.Fatal("closed route/selector refusal reached callback")
	}
}

func TestNativeProbeListenerFourRealTLSCallbacksKeepPrivateWireAndEmptyReceive(t *testing.T) {
	f := nativeProbeListenerTLS(t)
	l, b := nativeProbeListenerNew(t, f)
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := nativeProbeListenerClient(t, f, &f.client)
	input := nativeProbeListenerInput()
	input.Slot = "admission_secret"
	request := func(action string, body []byte) *http.Request {
		r := nativeProbeListenerRequest(t, l.Address(), action, body)
		if r.Method == http.MethodGet {
			q := r.URL.Query()
			q.Set("slot", input.Slot)
			r.URL.RawQuery = q.Encode()
		}
		return r
	}
	raw, _ := json.Marshal(input)
	var current model.NativeWorkerProbeResourceContext
	if json.Unmarshal(nativeProbeListenerResponse(t, client, request("read", nil), 200), &current) != nil || current.RunID != input.RunID || current.Slot != input.Slot || current.Kind != "Secret" {
		t.Fatal("actual context missing")
	}
	var bootstrap model.NativeWorkerProbeResourceBootstrap
	if json.Unmarshal(nativeProbeListenerResponse(t, client, request("bootstrap", nil), 200), &bootstrap) != nil || !bytes.Contains(bootstrap.ObjectJSON, []byte("cHJpdmF0ZS1ib290c3RyYXAtb25seS1jaQ==")) || bootstrap.Context.Slot != input.Slot || bootstrap.Context.Kind != "Secret" {
		t.Fatal("private bootstrap marshal was replaced by redacted public shape")
	}
	var permit model.NativeWorkerProbeResourcePermit
	if json.Unmarshal(nativeProbeListenerResponse(t, client, request("redeem", raw), 200), &permit) != nil || !nativeProbeResourceToken(permit.SettlementToken) {
		t.Fatal("private original permit missing")
	}
	received := model.NativeWorkerProbeResourceReceive{BindingName: input.BindingName, RunID: input.RunID, Slot: input.Slot, SettlementToken: permit.SettlementToken, HTTPStatus: 201, CompletedAt: time.Now().Add(-time.Hour), TransportCompleted: false, OriginalReturn: []byte(`{"private_original":"test-only"}`)}
	raw, err := received.MarshalPrivateJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(nativeProbeListenerResponse(t, client, request("receive", raw), 204)) != 0 {
		t.Fatal("receive acknowledgement has a body")
	}
	b.mu.Lock()
	retained := b.received
	b.mu.Unlock()
	if !bytes.Equal(retained.OriginalReturn, received.OriginalReturn) || !retained.CompletedAt.Equal(received.CompletedAt) || retained.TransportCompleted {
		t.Fatal("listener changed late/incomplete original custody")
	}
	originalInput := input
	input.Slot = "startup_challenge"
	var startup model.NativeWorkerProbeResourceBootstrap
	if json.Unmarshal(nativeProbeListenerResponse(t, client, request("bootstrap", nil), 200), &startup) != nil || startup.Context.Op != "startup_patch" || startup.Context.Slot != input.Slot {
		t.Fatal("reviewed startup patch slot did not reach private callback")
	}
	var patch []json.RawMessage
	if json.Unmarshal(startup.ObjectJSON, &patch) != nil || len(patch) != 3 {
		t.Fatal("startup patch lost its three original steps")
	}
	for _, variant := range []string{"startup_object", "startup_short_patch", "startup_create_op", "startup_delete_op", "foreign_slot_patch", "create_array"} {
		input.Slot = "startup_challenge"
		if variant == "foreign_slot_patch" || variant == "create_array" {
			input.Slot = "floor_pod"
		}
		b.mu.Lock()
		b.bootstrapVariant = variant
		b.mu.Unlock()
		nativeProbeListenerResponse(t, client, request("bootstrap", nil), 503)
	}
	b.mu.Lock()
	b.bootstrapVariant = ""
	b.mu.Unlock()
	input = originalInput
	for _, value := range []any{bootstrap, &bootstrap, permit, &permit, received, &received} {
		public, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(public, bootstrap.ObjectJSON) || bytes.Contains(public, []byte(permit.SettlementToken)) || bytes.Contains(public, received.OriginalReturn) {
			t.Fatal("private DTO escaped ordinary serialization")
		}
	}
	b.mu.Lock()
	b.fail = true
	b.mu.Unlock()
	public := nativeProbeListenerResponse(t, client, request("read", nil), 503)
	if bytes.Contains(public, []byte("private-callback")) {
		t.Fatal("backend error leaked")
	}
	received.OriginalReturn = bytes.Repeat([]byte{'x'}, (1<<20)+1)
	raw, _ = received.MarshalPrivateJSON()
	nativeProbeListenerResponse(t, client, request("receive", raw), 400)
}

func TestNativeProbeListenerOneStartKeepsOriginalCallbacksDuringOwnedClose(t *testing.T) {
	f := nativeProbeListenerTLS(t)
	l, b := nativeProbeListenerNew(t, f)
	parent, cancel := context.WithCancel(context.Background())
	if err := l.Start(parent); err != nil {
		t.Fatal(err)
	}
	cancel()
	if l.Start(context.Background()) == nil {
		t.Fatal("listener started twice")
	}
	client := nativeProbeListenerClient(t, f, &f.client)
	nativeProbeListenerResponse(t, client, nativeProbeListenerRequest(t, l.Address(), "read", nil), 200)
	entered, release := make(chan struct{}), make(chan struct{})
	b.mu.Lock()
	b.entered, b.release = entered, release
	b.mu.Unlock()
	returned := make(chan error, 1)
	originalRequest := nativeProbeListenerRequest(t, l.Address(), "read", nil)
	go func() {
		r, err := client.Do(originalRequest)
		if err == nil {
			_, err = io.Copy(io.Discard, r.Body)
			err = errors.Join(err, r.Body.Close())
		}
		returned <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual callback did not enter")
	}
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		l.state.mu.Lock()
		closing := l.state.closing
		l.state.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("owned close did not seal")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-closed:
		t.Fatal("close claimed joined while callback remained active")
	default:
	}
	close(release)
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal("parent cancellation destroyed original callback", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("original callback failed to return")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not join")
	}
	if l.Close() != nil || l.Start(context.Background()) == nil {
		t.Fatal("closed listener reopened")
	}
	// Backend remains borrowed and available; listener never closes its owner.
	b.mu.Lock()
	b.entered, b.release = nil, nil
	b.mu.Unlock()
	if _, err := b.Read(context.Background(), nativeProbeListenerInput()); err != nil {
		t.Fatal("listener stole backend ownership")
	}
}

// This deliberately non-cooperative callback proves that transport closure is
// not a claim that an arbitrary borrowed producer has finished its operation.
func TestNativeProbeListenerFiniteCloseDoesNotClaimUnjoinedBackend(t *testing.T) {
	f := nativeProbeListenerTLS(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	b := &nativeProbeListenerBackendFixture{config: f.config, calls: map[string]int{}, entered: entered, release: release, ignoreCancel: true}
	l, err := newNativeWorkerProbeResourceListener(f.config, b, nativeProbeListenerTestSource)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock(); _ = l.Close() })
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := nativeProbeListenerClient(t, f, &f.client)
	client.Timeout = 20 * time.Second
	req := nativeProbeListenerRequest(t, l.Address(), "read", nil)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		r, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("borrowed callback did not enter")
	}
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("unjoined callback gained a successful close")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("owned close exceeded its finite budget")
	}
	l.state.mu.Lock()
	idle := l.state.idle
	l.state.mu.Unlock()
	select {
	case <-idle:
		t.Fatal("non-cooperative callback unexpectedly joined")
	default:
	}
	unblock()
	select {
	case <-idle:
	case <-time.After(2 * time.Second):
		t.Fatal("released borrowed callback did not finish")
	}
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("owned HTTP caller did not return")
	}
	if l.Close() == nil {
		t.Fatal("idempotent close erased its original unresolved result")
	}
}
