package nativeworkerprobe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func trustedProbeClient(t *testing.T, f probeTLSFixture) tls.Certificate {
	t.Helper()
	pub, key := packetKeys(t)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(23), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.ca, pub, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func probeHTTP(t *testing.T, e *engine, ctx context.Context, f probeTLSFixture) *httptest.Server {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.ca)
	s := httptest.NewUnstartedServer(e.handler(ctx, fixtureSource))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{f.server}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func probeClient(t *testing.T, f probeTLSFixture, cert *tls.Certificate) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.ca)
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: config}
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrUnavailable }}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func probeCall(t *testing.T, client *http.Client, method, url, body string, want int) []byte {
	t.Helper()
	var input io.Reader
	if body != "" {
		input = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, input)
	if err != nil {
		t.Fatal(err)
	}
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(r.Body)
	closeErr := r.Body.Close()
	if r.StatusCode != want || readErr != nil || closeErr != nil || len(r.Header.Values("X-Yggdrasil-Source-Commit")) != 1 || r.Header.Get("X-Yggdrasil-Source-Commit") != fixtureSource {
		t.Fatal("original HTTP status/Source/completion", r.StatusCode, want, readErr, closeErr)
	}
	return raw
}

type trackedRequestBody struct {
	reads, closes int
	closeErr      error
}

func (b *trackedRequestBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *trackedRequestBody) Close() error             { b.closes++; return b.closeErr }

func TestProbeRealMTLSRefusesBeforeBodyAndKeepsSourceOnEveryOutcome(t *testing.T) {
	_, key := packetKeys(t)
	t.Cleanup(func() { wipe(key) })
	f := tlsFixture(t, "127.0.0.1")
	c := testConfig("floor")
	c.ControllerLeafSHA256 = sha(f.clientDER)
	e := &engine{material: &material{config: c, scope: "scope", signing: key}, initial: emptyBatch(), final: emptyBatch(), changed: make(chan struct{}, 1)}
	s := probeHTTP(t, e, context.Background(), f)
	probeCall(t, probeClient(t, f, nil), http.MethodPost, s.URL+InitialPath, "untrusted-body", http.StatusUnauthorized)
	wrong := trustedProbeClient(t, f)
	probeCall(t, probeClient(t, f, &wrong), http.MethodPost, s.URL+InitialPath, "untrusted-body", http.StatusForbidden)
	client := probeClient(t, f, &f.client)
	probeCall(t, client, http.MethodGet, s.URL+ReportPath, "", http.StatusOK)
	probeCall(t, client, http.MethodGet, s.URL+StartupPath, "", http.StatusForbidden)
	probeCall(t, client, http.MethodPost, s.URL+FinalPath, "", http.StatusConflict)
	probeCall(t, client, http.MethodPost, s.URL+InitialPath, "nonempty", http.StatusBadRequest)
	probeCall(t, client, http.MethodPost, s.URL+InitialPath+"?sequence=9", "", http.StatusBadRequest)
	probeCall(t, client, http.MethodGet, s.URL+"/probe/%72eport", "", http.StatusBadRequest)
	probeCall(t, client, http.MethodPost, s.URL+"/arbitrary", "", http.StatusNotFound)
	foreign := tlsFixture(t, "127.0.0.1")
	if r, err := probeClient(t, f, &foreign.client).Get(s.URL + ReportPath); err == nil {
		_ = r.Body.Close()
		t.Fatal("untrusted CA completed a TLS request")
	}
	for _, cert := range []*x509.Certificate{nil, mustProbeCertificate(t, wrong.Certificate[0])} {
		body := &trackedRequestBody{}
		r := httptest.NewRequest(http.MethodPost, "https://probe"+InitialPath, nil)
		r.Body = body
		if cert != nil {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, f.ca}}}
		}
		w := httptest.NewRecorder()
		e.handler(context.Background(), fixtureSource).ServeHTTP(w, r)
		if body.reads != 0 || body.closes != 0 || e.initial.report.State != "idle" {
			t.Fatal("unauthenticated identity touched body or phase state")
		}
	}
	keyCopy := append(ed25519.PrivateKey(nil), key...)
	raw, err := json.Marshal(e.report(fixtureSource))
	if err != nil || strings.Contains(string(raw), base64.StdEncoding.EncodeToString(keyCopy)) {
		t.Fatal("public report leaked private material", err)
	}
}

func TestProbeAuthenticatedBodyCloseAndRequestCancellationCannotStart(t *testing.T) {
	f := tlsFixture(t, "127.0.0.1")
	_, key := packetKeys(t)
	t.Cleanup(func() { wipe(key) })
	c := testConfig("floor")
	c.ControllerLeafSHA256 = sha(f.clientDER)
	e := &engine{material: &material{config: c, signing: key}, initial: emptyBatch(), final: emptyBatch(), changed: make(chan struct{}, 1)}
	leaf := mustProbeCertificate(t, f.clientDER)
	for _, class := range []string{"close_error", "canceled"} {
		t.Run(class, func(t *testing.T) {
			body := &trackedRequestBody{}
			r := httptest.NewRequest(http.MethodPost, "https://probe"+InitialPath, nil)
			r.Body, r.TLS = body, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, f.ca}}}
			if class == "close_error" {
				body.closeErr = ErrUnavailable
			} else {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			e.handler(context.Background(), fixtureSource).ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || body.reads != 1 || body.closes != 1 || e.initial.report.State != "idle" {
				t.Fatal("incomplete original request gained a phase", w.Code, body.reads, body.closes)
			}
		})
	}
	e.material.config.HardNotAfter = time.Now().Add(-time.Second)
	r := httptest.NewRequest(http.MethodGet, "https://probe"+ReportPath, nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, f.ca}}}
	w := httptest.NewRecorder()
	e.handler(context.Background(), fixtureSource).ServeHTTP(w, r)
	if w.Code != http.StatusGone || w.Header().Get("X-Yggdrasil-Source-Commit") != fixtureSource {
		t.Fatal("run expiry lost Source or allowed a fresh observation")
	}
}

func mustProbeCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProbeRealAuthenticatedPOSTStartsExactlyOnceAndGETOnlyReobserves(t *testing.T) {
	a, b, ctx := enginePair(t)
	f := tlsFixture(t, "127.0.0.1")
	a.material.config.ControllerLeafSHA256, b.material.config.ControllerLeafSHA256 = sha(f.clientDER), sha(f.clientDER)
	as, bs := probeHTTP(t, a, ctx, f), probeHTTP(t, b, ctx, f)
	client := probeClient(t, f, &f.client)
	for _, phase := range []string{InitialPath, FinalPath} {
		for _, server := range []*httptest.Server{as, bs} {
			probeCall(t, client, http.MethodPost, server.URL+phase, "", http.StatusAccepted)
		}
		name := "initial"
		if phase == FinalPath {
			name = "final"
		}
		for _, e := range []*engine{a, b} {
			waitProbeBatch(t, e, name, "complete")
		}
		for _, server := range []*httptest.Server{as, bs} {
			probeCall(t, client, http.MethodPost, server.URL+phase, "", http.StatusConflict)
			var report Report
			if json.Unmarshal(probeCall(t, client, http.MethodGet, server.URL+ReportPath, "", http.StatusOK), &report) != nil || report.SourceCommit != fixtureSource || report.ConfigSHA256 == "" {
				t.Fatal("original report missing identity")
			}
		}
	}
	for _, e := range []*engine{a, b} {
		r := e.report(fixtureSource)
		if len(r.Initial.Sent)+len(r.Final.Sent) != 6 || len(r.Initial.Echoed)+len(r.Final.Echoed) != 6 {
			t.Fatal("HTTP replay increased original packet budget")
		}
	}
}
