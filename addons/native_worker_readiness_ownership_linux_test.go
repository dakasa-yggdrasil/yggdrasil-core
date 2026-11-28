//go:build linux && native_readiness_ownership

package addons

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// CI builds this tagged test executable with native clean buildvcs metadata.
// The public listener constructor is used: no Source override, env pin, private
// test constructor, provider/Node qualification or readiness proof is involved.
type nativeReadinessOwnershipBackend struct {
	config  httpapi.NativeWorkerProbeResourceListenerConfig
	entered chan struct{}
	release <-chan struct{}
	left    chan struct{}
	once    sync.Once
}

func (b *nativeReadinessOwnershipBackend) Read(_ context.Context, in model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceContext, error) {
	if b.entered != nil {
		b.once.Do(func() { close(b.entered) })
		// Intentionally uncooperative original user proves that forced HTTP
		// shutdown cannot claim an owned-handler join or close its dependencies.
		<-b.release
		close(b.left)
	}
	return model.NativeWorkerProbeResourceContext{Schema: model.NativeWorkerProbeResourceContextSchema, BindingName: in.BindingName, RunID: in.RunID, Slot: in.Slot, CoreSourceCommit: b.config.CoreSourceCommit, SDKSourceCommit: b.config.SDKSourceCommit, SDKScopeSHA256: b.config.SDKScopeSHA256}, nil
}
func (*nativeReadinessOwnershipBackend) Bootstrap(context.Context, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourceBootstrap, error) {
	return model.NativeWorkerProbeResourceBootstrap{}, errors.New("unused ownership fixture route")
}
func (*nativeReadinessOwnershipBackend) Redeem(context.Context, model.NativeWorkerProbeResourceInput) (model.NativeWorkerProbeResourcePermit, error) {
	return model.NativeWorkerProbeResourcePermit{}, errors.New("unused ownership fixture route")
}
func (*nativeReadinessOwnershipBackend) Receive(context.Context, model.NativeWorkerProbeResourceReceive) error {
	return errors.New("unused ownership fixture route")
}

type nativeReadinessOwnershipTLS struct {
	listener *httpapi.NativeWorkerProbeResourceListener
	backend  *nativeReadinessOwnershipBackend
	client   *http.Client
	token    string
}

func nativeReadinessOwnershipDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func nativeReadinessOwnershipFixture(t *testing.T, blocked bool) nativeReadinessOwnershipTLS {
	t.Helper()
	source := capacity.CurrentGuestCoreSource()
	if !nativeRuntimeSource.MatchString(source) {
		t.Fatal("native clean buildvcs Source missing; ownership qualification was not exercised")
	}
	now := time.Now()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CI readiness owner only"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
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
	issue := func(serial int64, usage x509.ExtKeyUsage, identity string) tls.Certificate {
		t.Helper()
		public, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		u, e := url.Parse(identity)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{u}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, ca, public, key)
		if e != nil {
			t.Fatal(e)
		}
		parsed, e := x509.ParseCertificate(raw)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: private, Leaf: parsed}
	}
	server := issue(2, x509.ExtKeyUsageServerAuth, "spiffe://readiness.test/core")
	client := issue(3, x509.ExtKeyUsageClientAuth, "spiffe://readiness.test/sdk")
	token := strings.Repeat("ownership-fixture-only-", 3)
	c := httpapi.NativeWorkerProbeResourceListenerConfig{ListenAddr: "127.0.0.1:0", ServerName: "127.0.0.1", CoreSourceCommit: source, BindingName: "readiness-owner-ci", SDKSourceCommit: strings.Repeat("b", 40), SDKScopeSHA256: strings.Repeat("c", 64), ServerLeafSHA256: nativeReadinessOwnershipDigest(server.Certificate[0]), ServerURI: server.Leaf.URIs[0].String(), ClientLeafSHA256: nativeReadinessOwnershipDigest(client.Certificate[0]), ClientURI: client.Leaf.URIs[0].String(), BearerTokenSHA256: nativeReadinessOwnershipDigest([]byte(token)), ServerCertificate: server, ClientCAs: roots}
	b := &nativeReadinessOwnershipBackend{config: c}
	var release chan struct{}
	if blocked {
		release = make(chan struct{})
		b.entered, b.release, b.left = make(chan struct{}), release, make(chan struct{})
	}
	l, err := httpapi.NewNativeWorkerProbeResourceListener(c, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{client}}}
	h := &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() {
		if release != nil {
			close(release)
			select {
			case <-b.left:
			case <-time.After(2 * time.Second):
				t.Error("original fixture user did not leave")
			}
		}
		_ = l.Close() // A forced original Close remains an error after it joins.
		h.CloseIdleConnections()
	})
	return nativeReadinessOwnershipTLS{l, b, h, token}
}

func (f nativeReadinessOwnershipTLS) request() (*http.Response, error) {
	q := url.Values{"binding_name": {f.backend.config.BindingName}, "run_id": {"12345678-1234-4234-8234-123456789abc"}, "slot": {"floor_pod"}}
	r, err := http.NewRequest(http.MethodGet, "https://"+f.listener.Address()+"/internal/capacity/native-workers/probe-resources/read?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+f.token)
	r.Header.Set("X-Yggdrasil-Adapter-Source-Commit", f.backend.config.SDKSourceCommit)
	r.Header.Set("X-Yggdrasil-Adapter-Scope-SHA256", f.backend.config.SDKScopeSHA256)
	return f.client.Do(r)
}

func TestNativeReadinessOwnedTLSCallbackHoldsWorkersAndRollbackDependencies(t *testing.T) {
	f := nativeReadinessOwnershipFixture(t, true)
	returned := make(chan error, 1)
	go func() {
		r, err := f.request()
		if r != nil {
			_, readErr := io.Copy(io.Discard, r.Body)
			err = errors.Join(err, readErr, r.Body.Close())
		}
		returned <- err
	}()
	select {
	case <-f.backend.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual authenticated callback did not enter")
	}
	readiness := &nativeWorkerReadinessOwner{listener: f.listener}
	var lower atomic.Int32
	// The real owner chain has the same transfer order: readiness after Workers
	// in construction, hence readiness before borrowed Workers during Close.
	o := &nativeWorkerRuntimeOwner{&nativeWorkerRuntimeOwnerState{closers: []func() error{func() error { lower.Add(1); return nil }, readiness.Close}}}
	startup := errors.New("CI installation failure after listener start")
	retained, err := o.rollbackConstruction(startup)
	if retained != o || !errors.Is(err, startup) || !errors.Is(err, runtime.ErrDependencyShutdownHeld) || lower.Load() != 0 || len(o.closers) != 2 {
		t.Fatal("constructor rollback lost opaque original owner or closed Workers")
	}
	if ro, e := readiness.rollbackConstruction(startup); ro != readiness || !errors.Is(e, runtime.ErrDependencyShutdownHeld) {
		t.Fatal("inner readiness rollback discarded held receiving ownership")
	}
	app := runtime.New("CI retained rollback")
	app.RegisterCloser(func(context.Context) error { lower.Add(1); return nil }) // DB
	app.RegisterCloser(func(context.Context) error { lower.Add(1); return nil }) // broker
	// This is the exact startup-failure rollback used by bootstrapHTTP.
	err = rollbackNativeWorkerRuntimeInstallation(app, retained, err)
	if !errors.Is(err, runtime.ErrDependencyShutdownHeld) {
		t.Fatal("HTTP startup rollback discarded original hold")
	}
	for range 2 {
		if e := app.Shutdown(context.Background()); !errors.Is(e, runtime.ErrDependencyShutdownHeld) || lower.Load() != 0 {
			t.Fatal("startup failure closed borrowed DB/broker or second Close hid hold")
		}
	}
	if readiness.closed || !errors.Is(o.Close(), runtime.ErrDependencyShutdownHeld) || !errors.Is(readiness.Close(), runtime.ErrDependencyShutdownHeld) {
		t.Fatal("forced listener Close became a joined result")
	}
	select {
	case <-returned: // Force-close releases transport, not its original backend.
	case <-time.After(2 * time.Second):
		t.Fatal("force-closed original HTTP transport did not return")
	}
	select {
	case <-f.backend.left:
		t.Fatal("backend joined before original release")
	default:
	}
}

func TestNativeReadinessJoinedTLSReceivingClosesBeforeWorkersAndLegacySecondClose(t *testing.T) {
	f := nativeReadinessOwnershipFixture(t, false)
	r, err := f.request()
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, r.Body)
	if errors.Join(readErr, r.Body.Close()) != nil || r.StatusCode != http.StatusOK || r.Header.Get("X-Yggdrasil-Source-Commit") != capacity.CurrentGuestCoreSource() {
		t.Fatal("actual Source-bound callback did not complete")
	}
	readiness := &nativeWorkerReadinessOwner{listener: f.listener}
	var order []string
	sentinel := errors.New("ordinary lower close error")
	o := &nativeWorkerRuntimeOwner{&nativeWorkerRuntimeOwnerState{closers: []func() error{
		func() error {
			if !readiness.closed {
				t.Error("Workers closed before receiving joined")
			}
			if response, e := f.request(); e == nil {
				_ = response.Body.Close()
				t.Error("listener still admitted callbacks after readiness Close")
			}
			order = append(order, "workers")
			return sentinel
		},
		func() error {
			err := readiness.Close()
			order = append(order, "readiness")
			return err
		},
	}}}
	if err := o.Close(); !errors.Is(err, sentinel) || errors.Is(err, runtime.ErrDependencyShutdownHeld) || !reflect.DeepEqual(order, []string{"readiness", "workers"}) {
		t.Fatal("successful join changed real LIFO order or ordinary error")
	}
	if err := o.Close(); err != nil || len(order) != 2 {
		t.Fatal("legacy ordinary second Close changed or repeated a closer")
	}
}
