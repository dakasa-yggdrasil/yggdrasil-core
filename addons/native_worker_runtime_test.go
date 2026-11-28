package addons

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeRuntimeClosedConfigurationAndAbsentOnlyOff(t *testing.T) {
	old, present := os.LookupEnv(nativeWorkerRuntimeFileEnv)
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(nativeWorkerRuntimeFileEnv, old)
		} else {
			_ = os.Unsetenv(nativeWorkerRuntimeFileEnv)
		}
	})
	if err := os.Unsetenv(nativeWorkerRuntimeFileEnv); err != nil {
		t.Fatal(err)
	}
	if owner, err := loadNativeWorkerRuntime(context.Background(), nil, nil, coreprocess.APIWorker); err != nil || owner != nil {
		t.Fatal("absent file changed existing startup")
	}
	if err := os.Setenv(nativeWorkerRuntimeFileEnv, ""); err != nil {
		t.Fatal(err)
	}
	if owner, err := loadNativeWorkerRuntime(context.Background(), runtime.New("ci"), new(sql.DB), coreprocess.APIWorker); err == nil || owner != nil {
		t.Fatal("worker role adopted authority configuration")
	}
	if owner, err := loadNativeWorkerRuntime(context.Background(), runtime.New("ci"), new(sql.DB), coreprocess.Authority); err == nil || owner != nil {
		t.Fatal("present empty configuration fell back to disabled")
	}
	c := nativeWorkerRuntimeConfig{Schema: nativeWorkerRuntimeSchema, CoreSourceCommit: strings.Repeat("a", 40), Policy: nativeWorkerPolicyPin{ID: uuid.New(), Namespace: "infra", Name: "workers", Version: 1, Checksum: strings.Repeat("b", 64)}, PoolReaderScopeSHA256: strings.Repeat("c", 64), Profiles: []nativeWorkerProfileFiles{{Profile: "aws"}}}
	// Bypass ONLY the public redactor to create a synthetic on-disk fixture.
	type wire nativeWorkerRuntimeConfig
	raw := mustNativeJSON(t, wire(c))
	if _, err := nativeWorkerConfigDecode(raw, c.CoreSourceCommit); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"schema":`, `"schema":"other","schema":`, 1))
		},
		"case": func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"core_source_commit":`, `"Core_Source_Commit":`, 1))
		},
		"unknown": func(b []byte) []byte {
			return append(append([]byte{}, b[:len(b)-1]...), []byte(`,"endpoint_override":"https://caller.invalid"}`)...)
		},
		"trailing": func(b []byte) []byte { return append(b, []byte(`{}`)...) },
		"oversize": func([]byte) []byte { return []byte(strings.Repeat(" ", (256<<10)+1)) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := nativeWorkerConfigDecode(change(append([]byte(nil), raw...)), c.CoreSourceCommit); err == nil {
				t.Fatal("unclosed configuration accepted")
			}
		})
	}
	if _, err := nativeWorkerConfigDecode(raw, strings.Repeat("d", 40)); err == nil {
		t.Fatal("expected Source substituted for compiled Source")
	}
	c.Profiles = append(c.Profiles, c.Profiles[0])
	if _, err := nativeWorkerConfigDecode(mustNativeJSON(t, wire(c)), c.CoreSourceCommit); err == nil {
		t.Fatal("duplicate profile accepted")
	}
	// No format traverses this private configuration, even through a value copy.
	c.Profiles[0].AgentTokenFile = "PRIVATE_MOUNT_REFERENCE"
	if strings.Contains(fmt.Sprintf("%+v %#v %s", c, c, mustNativeJSON(t, c)), "PRIVATE_MOUNT_REFERENCE") {
		t.Fatal("private configuration formatting escaped")
	}
}

func TestNativeRuntimeDrainKeepsOriginalHTTPCallbackAndDependencyOwnership(t *testing.T) {
	// A real in-runner HTTP callback qualifies shutdown ordering only. It is
	// not a provider/floor/guest authority or a production-network fixture.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("CI original callback"))
	}))
	defer server.Close()
	db := new(sql.DB)
	policy := model.Manifest{ID: uuid.New(), APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: "infra", Name: "workers", Active: true}, Version: 1, Checksum: strings.Repeat("a", 64), Spec: json.RawMessage(`{"fixture":"ownership-only"}`)}
	app := runtime.New("ci")
	var order []string
	o := &nativeWorkerRuntimeOwner{&nativeWorkerRuntimeOwnerState{db: db, policy: policy, poolReaderScopeSHA256: strings.Repeat("b", 64), closers: []func() error{
		func() error { order = append(order, "worker"); return nil }, func() error { order = append(order, "network"); return nil }, func() error { order = append(order, "abort"); return nil },
	}}}
	app.SetResource(nativeWorkerRuntimeResource, o)
	app.RegisterCloser(func(context.Context) error { order = append(order, "database"); return nil })
	app.RegisterCloser(func(context.Context) error { order = append(order, "broker"); return nil })
	originals, err := httpapi.NewOriginalWorkflowOwners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	app.RegisterCloser(func(ctx context.Context) error {
		return shutdownNativeOwnedHTTPServers(ctx, originals, o, []*http.Server{server.Config})
	})
	app.RegisterDrainer(o.Seal)
	app.RegisterDrainer(originals.Seal)
	entered, allowCallback := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(allowCallback) }) }
	defer release()
	returned := make(chan error, 1)
	go func() {
		returned <- nativeWorkerExecutionResolver(app)(context.Background(), db, policy, func(ctx context.Context, _ message.NativeWorkerExecutionScope) error {
			close(entered)
			<-allowCallback
			requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, server.URL+"/callback", nil)
			if err != nil {
				return err
			}
			response, err := server.Client().Do(req)
			if err != nil {
				return err
			}
			raw, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if err := errors.Join(readErr, closeErr, requestCtx.Err()); err != nil {
				return err
			}
			if response.StatusCode != 200 || string(raw) != "CI original callback" {
				return errors.New("CI callback mismatch")
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("borrow did not enter")
	}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	err = app.Shutdown(expired)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, runtime.ErrDependencyShutdownHeld) {
		t.Fatal("join timeout lost its original disposition")
	}
	if len(order) != 0 || o.closed {
		t.Fatal("timeout closed dependencies or marked owner closed")
	}
	// The SAME original borrower can still obtain its callback after the
	// failed join. No new borrow is admitted, no request is replayed.
	if err := nativeWorkerExecutionResolver(app)(context.Background(), db, policy, func(context.Context, message.NativeWorkerExecutionScope) error { return nil }); err == nil {
		t.Fatal("draining accepted new original")
	}
	release()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("original callback could not complete")
	}
	join, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := app.Shutdown(join); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"abort", "network", "worker", "broker", "database"}) {
		t.Fatalf("wrong successful dependency order: %v", order)
	}
}

func TestNativeRuntimeOwnerBorrowSealCloseAndCurrentResource(t *testing.T) {
	db := new(sql.DB)
	policy := model.Manifest{ID: uuid.New(), APIVersion: "v1", Kind: "capacity_policy", Metadata: model.ManifestMetadata{Namespace: "infra", Name: "workers", Active: true}, Version: 1, Checksum: strings.Repeat("a", 64), Spec: json.RawMessage(`{ "source" : "original" }`)}
	app := runtime.New("ci")
	resolve := nativeWorkerExecutionResolver(app)
	call := func(context.Context, message.NativeWorkerExecutionScope) error { return nil }
	if err := resolve(context.Background(), db, policy, call); err == nil {
		t.Fatal("pre-installation acquired owner")
	}
	var order []string
	sentinel := errors.New("CI close failure")
	o := &nativeWorkerRuntimeOwner{&nativeWorkerRuntimeOwnerState{db: db, policy: policy, poolReaderScopeSHA256: strings.Repeat("b", 64), mutations: map[string]*capacity.NativeWorkerRPCClient{"aws": nil}, closers: []func() error{
		func() error { order = append(order, "worker"); return nil }, func() error { order = append(order, "network"); return sentinel }, func() error { order = append(order, "abort"); return nil },
	}}}
	app.SetResource(nativeWorkerRuntimeResource, o)
	// This fixture exercises only the owner/borrow fence. It claims no real
	// factory, network, SDK, registry or useful-worker qualification.
	if err := resolve(context.Background(), db, policy, func(_ context.Context, s message.NativeWorkerExecutionScope) error {
		if s.PoolReaderScopeSHA256 != strings.Repeat("b", 64) {
			t.Fatal("private pool scope pin not forwarded")
		}
		s.PoolReaderScopeSHA256 = strings.Repeat("c", 64)
		delete(s.ProviderMutations, "aws")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.mutations["aws"]; !ok || o.poolReaderScopeSHA256 != strings.Repeat("b", 64) {
		t.Fatal("borrowed map changed owner")
	}
	if err := resolve(context.Background(), db, policy, func(ctx context.Context, _ message.NativeWorkerExecutionScope) error {
		if err := resolve(ctx, db, policy, call); err == nil {
			t.Fatal("recursive borrow accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*model.Manifest){"ID": func(p *model.Manifest) { p.ID = uuid.New() }, "version": func(p *model.Manifest) { p.Version++ }, "checksum": func(p *model.Manifest) { p.Checksum = strings.Repeat("b", 64) }, "raw JSONB": func(p *model.Manifest) { p.Spec = json.RawMessage(`{"source":"original"}`) }, "inactive": func(p *model.Manifest) { p.Metadata.Active = false }} {
		t.Run(name, func(t *testing.T) {
			p := policy
			mutate(&p)
			if err := resolve(context.Background(), db, p, call); err == nil {
				t.Fatal("policy substitution accepted")
			}
		})
	}
	if err := resolve(context.Background(), new(sql.DB), policy, call); err == nil {
		t.Fatal("different database accepted")
	}
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var borrowerFinished atomic.Bool
	go func() {
		returned <- resolve(context.Background(), db, policy, func(context.Context, message.NativeWorkerExecutionScope) error {
			close(entered)
			<-release
			borrowerFinished.Store(true)
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("borrow never entered")
	}
	sealReturned := make(chan struct{})
	go func() { o.Seal(); close(sealReturned) }()
	select {
	case <-sealReturned:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("drainer joined active borrower")
	}
	if err := resolve(context.Background(), db, policy, call); err == nil {
		close(release)
		t.Fatal("sealed owner accepted new borrower")
	}
	closed := make(chan error, 1)
	go func() { closed <- o.Close() }()
	select {
	case <-closed:
		close(release)
		t.Fatal("owner closed borrowed resources before callback returned")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-returned; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; !errors.Is(err, sentinel) {
		t.Fatal("close failure lost")
	}
	if !borrowerFinished.Load() || !reflect.DeepEqual(order, []string{"abort", "network", "worker"}) {
		t.Fatal("wrong owned close order")
	}
	if err := o.Close(); err != nil || len(order) != 3 {
		t.Fatal("Close was not idempotent")
	}
	if err := resolve(context.Background(), db, policy, call); err == nil {
		t.Fatal("closed owner adopted new work")
	}
	app.SetResource(nativeWorkerRuntimeResource, nil)
	if err := resolve(context.Background(), db, policy, call); err == nil {
		t.Fatal("missing current resource reused prior owner")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v %s", *o, *o, mustNativeJSON(t, *o)), policy.Checksum) {
		t.Fatal("owner value formatting escaped")
	}
}
