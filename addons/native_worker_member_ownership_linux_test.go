//go:build linux && native_readiness_ownership

package addons

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
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

var errNativeMemberOwnershipUnused = errors.New("unused member ownership fixture route")

type nativeMemberOwnershipBackend struct {
	entered, left chan struct{}
	release       <-chan struct{}
	seen          chan httpapi.NativeWorkerSchedulerBinding
	enter, leave  sync.Once
	calls         atomic.Int32
}

func (*nativeMemberOwnershipBackend) Read(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error) {
	return model.CapacityNativeWorkerMemberRead{}, errNativeMemberOwnershipUnused
}
func (*nativeMemberOwnershipBackend) ReadAllocatorFence(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerAllocatorFenceRead, error) {
	return model.CapacityNativeWorkerAllocatorFenceRead{}, errNativeMemberOwnershipUnused
}
func (*nativeMemberOwnershipBackend) Redeem(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberPermit, error) {
	return model.CapacityNativeWorkerMemberPermit{}, errNativeMemberOwnershipUnused
}
func (*nativeMemberOwnershipBackend) Receive(context.Context, model.CapacityNativeWorkerMemberReceive) error {
	return errNativeMemberOwnershipUnused
}
func (*nativeMemberOwnershipBackend) ReceiveRead(context.Context, model.CapacityNativeWorkerMemberReadOriginal) error {
	return errNativeMemberOwnershipUnused
}
func (*nativeMemberOwnershipBackend) Reconcile(context.Context, model.CapacityNativeWorkerMemberSelectors) (model.CapacityNativeWorkerMemberRead, error) {
	return model.CapacityNativeWorkerMemberRead{}, errNativeMemberOwnershipUnused
}
func (b *nativeMemberOwnershipBackend) Bind(_ context.Context, in httpapi.NativeWorkerSchedulerBinding) error {
	b.calls.Add(1)
	b.enter.Do(func() {
		b.seen <- in
		close(b.entered)
	})
	if b.release != nil {
		// This original user deliberately ignores cancellation. A forced
		// connection close is not proof the callback released dependencies.
		<-b.release
	}
	b.leave.Do(func() { close(b.left) })
	return nil
}

type nativeMemberOwnershipTLS struct {
	listener *httpapi.NativeWorkerMemberListener
	backend  *nativeMemberOwnershipBackend
	client   *http.Client
	release  func()
}

func nativeMemberOwnershipFixture(t *testing.T, blocked bool) nativeMemberOwnershipTLS {
	t.Helper()
	// Reuse only real TLS material and the clean compiled Source. The original
	// probe listener receives no requests and is not relabelled as a member.
	material := nativeReadinessOwnershipFixture(t, false)
	c := material.backend.config
	c.BindingName = "member-stock-owner-ci"
	c.SDKSourceCommit, c.SDKScopeSHA256, c.BearerTokenSHA256 = "", "", ""
	b := &nativeMemberOwnershipBackend{entered: make(chan struct{}), left: make(chan struct{}), seen: make(chan httpapi.NativeWorkerSchedulerBinding, 1)}
	release := make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	if blocked {
		b.release = release
	}
	// The profile declaration is synthetic protected CI input, not an
	// installer attestation or a claim that a stock scheduler is running.
	l, err := httpapi.NewNativeWorkerMemberListener(httpapi.NativeWorkerMemberListenerConfig{Role: "stock_scheduler", Transport: c, StockProfileSourceCommit: c.CoreSourceCommit, StockProfileSHA256: strings.Repeat("d", 64)}, b)
	if err != nil {
		t.Fatal("public clean-Source member constructor refused real TLS material", err)
	}
	t.Cleanup(func() {
		finish()
		if b.calls.Load() != 0 {
			select {
			case <-b.left:
			case <-time.After(2 * time.Second):
				t.Error("original member callback did not leave after release")
			}
		}
		_ = l.Close() // An original forced-close error remains sticky.
	})
	startup, cancel := context.WithCancel(t.Context())
	if err := l.Start(startup); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel() // Binding cancellation must not cancel the receiving lifetime.
	return nativeMemberOwnershipTLS{l, b, material.client, finish}
}

func (f nativeMemberOwnershipTLS) request(ctx context.Context) (*http.Response, error) {
	// Exact upstream ExtenderBindingArgs has no tags and therefore sends these
	// PascalCase fields. Do not derive the sole positive from our own mirror.
	raw, err := json.Marshal(struct{ PodName, PodNamespace, PodUID, Node string }{"nw-ci-member-pod", "ci-members", "12345678-1234-4234-8234-123456789abc", "nw-ci-member-node"})
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+f.listener.Address()+"/internal/capacity/native-workers/native-scheduler/bind", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	r.GetBody = nil
	r.Header.Set("Content-Type", "application/json")
	// Stock has no SDK Source/scope headers or writer bearer.
	return f.client.Do(r)
}

func TestNativeMemberOwnershipBlockedTLSRetainsRollbackAndLowerDependencies(t *testing.T) {
	f := nativeMemberOwnershipFixture(t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		r, err := f.request(ctx)
		if r != nil {
			_, readErr := io.Copy(io.Discard, r.Body)
			err = errors.Join(err, readErr, r.Body.Close())
		}
		returned <- err
	}()
	select {
	case <-f.backend.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual stock mTLS request did not reach the member callback")
	}
	in := <-f.backend.seen
	if in.PodName != "nw-ci-member-pod" || in.PodNamespace != "ci-members" || in.PodUID != "12345678-1234-4234-8234-123456789abc" || in.Node != "nw-ci-member-node" || f.backend.calls.Load() != 1 {
		t.Fatal("official stock fields changed or callback was replayed")
	}
	// This is the real lifecycle seam with a real receiving user, not the
	// complete file/DB/runtime constructor. Lower resources are explicit spies.
	member := &nativeWorkerMemberOwner{listeners: []*httpapi.NativeWorkerMemberListener{f.listener}}
	startup := errors.New("CI member installation failure after listener start")
	retainedMember, err := member.rollbackConstruction(startup)
	if retainedMember != member || !errors.Is(err, startup) || !errors.Is(err, runtime.ErrDependencyShutdownHeld) || member.closed || len(member.listeners) != 1 {
		t.Fatal("member rollback dropped opaque held ownership or claimed joined", err)
	}
	var workers, database, broker atomic.Int32
	o := &nativeWorkerRuntimeOwner{&nativeWorkerRuntimeOwnerState{members: retainedMember, closers: []func() error{func() error { workers.Add(1); return nil }, retainedMember.Close}}}
	retained, outerErr := o.rollbackConstruction(err)
	if retained != o || !errors.Is(outerErr, startup) || !errors.Is(outerErr, runtime.ErrDependencyShutdownHeld) || workers.Load() != 0 || len(o.closers) != 2 {
		t.Fatal("outer rollback closed Workers or lost held member owner", outerErr)
	}
	app := runtime.New("CI member retained rollback")
	app.RegisterCloser(func(context.Context) error { database.Add(1); return nil })
	app.RegisterCloser(func(context.Context) error { broker.Add(1); return nil })
	err = rollbackNativeWorkerRuntimeInstallation(app, retained, outerErr)
	if !errors.Is(err, startup) || !errors.Is(err, runtime.ErrDependencyShutdownHeld) {
		t.Fatal("actual HTTP startup rollback helper discarded member hold", err)
	}
	for range 2 {
		if err := app.Shutdown(context.Background()); !errors.Is(err, runtime.ErrDependencyShutdownHeld) || workers.Load() != 0 || database.Load() != 0 || broker.Load() != 0 {
			t.Fatal("held member receiving closed borrowed lower resources", err)
		}
	}
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("force-closed original request became a successful Bind receipt")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("force-closed member HTTP connection did not return")
	}
	select {
	case <-f.backend.left:
		t.Fatal("original callback joined without its explicit release")
	default:
	}
	f.release()
	select {
	case <-f.backend.left:
	case <-time.After(2 * time.Second):
		t.Fatal("released original callback did not leave")
	}
	alias := *f.listener
	if alias.Close() == nil || !errors.Is(member.Close(), runtime.ErrDependencyShutdownHeld) || !errors.Is(o.Close(), runtime.ErrDependencyShutdownHeld) || member.closed || workers.Load() != 0 || database.Load() != 0 || broker.Load() != 0 || f.backend.calls.Load() != 1 {
		t.Fatal("late join erased original held ownership, retried Bind or closed dependencies")
	}
}

func TestNativeMemberOwnershipJoinedTLSClosesBeforeWorkersAndLegacySecondClose(t *testing.T) {
	f := nativeMemberOwnershipFixture(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	r, err := f.request(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(r.Body, 2049))
	closeErr := r.Body.Close()
	var out map[string]string
	sources := r.Header.Values("X-Yggdrasil-Source-Commit")
	if errors.Join(readErr, closeErr) != nil || r.StatusCode != http.StatusOK || len(raw) > 2048 || len(sources) != 1 || sources[0] != capacity.CurrentGuestCoreSource() || r.Header.Get("Cache-Control") != "no-store" || json.Unmarshal(raw, &out) != nil || len(out) != 1 || out["Error"] != "" {
		t.Fatal("actual member callback did not return the official Source-bound result")
	}
	if _, ok := out["Error"]; !ok || f.backend.calls.Load() != 1 {
		t.Fatal("official Error field missing or callback retried")
	}
	member := &nativeWorkerMemberOwner{listeners: []*httpapi.NativeWorkerMemberListener{f.listener}}
	address := f.listener.Address()
	var order []string
	sentinel := errors.New("ordinary CI Workers close error")
	o := &nativeWorkerRuntimeOwner{&nativeWorkerRuntimeOwnerState{members: member, closers: []func() error{
		func() error {
			if !member.closed {
				t.Error("Workers closed before member receiving joined")
			}
			// Probe only the TCP listener after Close; never resend Bind to
			// discover whether an earlier uncertain mutation completed.
			if conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond); err == nil {
				_ = conn.Close()
				t.Error("member listener was still accepting after successful join")
			}
			order = append(order, "workers")
			return sentinel
		},
		func() error {
			err := member.Close()
			order = append(order, "member")
			return err
		},
	}}}
	app := runtime.New("CI member joined dependencies")
	app.RegisterCloser(func(context.Context) error { order = append(order, "database"); return nil })
	app.RegisterCloser(func(context.Context) error { order = append(order, "broker"); return nil })
	app.RegisterCloser(func(context.Context) error { return o.Close() })
	if err := app.Shutdown(context.Background()); !errors.Is(err, sentinel) || errors.Is(err, runtime.ErrDependencyShutdownHeld) || !reflect.DeepEqual(order, []string{"member", "workers", "broker", "database"}) {
		t.Fatal("joined member changed LIFO or hid the ordinary lower error", err)
	}
	if err := o.Close(); err != nil || len(order) != 4 || member.Close() != nil || f.backend.calls.Load() != 1 {
		t.Fatal("normal second Close repeated an effect/closer or changed legacy semantics", err)
	}
}
