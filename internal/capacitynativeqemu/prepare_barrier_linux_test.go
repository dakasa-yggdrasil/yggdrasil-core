//go:build linux && nativequalification

package capacitynativeqemu

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Done is observed only when Await reaches its missing-file select. It does
// not change cancellation, deadlines or Err; no timing sleep orders publication.
type prepareBarrierContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *prepareBarrierContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func prepareBarrierFixture(t *testing.T) (*Realm, string, func()) {
	t.Helper()
	private := t.TempDir()
	guest := t.TempDir()
	t.Setenv("GUEST_NATIVE_SOURCE_ROOT", guest)
	dir := SlotDirectory(private, 1)
	for _, path := range []string{dir, filepath.Join(dir, "source-bundle"), filepath.Join(guest, "docs", "systemd")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	r := &Realm{PrivateDirectory: private, Request: SourceRequest{
		NativeCase: "positive_original_lifecycle", CreatorSourceSHA256: digest([]byte("creator")),
		OriginalContextDeadline: time.Now().UTC().Add(time.Minute),
		Slots:                   []SlotRequest{{Slot: 1, ResourceID: "original-resource"}},
	}, started: map[int]bool{}, prepared: map[int]PreCreateRequest{}}
	r.Profile.BootstrapSHA256 = digest([]byte("bootstrap"))
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	publish := func() {
		for _, unit := range []string{"yggdrasil-guest-retirement.service", "yggdrasil-guest-protected-runtime-owner.service"} {
			original := []byte("[Unit]\nDescription=fixture\n[Service]\nExecStart=/bin/true\n")
			write(filepath.Join(guest, "docs", "systemd", unit), original)
			approved := bytes.Replace(original, []byte("[Service]\n"), []byte("[Service]\nEnvironment=GUEST_ORIGINAL_NATIVE_CASE=positive_original_lifecycle\n"), 1)
			write(filepath.Join(dir, "source-bundle", unit), approved)
		}
		stage, iso, bootstrap := []byte("stage"), []byte("iso"), []byte("bootstrap")
		write(filepath.Join(dir, "source-config-ready.json"), stage)
		write(filepath.Join(dir, "source.iso"), iso)
		write(filepath.Join(dir, "user-data"), bootstrap)
		write(filepath.Join(dir, "original.qcow2"), []byte("owned-disk"))
		pre := PreCreateRequest{Schema: FixtureSchema, Stage: "pre-create-request.json", NativeCase: r.Request.NativeCase,
			Slot: 1, ResourceID: r.Request.Slots[0].ResourceID, CreatorSourceSHA256: r.Request.CreatorSourceSHA256,
			OriginalContextDeadline: r.Request.OriginalContextDeadline, OriginalProvisioningBudgetSeconds: 420,
			SourceConfigStageSHA256: digest(stage), SourceISOSHA256: digest(iso), BootstrapSHA256: digest(bootstrap)}
		raw, err := json.Marshal(pre)
		if err != nil {
			t.Fatal(err)
		}
		// The final barrier is published only after all body writes are closed.
		if _, err := PublishBytes(context.Background(), filepath.Join(dir, "pre-create-request.json"), raw); err != nil {
			t.Fatal(err)
		}
	}
	return r, dir, publish
}

func TestOriginalPrepareWaitsForPreCreateBeforeSourceReads(t *testing.T) {
	r, _, publish := prepareBarrierFixture(t)
	base, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx := &prepareBarrierContext{Context: base, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- r.Prepare(ctx, 1) }()
	select {
	case err := <-result:
		t.Fatalf("Prepare returned before producer barrier: %v", err)
	case <-ctx.waiting:
	case <-base.Done():
		t.Fatal("Prepare never reached barrier")
	}
	publish()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-base.Done():
		t.Fatal("Prepare did not finish after publication")
	}
	if _, ok := r.prepared[1]; !ok {
		t.Fatal("preparation not retained")
	}
	if _, ok := r.disks[1]; !ok {
		t.Fatal("owned disk identity not retained")
	}
}

func TestOriginalPrepareBarrierPreservesNegativeChecks(t *testing.T) {
	for _, name := range []string{"unit", "iso", "prehash", "expired-context"} {
		t.Run(name, func(t *testing.T) {
			r, dir, publish := prepareBarrierFixture(t)
			publish()
			ctx := context.Background()
			switch name {
			case "unit":
				if err := os.WriteFile(filepath.Join(dir, "source-bundle", "yggdrasil-guest-retirement.service"), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "iso":
				if err := os.WriteFile(filepath.Join(dir, "source.iso"), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "prehash":
				path := filepath.Join(dir, "pre-create-request.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var pre PreCreateRequest
				if err = json.Unmarshal(raw, &pre); err != nil {
					t.Fatal(err)
				}
				pre.BootstrapSHA256 = digest([]byte("foreign"))
				raw, err = json.Marshal(pre)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "expired-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			if err := r.Prepare(ctx, 1); err == nil {
				t.Fatal("invalid preparation accepted")
			}
			if len(r.prepared) != 0 || len(r.disks) != 0 {
				t.Fatal("invalid preparation retained")
			}
		})
	}
}
