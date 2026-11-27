package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeBootstrapFactoryFunc func(context.Context, model.CapacityNativeWorkerAttempt, json.RawMessage, time.Time) ([]byte, error)

func (f nativeBootstrapFactoryFunc) RenderNativeWorkerPrivateBootstrap(c context.Context, a model.CapacityNativeWorkerAttempt, l json.RawMessage, e time.Time) ([]byte, error) {
	return f(c, a, l, e)
}

func TestNativeWorkerPrivateBootstrapIsPreflightOutsideSQLLocksPostgres(t *testing.T) {
	f, workers, r, authority := nativeAttemptFixture(t)
	runtime := &nativeCommandRuntime{nativeAttemptRuntime: r}
	workers.Runtime = runtime
	a, err := workers.Reserve(t.Context(), f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	f.db.SetMaxOpenConns(1)
	store := CapacityNativeWorkerCommandStore{Workers: workers}
	store.Workers.Capacity.ExecutorID, store.Workers.Capacity.WorkflowID = "", uuid.Nil
	policy, caller, err := store.Resolve(t.Context(), a.ID, a.Execution.BindingName, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, map[string]bool{a.Execution.EnsureCapability: true})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var raw []byte
	store.BootstrapFactory = nativeBootstrapFactoryFunc(func(ctx context.Context, own model.CapacityNativeWorkerAttempt, launch json.RawMessage, expiry time.Time) ([]byte, error) {
		calls.Add(1)
		var one int
		if err := f.db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			return nil, errors.New("factory retained the only SQL connection")
		}
		if own.ID != a.ID || own.Execution.ScopeSHA256 != a.Execution.ScopeSHA256 || len(launch) == 0 || !expiry.After(time.Now()) {
			return nil, errors.New("wrong private attempt")
		}
		raw = []byte("#cloud-config\nprivate-ci-agent-material\n")
		return raw, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	out, err := store.Bootstrap(ctx, policy, a.ID, caller)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if calls.Load() != 1 || runtime.captures.Load() != 0 {
		t.Fatal("bootstrap called a sender or original-return capture")
	}
	for _, b := range raw {
		if b != 0 {
			t.Fatal("factory output remained after private response serialization")
		}
	}
	var body bytes.Buffer
	if err = out.WritePrivateJSON(&body); err != nil {
		t.Fatal(err)
	}
	var wire struct {
		AttemptID uuid.UUID       `json:"attempt_id"`
		Launch    json.RawMessage `json:"public_launch_json"`
		CloudInit []byte          `json:"cloud_init_base64"`
	}
	if json.Unmarshal(body.Bytes(), &wire) != nil || wire.AttemptID != a.ID || !bytes.Contains(wire.CloudInit, []byte("private-ci-agent-material")) {
		t.Fatal("actor private bootstrap contract not delivered")
	}
	current, err := workers.Read(t.Context(), policy, a.ID)
	if err != nil || current.State != "reserved" || current.Revision != a.Revision {
		t.Fatal("bootstrap consumed or rewrote the one-send attempt")
	}
	grant, err := store.Redeem(t.Context(), policy, a.ID, caller)
	if err != nil || !grant.MutationPermitted || !bytes.Equal(grant.PublicLaunchJSON, wire.Launch) {
		t.Fatal("private preflight and actual later grant diverged", err)
	}
	if _, err = store.Bootstrap(t.Context(), policy, a.ID, caller); err == nil || calls.Load() != 1 {
		t.Fatal("consumed attempt reissued private launch")
	}
}

func TestNativeWorkerPrivateBootstrapRefusesStaleOrFailedPreflightPostgres(t *testing.T) {
	for _, mode := range []string{"missing-factory", "factory-error", "oversized", "wrong-prefix", "policy-closed", "redeemed-during-render", "cancelled", "substituted-caller"} {
		t.Run(mode, func(t *testing.T) {
			f, workers, _, authority := nativeAttemptFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			a, err := workers.Reserve(ctx, f.policy, authority)
			if err != nil {
				t.Fatal(err)
			}
			store := CapacityNativeWorkerCommandStore{Workers: workers}
			policy, caller, err := store.Resolve(ctx, a.ID, a.Execution.BindingName, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, map[string]bool{a.Execution.EnsureCapability: true})
			if err != nil {
				t.Fatal(err)
			}
			var calls int
			var retained []byte
			store.BootstrapFactory = nativeBootstrapFactoryFunc(func(ctx context.Context, _ model.CapacityNativeWorkerAttempt, _ json.RawMessage, _ time.Time) ([]byte, error) {
				calls++
				retained = []byte("#cloud-config\nprivate-refused-material\n")
				switch mode {
				case "factory-error":
					return retained, errors.New("private-fixture-error-must-not-escape")
				case "oversized":
					retained = append(retained, bytes.Repeat([]byte("x"), 16384)...)
				case "wrong-prefix":
					retained = []byte("caller-shell")
				case "policy-closed":
					_, e := f.db.ExecContext(ctx, "UPDATE public.manifests SET active=false WHERE id=$1", policy.ID)
					if e != nil {
						return retained, e
					}
				case "redeemed-during-render":
					if _, e := store.Redeem(ctx, policy, a.ID, caller); e != nil {
						return retained, e
					}
				case "cancelled":
					cancel()
				}
				return retained, nil
			})
			if mode == "missing-factory" {
				store.BootstrapFactory = nil
			}
			if mode == "substituted-caller" {
				caller.SDKSourceCommit = strings.Repeat("d", 40)
			}
			out, err := store.Bootstrap(ctx, policy, a.ID, caller)
			if err == nil || strings.Contains(err.Error(), "private-fixture") {
				out.Close()
				t.Fatal("invalid private response exposed material or succeeded", err)
			}
			if (mode == "missing-factory" || mode == "substituted-caller") && calls != 0 {
				t.Fatal("unauthorized factory invocation")
			}
			for _, b := range retained {
				if b != 0 {
					t.Fatal("refused private material retained")
				}
			}
		})
	}
}
