package repository

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeConcreteRuntimeArchiveAbsenceNeverBecomesAnEmptyOriginal(t *testing.T) {
	f, store, _, authority := nativeAttemptFixture(t)
	ctx := t.Context()
	a, err := store.Reserve(ctx, f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Redeem(ctx, f.policy, authority, a.ID); err != nil {
		t.Fatal(err)
	}
	a, err = store.Read(ctx, f.policy, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Only the archive projection is under test. The fixture's actual claim,
	// reservation and one-send ledger remain real PostgreSQL records; no
	// physical observer, factory or readiness proof is fabricated here.
	runtime := &NativeWorkerConcreteRuntime{&nativeWorkerConcreteRuntimeState{db: f.db, policy: f.policy, source: a.SourceCommit}}
	store.Runtime = runtime
	if _, err = store.Record(ctx, f.policy, authority, a.ID); !errors.Is(err, ErrCapacityNativeReturnPending) {
		t.Fatal("a missing archived return did not remain pending", err)
	}
	var originals int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1`, a.ID).Scan(&originals); err != nil || originals != 0 {
		t.Fatal("archive-only capture manufactured empty custody", originals, err)
	}
	current, err := store.Read(ctx, f.policy, a.ID)
	if err != nil || current.State != "send_started" || current.Revision != a.Revision {
		t.Fatal("pending custody changed the original charged send", current.State, err)
	}
	// A cancelled/failed archive read must use the same no-empty sentinel,
	// rather than triggering Store.original's external-capture error fallback.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if original, err := runtime.CaptureOriginalReturn(cancelled, a); !errors.Is(err, ErrCapacityNativeReturnPending) || len(original.Wire) != 0 || original.CaptureComplete {
		t.Fatal("cancelled archive read became a completed original", err)
	}
	foreign := a
	foreign.PolicyChecksum += "different"
	if original, err := runtime.CaptureOriginalReturn(ctx, foreign); !errors.Is(err, ErrCapacityNativeReturnPending) || len(original.Wire) != 0 || original.CaptureComplete {
		t.Fatal("unavailable archive evidence became a completed original", err)
	}
	if _, err = store.Redeem(ctx, f.policy, authority, a.ID); err == nil {
		t.Fatal("pending archive reopened the consumed provider permit")
	}
	// Even a real retained zero-byte incomplete row is not an original
	// response that this archive-only port may present as captured wire.
	if _, _, err = persistNativeWorkerOriginal(ctx, f.db, a.ID, model.CapacityNativeWorkerOriginalReturn{Wire: []byte{}, CaptureComplete: false, ErrorClass: "ORIGINAL_TRANSPORT_UNCERTAIN"}); err != nil {
		t.Fatal(err)
	}
	if original, err := runtime.CaptureOriginalReturn(ctx, a); !errors.Is(err, ErrCapacityNativeReturnPending) || len(original.Wire) != 0 || original.CaptureComplete {
		t.Fatal("empty retained prefix became a captured original response", err)
	}
}

func TestNativeConcreteRuntimeReadsOnlyCommittedOriginalBytesAndKeepsDatabaseOwnedByCaller(t *testing.T) {
	f, store, _, authority := nativeAttemptFixture(t)
	ctx := t.Context()
	a, err := store.Reserve(ctx, f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Redeem(ctx, f.policy, authority, a.ID); err != nil {
		t.Fatal(err)
	}
	a, err = store.Read(ctx, f.policy, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	original := model.CapacityNativeWorkerOriginalReturn{Wire: []byte("private original incomplete provider bytes"), CaptureComplete: false, ErrorClass: "ORIGINAL_TRANSPORT_UNCERTAIN"}
	if _, _, err = persistNativeWorkerOriginal(ctx, f.db, a.ID, original); err != nil {
		t.Fatal(err)
	}
	runtime := &NativeWorkerConcreteRuntime{&nativeWorkerConcreteRuntimeState{db: f.db, policy: f.policy, source: a.SourceCommit}}
	got, err := runtime.CaptureOriginalReturn(ctx, a)
	if err != nil || !bytes.Equal(got.Wire, original.Wire) || got.CaptureComplete || got.ErrorClass != original.ErrorClass {
		t.Fatal("committed original custody was interpreted or changed", err)
	}
	got.Wire[0] = '!'
	again, err := runtime.CaptureOriginalReturn(ctx, a)
	if err != nil || !bytes.Equal(again.Wire, original.Wire) {
		t.Fatal("caller mutation reached immutable archive bytes", err)
	}
	if _, err = runtime.Qualify(ctx, a, original); err == nil {
		t.Fatal("the explicit AWS-only runtime qualified the HCloud fixture")
	}
	forged := a
	forged.Provider = "aws"
	if _, err = runtime.Qualify(ctx, forged, original); err == nil {
		t.Fatal("a forged provider bypassed the exact stored Attempt join")
	}
	if out, err := runtime.ObserveAuthority(ctx, f.policy); err == nil || out != nil {
		t.Fatal("header-only runtime fabricated a useful/zero-member pool")
	}
	copy := *runtime
	if err = copy.Close(); err != nil || runtime.SourceCommit() != "" || runtime.BoundToDatabase(f.db) {
		t.Fatal("copied runtime did not share the Close fence", err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal("Close was not idempotent", err)
	}
	if err = f.db.PingContext(ctx); err != nil {
		t.Fatal("runtime closed its caller-owned database", err)
	}
	if _, err = runtime.CaptureOriginalReturn(ctx, a); !errors.Is(err, ErrCapacityNativeReturnPending) {
		t.Fatal("closed runtime enabled Store.original's empty capture fallback", err)
	}
}
