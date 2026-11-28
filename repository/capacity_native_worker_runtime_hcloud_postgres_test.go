package repository

import (
	"bytes"
	"context"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeConcreteHCloudRuntimeJoinsCommittedOriginalAndKeepsSealedWitness(t *testing.T) {
	f, store, provider, authority := nativeHCloudRepositoryFixture(t)
	ctx := t.Context()
	a, err := store.Reserve(ctx, f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := store.Redeem(ctx, f.policy, authority, a.ID)
	if err != nil || permit.AttemptID != a.ID || permit.LaunchSHA256 != a.LaunchSHA256 || permit.Capability != a.Execution.EnsureCapability {
		t.Fatal("actual one-send redemption refused", err)
	}
	a, err = store.Read(ctx, f.policy, a.ID)
	if err != nil || a.State != "send_started" {
		t.Fatal("actual stored send state unavailable", err)
	}
	original, err := provider.CaptureOriginalReturn(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	qualifier, err := capacity.NewNativeWorkerACKQualifier(f.p, func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, request model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		var count int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1 AND wire=$2`, a.ID, original.Wire).Scan(&count); err != nil || count != 1 {
			t.Fatal("concrete qualifier read before original custody", err)
		}
		return provider.read(a, b, request), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Only the qualification/archive ports are under test here. The separate
	// published-executable root constructs the real factory/runtime handle.
	// This state is not an installed runtime, factory, Node or readiness proof.
	runtime := &NativeWorkerConcreteRuntime{&nativeWorkerConcreteRuntimeState{db: f.db, policy: f.policy, spec: f.p, source: a.SourceCommit, physical: qualifier}}
	t.Cleanup(func() { _ = runtime.Close() })
	if _, err := runtime.Qualify(ctx, a, original); err == nil || provider.reads != 0 {
		t.Fatal("unarchived HCloud acceptance reached an independent read")
	}
	if _, _, err := persistNativeWorkerOriginal(ctx, f.db, a.ID, original); err != nil {
		t.Fatal(err)
	}
	qualified, err := runtime.Qualify(ctx, a, original)
	if err != nil || provider.reads != 1 || qualified.HCloudWitness == nil || qualified.IndependentCurrent.AccountID != "" || qualified.OriginalRequestID != "" || qualified.IndependentRequestID != "" || a.HCloudWitness != nil {
		t.Fatal("concrete HCloud qualification lost typed proof or invented account/request IDs", err)
	}
	if !capacity.NativeWorkerHCloudWitnessBindingValid(f.p, a, qualified.HCloudWitness) || capacity.NativeWorkerObservationValid(a, qualified, qualified.ObservedAt, f.p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds) != nil {
		t.Fatal("real qualifier output does not join the protected reader and original")
	}
	before := provider.reads
	changed := original
	changed.Wire = append(bytes.Clone(original.Wire), '\n')
	if _, err := runtime.Qualify(ctx, a, changed); err == nil || provider.reads != before {
		t.Fatal("different original bytes bypassed committed custody")
	}
	for _, change := range []func(*model.CapacityNativeWorkerAttempt){func(a *model.CapacityNativeWorkerAttempt) { a.Provider = "aws" }, func(a *model.CapacityNativeWorkerAttempt) { a.Provider = "hcloud" }, func(a *model.CapacityNativeWorkerAttempt) { a.Region = "eu-central" }, func(a *model.CapacityNativeWorkerAttempt) { a.LaunchSHA256 = "substituted" }} {
		other := a
		change(&other)
		if _, err := runtime.Qualify(ctx, other, original); err == nil || provider.reads != before {
			t.Fatal("substituted provider/region/launch reached the independent reader")
		}
	}
	// The existing real Record path seals its own typed original/read witness;
	// this test neither copies that proof into the database nor fabricates birth.
	a, err = store.Record(ctx, f.policy, authority, a.ID)
	if err != nil || a.State != "acknowledged" || a.Physical == nil || a.HCloudWitness == nil {
		t.Fatal("actual HCloud ledger did not seal its reviewed witness", err)
	}
	var eventsBefore int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_events WHERE attempt_id=$1`, a.ID).Scan(&eventsBefore); err != nil {
		t.Fatal(err)
	}
	physical, err := runtime.ReobserveACK(ctx, a)
	if err != nil || physical != *a.Physical {
		t.Fatal("concrete sealed HCloud reobservation changed its physical identity", err)
	}
	actual, err := store.Read(ctx, f.policy, a.ID)
	if err != nil || actual.State != a.State || actual.Revision != a.Revision || actual.HCloudWitness == nil || actual.HCloudWitness.EvidenceSHA256 != a.HCloudWitness.EvidenceSHA256 {
		t.Fatal("GET-only reobservation wrote lifecycle state or another witness", err)
	}
	var eventsAfter int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_native_worker_events WHERE attempt_id=$1`, a.ID).Scan(&eventsAfter); err != nil || eventsAfter != eventsBefore {
		t.Fatal("GET-only reobservation emitted a new transition or birth", err)
	}
}
