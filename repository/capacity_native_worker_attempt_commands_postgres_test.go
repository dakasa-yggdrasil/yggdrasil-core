package repository

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type nativeCommandRuntime struct {
	*nativeAttemptRuntime
	captures atomic.Int32
}

func (r *nativeCommandRuntime) CaptureOriginalReturn(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	r.captures.Add(1)
	return model.CapacityNativeWorkerOriginalReturn{}, ErrCapacityNativeReturnPending
}

func TestNativeWorkerAttemptCommandOriginalCustodyPostgres(t *testing.T) {
	f, workers, r, authority := nativeAttemptFixture(t)
	runtime := &nativeCommandRuntime{nativeAttemptRuntime: r}
	workers.Runtime = runtime
	store := CapacityNativeWorkerCommandStore{Workers: workers}
	ctx := t.Context()
	a, err := workers.Reserve(ctx, f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	// The HTTP composition knows neither controller identity. Only the private
	// context committed by Reserve may restore these for an actual redemption.
	store.Workers.Capacity.ExecutorID, store.Workers.Capacity.WorkflowID = "", uuid.Nil
	caps := map[string]bool{a.Execution.EnsureCapability: true}
	if !store.MachineAuthorized(ctx, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, caps) || store.MachineAuthorized(ctx, uuid.NewString(), a.Execution.SDKSourceCommit, caps) || store.MachineAuthorized(ctx, a.Execution.Adapter.ManifestID, strings.Repeat("d", 40), caps) || store.MachineAuthorized(ctx, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, map[string]bool{"destroy_server": true}) {
		t.Fatal("prebody machine scope did not require actual immutable Native context")
	}
	policy, caller, err := store.Resolve(ctx, a.ID, a.Execution.BindingName, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, caps)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []model.CapacityNativeWorkerCommandCaller{{BindingName: caller.BindingName, InstanceID: uuid.NewString(), SDKSourceCommit: caller.SDKSourceCommit, Capability: caller.Capability}, {BindingName: caller.BindingName, InstanceID: caller.InstanceID, SDKSourceCommit: strings.Repeat("d", 40), Capability: caller.Capability}, {BindingName: caller.BindingName, InstanceID: caller.InstanceID, SDKSourceCommit: caller.SDKSourceCommit, Capability: "destroy_server"}} {
		if _, err = store.Read(ctx, policy, a.ID, bad); err == nil {
			t.Fatal("substituted machine scope read private context")
		}
	}
	read, err := store.Read(ctx, policy, a.ID, caller)
	if err != nil || !read.Redeemable || read.MutationPermitted || read.Execution != nil || len(read.PublicLaunchJSON) != 0 || read.ExecutionScopeSHA256 != a.Execution.ScopeSHA256 {
		t.Fatal("Read leaked original permit or failed exact scope", read, err)
	}
	var command []byte
	if err = f.db.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&command); err != nil || !strings.Contains(string(command), workers.Capacity.ExecutorID) || !strings.Contains(string(command), workers.Capacity.WorkflowID.String()) {
		t.Fatal("Reserve lost private controller authority", err)
	}
	public, _ := json.Marshal(a)
	readWire, _ := json.Marshal(read)
	for _, private := range []string{workers.Capacity.ExecutorID, workers.Capacity.WorkflowID.String()} {
		if strings.Contains(string(public), private) || strings.Contains(string(readWire), private) {
			t.Fatal("private controller identity entered public Attempt/read")
		}
	}
	if _, err = f.db.ExecContext(ctx, `UPDATE public.capacity_native_worker_command_contexts SET record=record WHERE attempt_id=$1`, a.ID); err == nil {
		t.Fatal("private command context changed after Reserve")
	}
	if _, err = f.db.ExecContext(ctx, `DELETE FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID); err == nil {
		t.Fatal("immutable command history erased")
	}
	// No original may be accepted before send_started commits.
	receipt := model.CapacityNativeWorkerCommandReceive{AttemptID: a.ID, BindingName: caller.BindingName, OriginalReturn: []byte(`{"provider":"original","root_password":"private-ci-no-public-hash"}`), CaptureComplete: true}
	if err = store.Receive(ctx, policy, caller, receipt); err == nil {
		t.Fatal("unsent original was archived as a consumed command")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			grant, e := store.Redeem(ctx, policy, a.ID, caller)
			if e == nil {
				if !grant.MutationPermitted || grant.Redeemable || len(grant.PublicLaunchJSON) == 0 || grant.Execution == nil || grant.ExecutionScopeSHA256 != a.Execution.ScopeSHA256 {
					t.Error("invalid private original permit")
				}
				wins.Add(1)
			} else if grant.MutationPermitted || len(grant.PublicLaunchJSON) != 0 {
				t.Error("failed/unknown redemption returned a possible send grant")
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("not exactly one committed creator grant", wins.Load())
	}
	read, err = store.Read(ctx, policy, a.ID, caller)
	if err != nil || read.Redeemable || read.MutationPermitted || len(read.PublicLaunchJSON) != 0 {
		t.Fatal("consumed command returned a second permit", read, err)
	}
	r.failSDK.Store(true)
	if err = store.Receive(ctx, policy, caller, receipt); err != nil {
		t.Fatal("SDK failure discarded already committed private custody", err)
	}
	got, err := workers.Read(ctx, policy, a.ID)
	if err != nil || got.State != "unknown" || runtime.captures.Load() != 0 {
		t.Fatal("raw callback was repulled or SDK failure invented ACK", got.State, err)
	}
	// The exact original remains receivable after its lease and policy close.
	var parent model.CapacityIntent
	if err = f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, policy.Metadata.Namespace).Scan((*nativeIntentScan)(&parent)); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Second)
	parent.LeaseExpiresAt = &expired
	raw, _ := json.Marshal(parent)
	if _, err = f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2 WHERE namespace=$1`, policy.Metadata.Namespace, raw); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, policy.ID); err != nil {
		t.Fatal(err)
	}
	r.failSDK.Store(false)
	if err = store.Receive(ctx, policy, caller, receipt); err != nil {
		t.Fatal("late original custody was refused", err)
	}
	got, err = workers.Read(ctx, policy, a.ID)
	if err != nil || got.State != "acknowledged" || got.BirthSHA256 == "" || runtime.captures.Load() != 0 {
		t.Fatal("late independent ACK truth was lost", got, err)
	}
	if _, err = store.Redeem(ctx, policy, a.ID, caller); err == nil {
		t.Fatal("expired consumed command authorized another create")
	}
	bad := receipt
	bad.OriginalReturn = []byte(`{"replacement":true}`)
	if err = store.Receive(ctx, policy, caller, bad); err == nil {
		t.Fatal("duplicate callback replaced immutable original")
	}
	rawSHA := ""
	var retained []byte
	if err = f.db.QueryRowContext(ctx, `SELECT wire,raw_sha256 FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1`, a.ID).Scan(&retained, &rawSHA); err != nil || string(retained) != string(receipt.OriginalReturn) {
		t.Fatal("private original changed", err)
	}
	public, _ = json.Marshal(got)
	read, err = store.Read(ctx, policy, a.ID, caller)
	if err != nil {
		t.Fatal(err)
	}
	readWire, _ = json.Marshal(read)
	for _, private := range []string{"private-ci-no-public-hash", rawSHA, workers.Capacity.ExecutorID, workers.Capacity.WorkflowID.String()} {
		if strings.Contains(string(public), private) || strings.Contains(string(readWire), private) {
			t.Fatal("private original/controller identity entered public projection")
		}
	}
}

func TestNativeWorkerAttemptCommandOriginalDeadlinePostgres(t *testing.T) {
	f, workers, _, authority := nativeAttemptFixture(t)
	ctx := t.Context()
	var parent model.CapacityIntent
	if err := f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan((*nativeIntentScan)(&parent)); err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(2 * time.Second)
	parent.LeaseExpiresAt = &soon
	wire, _ := json.Marshal(parent)
	if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2 WHERE namespace=$1`, f.policy.Metadata.Namespace, wire); err != nil {
		t.Fatal(err)
	}
	a, err := workers.Reserve(ctx, f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	store := CapacityNativeWorkerCommandStore{Workers: workers}
	_, caller, err := store.Resolve(ctx, a.ID, a.Execution.BindingName, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, map[string]bool{a.Execution.EnsureCapability: true})
	if err != nil {
		t.Fatal(err)
	}
	read, err := store.Read(ctx, f.policy, a.ID, caller)
	if err != nil || !read.Redeemable {
		t.Fatal("fresh original command unavailable", err)
	}
	if err = workers.Renew(ctx, f.policy, authority); err != nil {
		t.Fatal(err)
	}
	// Renewing progress does not extend an original one-send command deadline.
	timer := time.NewTimer(time.Until(read.ExpiresAt.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if _, err = store.Redeem(ctx, f.policy, a.ID, caller); err == nil {
		t.Fatal("progress renewal silently renewed original create authority")
	}
	a, err = workers.Read(ctx, f.policy, a.ID)
	if err != nil || a.State != "reserved" {
		t.Fatal("expired unsent command inferred a send or released its reservation", a.State, err)
	}
}
