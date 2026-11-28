package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeWorkerExecutionConcurrentResumeAndOneRPCBarrierPostgres(t *testing.T) {
	f, workers, _, authority := nativeAttemptFixture(t)
	session, err := workers.OpenNativeExecution(t.Context(), f.policy, workers.Capacity.WorkflowID)
	if err != nil {
		t.Fatal("original Claim not usable", err)
	}
	const callers = 8
	ids := make(chan uuid.UUID, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, e := session.Next(t.Context())
			if e != nil {
				errs <- e
				return
			}
			ids <- a.ID
		}()
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		t.Fatal("concurrent current-child lookup", err)
	}
	id := uuid.Nil
	for got := range ids {
		if id == uuid.Nil {
			id = got
		}
		if got != id {
			t.Fatal("retry allocated another attempt")
		}
	}
	var attempts, commands int
	if err = f.store.DB.QueryRowContext(t.Context(), `SELECT count(*),count(c.attempt_id) FROM public.capacity_native_worker_attempts a LEFT JOIN public.capacity_native_worker_command_contexts c ON c.attempt_id=a.id WHERE a.policy_id=$1`, f.policy.ID).Scan(&attempts, &commands); err != nil || attempts != 1 || commands != 1 {
		t.Fatal("lookup/reserve not atomic", attempts, commands, err)
	}
	var calls atomic.Int32
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			won, e := session.ClaimDispatch(t.Context(), id, "provider_create", id)
			if e != nil {
				t.Error("dispatch barrier", e)
				return
			}
			if won {
				calls.Add(1)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent execution emitted multiple SDK RPCs", calls.Load())
	}
	// Model crash immediately after the barrier commit, before the RPC. Neither
	// a fresh invocation ID nor a restart turns this uncertainty into a resend.
	restarted := workers
	restarted.Capacity.ExecutorID = uuid.NewString()
	resumed, err := restarted.OpenNativeExecution(t.Context(), f.policy, workers.Capacity.WorkflowID)
	if err != nil {
		t.Fatal("durable114 identity not restored", err)
	}
	a, err := resumed.Next(t.Context())
	if err != nil || a.ID != id || a.State != "reserved" {
		t.Fatal("crash-before-RPC fabricated send state", a.State, err)
	}
	won, err := resumed.ClaimDispatch(t.Context(), id, "provider_create", id)
	if err != nil || won {
		t.Fatal("uncertain original dispatch replayed", err)
	}
	permit, err := workers.Redeem(t.Context(), f.policy, authority, id)
	if err != nil || !permit.MutationPermitted {
		t.Fatal("original SDK redemption failed", err)
	}
	if _, err = workers.Record(t.Context(), f.policy, authority, id); err != nil {
		t.Fatal("original SDK callback failed", err)
	}
	a, err = resumed.Next(t.Context())
	if err != nil || a.ID != id || a.State != "acknowledged" {
		t.Fatal("callback/retry reserved again", a.State, err)
	}
	won, err = resumed.ClaimDispatch(t.Context(), id, "provider_create", id)
	if err != nil || won || calls.Load() != 1 {
		t.Fatal("post-callback RPC replayed", err)
	}
	if _, err = resumed.Complete(t.Context()); err == nil {
		t.Fatal("ACK or phase observation promoted parent without useful capacity")
	}
}

func TestNativeWorkerExecutionAuthorityAndDispatchCustodyPostgres(t *testing.T) {
	f, workers, _, _ := nativeAttemptFixture(t)
	// A new invocation cannot adopt a claimed parent before any114 command
	// exists. This is deliberately HOLD after that narrow crash boundary.
	other := workers
	other.Capacity.ExecutorID = uuid.NewString()
	if _, err := other.OpenNativeExecution(t.Context(), f.policy, workers.Capacity.WorkflowID); err == nil {
		t.Fatal("adopted claim without private original command")
	}
	session, err := workers.OpenNativeExecution(t.Context(), f.policy, workers.Capacity.WorkflowID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = session.Pending(t.Context()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("admission-only lookup allocated", err)
	}
	a, err := session.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if won, err := session.ClaimDispatch(t.Context(), a.ID, "provider_create", uuid.New()); err == nil || won {
		t.Fatal("foreign target authorized")
	}
	if won, err := session.ClaimDispatch(t.Context(), a.ID, "destroy", a.ID); err == nil || won {
		t.Fatal("unclosed operation authorized")
	}
	if _, err = workers.OpenNativeExecution(t.Context(), f.policy, uuid.New()); err == nil {
		t.Fatal("workflow identity replaced")
	}
	if won, err := session.ClaimDispatch(t.Context(), a.ID, "provider_create", a.ID); err != nil || !won {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE public.capacity_native_worker_execution_dispatches SET source_commit=repeat('b',40) WHERE attempt_id=$1`,
		`DELETE FROM public.capacity_native_worker_execution_dispatches WHERE attempt_id=$1`,
	} {
		if _, err = f.store.DB.ExecContext(t.Context(), query, a.ID); err == nil {
			t.Fatal("dispatch custody could be altered or discarded")
		}
	}
	var snapshot []byte
	if err = f.store.DB.QueryRowContext(t.Context(), `SELECT snapshot FROM public.capacity_native_worker_execution_dispatches WHERE attempt_id=$1`, a.ID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	var retained model.CapacityNativeWorkerAttempt
	if json.Unmarshal(snapshot, &retained) != nil || retained.ID != a.ID || retained.Generation != a.Generation || retained.FencingToken != a.FencingToken || retained.SourceCommit != a.SourceCommit || retained.State != "reserved" {
		t.Fatal("dispatch did not retain exact original authority")
	}
	wire, err := json.Marshal(session)
	if err != nil || strings.Contains(string(wire), workers.Capacity.ExecutorID) || strings.Contains(string(wire), "lease_owner") {
		t.Fatal("session leaked private controller authority")
	}
}

func TestNativeWorkerExecutionExpiredParentOnlyReceivesOriginalPostgres(t *testing.T) {
	f, workers, r, authority := nativeAttemptFixture(t)
	session, err := workers.OpenNativeExecution(t.Context(), f.policy, workers.Capacity.WorkflowID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := session.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = workers.Redeem(t.Context(), f.policy, authority, a.ID); err != nil {
		t.Fatal(err)
	}
	r.pending.Store(true)
	if err = workers.ReceiveNativeExecution(t.Context(), f.policy); err != nil {
		t.Fatal("pending capture replaced with empty original", err)
	}
	var captured int
	if err = f.store.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1`, a.ID).Scan(&captured); err != nil || captured != 0 {
		t.Fatal("fabricated original custody", captured, err)
	}
	// Normal protected transaction changes only the already current lease's
	// deadline; this models expiration without sleeps or bypassing SQL guards.
	_, err = workers.Capacity.transactionWithTx(t.Context(), f.policy, func(_ model.CapacityPolicySpec, old *model.CapacityIntent, now time.Time, _ *sql.Tx) (model.CapacityIntent, string, error) {
		next := *old
		expiry := now.Add(-time.Second)
		next.LeaseExpiresAt = &expiry
		return next, "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = workers.OpenNativeExecution(t.Context(), f.policy, workers.Capacity.WorkflowID); err == nil {
		t.Fatal("expired parent adopted or renewed")
	}
	r.pending.Store(false)
	if err = workers.ReceiveNativeExecution(t.Context(), f.policy); err != nil {
		t.Fatal("late original receiving blocked", err)
	}
	current, err := workers.Read(context.Background(), f.policy, a.ID)
	if err != nil || current.State != "acknowledged" {
		t.Fatal("historical ACK did not survive expiry", current.State, err)
	}
	if _, err = session.Next(t.Context()); err == nil {
		t.Fatal("expiry enabled another reservation")
	}
	var count int
	if err = f.store.DB.QueryRowContext(t.Context(), `SELECT count(*) FROM public.capacity_native_worker_attempts WHERE policy_id=$1`, f.policy.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("expired generation created replacement", count, err)
	}
}

func TestNativeWorkerExecutionCompletesOnlyExactUsefulTargetPostgres(t *testing.T) {
	f, workers, r, authority := nativeAttemptFixture(t, func(p *model.CapacityPolicySpec) { p.Step = 2 })
	// Existing synthetic provider/readiness fixture; actual stores, command,
	// original archive, birth events, SQL guards and parent closure are real.
	workers.Runtime = nativeBudgetRuntime{r}
	session, err := workers.OpenNativeExecution(t.Context(), f.policy, workers.Capacity.WorkflowID)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		a, err := session.Next(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = workers.Redeem(t.Context(), f.policy, authority, a.ID); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			a, err = session.Record(t.Context(), a.ID)
			if err != nil {
				t.Fatal(err)
			}
		}
		if a.State != "admitted" {
			t.Fatal("real Record did not reach admitted", a.State)
		}
		f.pool.Nodes = append(f.pool.Nodes, model.CapacityNativeWorkerNode{NodeUID: a.NodeUID, NodeResourceVersion: "1", ProviderID: a.Physical.ProviderID, Provider: a.Provider, Profile: a.Profile, PoolUID: a.PoolUID, RegistrationEpoch: a.PoolEpoch, RegistrationBindingSHA256: f.p.NativeWorkerPoolBinding.Profiles[0].RegistrationBindingSHA, PhysicalSpecSHA256: a.PhysicalSpecSHA256, CurrentRegistration: true, CapacityPolicyID: a.PolicyID.String(), IntentGeneration: a.Generation, FencingToken: a.FencingToken, RegistrationReceiptSHA256: a.BirthSHA256, Ready: true, SchedulingAdmitted: true, AdmissionReceiptSHA256: strings.Repeat("c", 64), AdmissionRegistryUID: a.Registry.UID, AdmissionRegistryResourceVersion: f.pool.OwnerResourceVersion, ReadyObservedAt: time.Now().UTC(), AllocatableMilliCPU: 1000, AllocatableMemoryBytes: 1 << 30})
		f.market.Profiles[0].Quotas[0].Used = int64(len(f.pool.Nodes))
	}
	original := f.pool.Nodes[0]
	for _, change := range []func(){
		func() { f.pool.Nodes[0].Ready = false },
		func() { f.pool.Nodes[0].NodeUID = uuid.NewString() },
		func() { f.pool.Nodes[0].ProviderID += "-other" },
		func() { f.pool.Nodes[0].RegistrationReceiptSHA256 = strings.Repeat("e", 64) },
	} {
		change()
		if _, err = session.Complete(t.Context()); err == nil {
			t.Fatal("partial/substituted pool promoted parent")
		}
		f.pool.Nodes[0] = original
	}
	if _, err = session.Next(t.Context()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("complete target created another reservation", err)
	}
	complete, err := session.Complete(t.Context())
	if err != nil || complete.Phase != "promoted" || complete.Assessment.Snapshot.Units != 2 || complete.LeaseOwner != "" || complete.LeaseExecutorID != "" || complete.LeaseExpiresAt != nil {
		t.Fatal("real Native closure failed", complete.Phase, err)
	}
	var attempts, events int
	if err = f.store.DB.QueryRowContext(t.Context(), `SELECT count(*),sum(revision) FROM public.capacity_native_worker_attempts WHERE policy_id=$1`, f.policy.ID).Scan(&attempts, &events); err != nil || attempts != 2 || events != 10 {
		t.Fatal("closure rewrote child history or allocated surplus", attempts, events, err)
	}
	if _, err = session.Next(t.Context()); err == nil {
		t.Fatal("completed generation issued more capacity")
	}
}
