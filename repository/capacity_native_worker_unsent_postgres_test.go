package repository

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

func unsentNativeFixture(t *testing.T) (marketRepositoryFixture, CapacityNativeWorkerCommandStore, model.CapacityNativeWorkerAuthority, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerCommandCaller) {
	t.Helper()
	f, workers, _, authority := nativeAttemptFixture(t, func(p *model.CapacityPolicySpec) { p.LeaseSeconds = 5 })
	a, err := workers.Reserve(t.Context(), f.policy, authority)
	if err != nil {
		t.Fatal(err)
	}
	caller := model.CapacityNativeWorkerCommandCaller{BindingName: a.Execution.BindingName, InstanceID: a.Execution.Adapter.ManifestID, SDKSourceCommit: a.Execution.SDKSourceCommit, Capability: a.Execution.EnsureCapability}
	return f, CapacityNativeWorkerCommandStore{Workers: workers}, authority, a, caller
}

func waitNativeUnsentDeadline(t *testing.T, f marketRepositoryFixture, id uuid.UUID) {
	t.Helper()
	// Exercise the real immutable deadline and PostgreSQL clock; never rewrite
	// command authority or change the production time source for this fixture.
	var seconds float64
	if err := f.db.QueryRow(`SELECT GREATEST(0,extract(epoch FROM ((record->>'expires_at')::timestamptz-clock_timestamp()))) FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, id).Scan(&seconds); err != nil {
		t.Fatal(err)
	}
	if seconds > 6 {
		t.Fatal("unexpected synthetic CI command lifetime", seconds)
	}
	time.Sleep(time.Duration(seconds*float64(time.Second)) + 50*time.Millisecond)
}

func TestNativeUnsentClosurePostgresExpiresOriginalCommandAndRetainsHistory(t *testing.T) {
	f, store, _, a, caller := unsentNativeFixture(t)
	ctx := t.Context()
	if _, err := store.CloseUnredeemed(ctx, f.policy, a.ID); err == nil {
		t.Fatal("a live command was closed before its immutable deadline")
	}
	if _, err := f.db.Exec(`UPDATE public.capacity_native_worker_attempts SET state='absent',revision=revision+1,attempt=jsonb_set(jsonb_set(attempt,'{state}','"absent"'),'{revision}',to_jsonb(revision+1)) WHERE id=$1`, a.ID); err == nil {
		t.Fatal("direct state change bypassed the retained no-send proof")
	}
	waitNativeUnsentDeadline(t, f, a.ID)
	closed, err := store.CloseUnredeemed(ctx, f.policy, a.ID)
	if err != nil || closed.State != "absent" || closed.Physical != nil || closed.NodeUID != "" || closed.BirthSHA256 != "" || closed.Revision != a.Revision+1 {
		t.Fatal("unsent closure fabricated a physical lifetime or failed", err)
	}
	repeated, err := store.CloseUnredeemed(ctx, f.policy, a.ID)
	if err != nil || repeated.Revision != closed.Revision || repeated.State != "absent" {
		t.Fatal("original closure is not idempotent", err)
	}
	var events, proofs, captures, charged int
	if err = f.db.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_native_worker_events WHERE attempt_id=$1),(SELECT count(*) FROM public.capacity_native_worker_unsent_closures WHERE attempt_id=$1),(SELECT count(*) FROM public.capacity_native_worker_original_returns WHERE attempt_id=$1),(SELECT count(*) FROM public.capacity_native_worker_attempts WHERE id=$1 AND state<>'absent')`, a.ID).Scan(&events, &proofs, &captures, &charged); err != nil || events != 2 || proofs != 1 || captures != 0 || charged != 0 {
		t.Fatal("closure lost history, fabricated custody or kept a nonexistent charge", events, proofs, captures, charged, err)
	}
	read, err := store.Read(ctx, f.policy, a.ID, caller)
	if err != nil || read.Redeemable || read.MutationPermitted || read.AttemptState != "absent" {
		t.Fatal("closed command reopened creation", err)
	}
	if _, err = store.Redeem(ctx, f.policy, a.ID, caller); err == nil {
		t.Fatal("closed command granted a provider send")
	}
	if err = store.Receive(ctx, f.policy, caller, model.CapacityNativeWorkerCommandReceive{AttemptID: a.ID, BindingName: caller.BindingName, OriginalReturn: []byte("a provider response cannot follow a proven unsent command"), CaptureComplete: true}); err == nil {
		t.Fatal("proven no-send history accepted later provider custody")
	}
}

func TestNativeUnsentClosurePostgresNeverClosesAnExposedSend(t *testing.T) {
	f, store, authority, a, _ := unsentNativeFixture(t)
	if _, err := store.Workers.Redeem(t.Context(), f.policy, authority, a.ID); err != nil {
		t.Fatal(err)
	}
	waitNativeUnsentDeadline(t, f, a.ID)
	if _, err := store.CloseUnredeemed(t.Context(), f.policy, a.ID); err == nil {
		t.Fatal("an expired possibly successful send became no effect")
	}
	current, err := store.Workers.Read(t.Context(), f.policy, a.ID)
	if err != nil || current.State != "send_started" || current.Revision != 2 {
		t.Fatal("exposed send lost its honest state", err)
	}
	var proofs int
	if err = f.db.QueryRow(`SELECT count(*) FROM public.capacity_native_worker_unsent_closures WHERE attempt_id=$1`, a.ID).Scan(&proofs); err != nil || proofs != 0 {
		t.Fatal("exposed send acquired unsent closure", err)
	}
	if _, err = f.db.Exec(`INSERT INTO public.capacity_native_worker_unsent_closures(attempt_id,policy_id,namespace,from_revision,command_context,closed_at) SELECT a.id,a.policy_id,a.namespace,1,c.record,clock_timestamp() FROM public.capacity_native_worker_attempts a JOIN public.capacity_native_worker_command_contexts c ON c.attempt_id=a.id WHERE a.id=$1`, a.ID); err == nil {
		t.Fatal("SQL guard accepted a forged unsent proof for an exposed send")
	}
}

func TestNativeUnsentClosurePostgresConcurrentClosersShareOneRetainedProof(t *testing.T) {
	f, store, _, a, _ := unsentNativeFixture(t)
	waitNativeUnsentDeadline(t, f, a.ID)
	var group sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		group.Go(func() {
			_, err := store.CloseUnredeemed(t.Context(), f.policy, a.ID)
			results <- err
		})
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent original closure was not idempotent", err)
		}
	}
	var events, proofs int
	if err := f.db.QueryRow(`SELECT (SELECT count(*) FROM public.capacity_native_worker_events WHERE attempt_id=$1),(SELECT count(*) FROM public.capacity_native_worker_unsent_closures WHERE attempt_id=$1)`, a.ID).Scan(&events, &proofs); err != nil || events != 2 || proofs != 1 {
		t.Fatal("concurrent closures changed custody more than once", events, proofs, err)
	}
}

func TestNativeUnsentClosurePostgresScopeGatesAndImmutableRollback(t *testing.T) {
	f, store, _, a, _ := unsentNativeFixture(t)
	ctx := t.Context()
	off := store
	off.Workers.Enabled = false
	if _, err := off.CloseUnredeemed(ctx, f.policy, a.ID); err == nil {
		t.Fatal("disabled Native lifecycle closed a reservation")
	}
	off = store
	off.Workers.Capacity.ExecutionEnabled = false
	if _, err := off.CloseUnredeemed(ctx, f.policy, a.ID); err == nil {
		t.Fatal("global process gate was ignored")
	}
	waitNativeUnsentDeadline(t, f, a.ID)
	wrong := f.policy
	wrong.Checksum = strings.Repeat("f", 64)
	if _, err := store.CloseUnredeemed(ctx, wrong, a.ID); err == nil {
		t.Fatal("substituted policy closed an original reservation")
	}
	if _, err := store.CloseUnredeemed(ctx, f.policy, a.ID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE public.capacity_native_worker_unsent_closures SET closed_at=closed_at+interval '1 second' WHERE attempt_id=$1`,
		`DELETE FROM public.capacity_native_worker_unsent_closures WHERE attempt_id=$1`,
		`INSERT INTO public.capacity_native_worker_original_returns(attempt_id,wire,raw_sha256,capture_complete,error_class) VALUES($1,'late',repeat('a',64),true,'')`,
	} {
		if _, err := f.db.Exec(statement, a.ID); err == nil {
			t.Fatal("SQL guard let retained no-send truth change")
		}
	}
	if err := goose.DownTo(f.db, "../db/migrations", 115); err == nil || !strings.Contains(err.Error(), "Native unsent closure history cannot be discarded") {
		t.Fatal("migration rollback discarded retained unsent closure")
	}
	var command json.RawMessage
	if err := f.db.QueryRow(`SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&command); err != nil || len(command) == 0 {
		t.Fatal("original command authority was discarded", err)
	}
}
