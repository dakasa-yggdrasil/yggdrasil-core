package executoractivity

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type activityFakeStore struct {
	mu       sync.Mutex
	s        ExecutorActivityState
	err      error
	conflict bool
}

func (f *activityFakeStore) Load(ctx context.Context, _ string) (ExecutorActivityState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ExecutorActivityState{}, err
	}
	return cloneActivity(f.s), f.err
}
func (f *activityFakeStore) CompareAndSwap(ctx context.Context, _ string, revision uint64, next ExecutorActivityState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.conflict || f.s.Revision != revision {
		return ErrExecutorActivityConflict
	}
	f.s = cloneActivity(next)
	return nil
}
func cloneActivity(s ExecutorActivityState) ExecutorActivityState {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	var out ExecutorActivityState
	if err = json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

var activityTestPolicy = ExecutorActivityPolicy{LeaseTTL: 30 * time.Second, IdleAfter: 10 * time.Second, MaxObservationAge: 5 * time.Second, MaxTasks: 100}
var activityTestNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func activityUpdate(t *testing.T, f *activityFakeStore, now time.Time, change func(*ExecutorActivityState) error) ExecutorActivityState {
	t.Helper()
	s, err := UpdateExecutorActivity(context.Background(), f, "lab/pool", activityTestPolicy, now, change)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func activityEvent(id string, seq uint64, release bool) ExecutorActivityEvent {
	return ExecutorActivityEvent{TaskID: id, Owner: "agent-a", Sequence: seq, Release: release}
}
func activityApply(t *testing.T, f *activityFakeStore, now time.Time, e ExecutorActivityEvent) ExecutorActivityState {
	t.Helper()
	return activityUpdate(t, f, now, func(s *ExecutorActivityState) error { return ApplyExecutorActivity(s, activityTestPolicy, e, now) })
}
func quietObservation(now time.Time) ExecutorActivityObservation {
	return ExecutorActivityObservation{ObservedAt: now, Complete: true}
}
func activityQuiet(t *testing.T, f *activityFakeStore, now time.Time) ExecutorActivityState {
	t.Helper()
	return activityUpdate(t, f, now, func(s *ExecutorActivityState) error {
		return ObserveExecutorQuiet(s, activityTestPolicy, quietObservation(now), now)
	})
}
func activityDraining(t *testing.T) (*activityFakeStore, time.Time) {
	t.Helper()
	f := &activityFakeStore{}
	now := activityTestNow
	for i := 0; i <= 10; i += 5 {
		activityQuiet(t, f, now.Add(time.Duration(i)*time.Second))
	}
	now = now.Add(10 * time.Second)
	activityUpdate(t, f, now, func(s *ExecutorActivityState) error {
		return ReserveExecutorStop(s, activityTestPolicy, "stop-1", quietObservation(now), now)
	})
	return f, now
}

func TestExecutorActivityConcurrentTasksAndReplay(t *testing.T) {
	f := &activityFakeStore{}
	now := activityTestNow
	activityApply(t, f, now, activityEvent("run-a", 1, false))
	s := activityApply(t, f, now, activityEvent("run-b", 1, false))
	expires := s.Tasks["run-a"].ExpiresAt
	s = activityApply(t, f, now.Add(time.Second), activityEvent("run-a", 1, false))
	if s.Tasks["run-a"].ExpiresAt != expires || ExecutorActiveTasks(s, now) != 2 {
		t.Fatal("retry extended TTL or lost second task")
	}
	s = activityApply(t, f, now.Add(2*time.Second), activityEvent("run-a", 2, true))
	if ExecutorActiveTasks(s, now.Add(2*time.Second)) != 1 {
		t.Fatal("release affected another task")
	}
	wrong := activityEvent("run-b", 2, false)
	wrong.Owner = "other-agent"
	if ApplyExecutorActivity(&s, activityTestPolicy, wrong, now.Add(3*time.Second)) == nil {
		t.Fatal("owner changed")
	}
	if ApplyExecutorActivity(&s, activityTestPolicy, activityEvent("run-a", 3, false), now.Add(3*time.Second)) == nil {
		t.Fatal("released task resurrected")
	}
	if ApplyExecutorActivity(&s, activityTestPolicy, activityEvent("run-b", 2, false), now.Add(31*time.Second)) == nil {
		t.Fatal("expired task resurrected")
	}
}

func TestExecutorActivityDisconnectDoesNotKillBuild(t *testing.T) {
	f := &activityFakeStore{}
	now := activityTestNow
	activityApply(t, f, now, activityEvent("run-a", 1, false))
	now = now.Add(time.Minute) // AI disappeared; independent build still running.
	o := quietObservation(now)
	o.ActiveJobs = 1
	s := activityUpdate(t, f, now, func(s *ExecutorActivityState) error { return ObserveExecutorQuiet(s, activityTestPolicy, o, now) })
	if ExecutorActiveTasks(s, now) != 0 || !s.IdleSince.IsZero() {
		t.Fatal("expired agent inferred idle despite build")
	}
	if ReserveExecutorStop(&s, activityTestPolicy, "stop", o, now) == nil {
		t.Fatal("stopped active build")
	}
	o.ActiveJobs = 0
	o.Complete = false
	if err := ObserveExecutorQuiet(&s, activityTestPolicy, o, now); err != nil || !s.IdleSince.IsZero() {
		t.Fatal("unknown inventory inferred idle")
	}
}

func TestExecutorActivityIdleGapAndClockRollback(t *testing.T) {
	f := &activityFakeStore{}
	activityQuiet(t, f, activityTestNow)
	now := activityTestNow.Add(time.Minute)
	s := activityQuiet(t, f, now)
	if !s.IdleSince.Equal(now) {
		t.Fatal("restart gap preserved unobserved quiet window")
	}
	if ReserveExecutorStop(&s, activityTestPolicy, "stop", quietObservation(now), now) == nil {
		t.Fatal("idle interval skipped")
	}
	_, err := UpdateExecutorActivity(context.Background(), f, "lab/pool", activityTestPolicy, now.Add(-time.Second), func(*ExecutorActivityState) error { return nil })
	if err == nil {
		t.Fatal("clock rollback accepted")
	}
}

func TestExecutorActivityNewDemandRevokesDrain(t *testing.T) {
	f, now := activityDraining(t)
	stale := cloneActivity(f.s)
	s := activityApply(t, f, now, activityEvent("new-run", 1, false))
	if s.Stop != nil || !ExecutorDemandPending(s, now) {
		t.Fatal("new demand did not revoke unsent stop")
	}
	o := quietObservation(now)
	o.AdmissionClosed = true
	o.Epoch = stale.Epoch
	if err := MarkExecutorStopPossibleSend(&stale, activityTestPolicy, "stop-1", o, now); err != nil {
		t.Fatal(err)
	}
	stale.Revision++
	if err := f.CompareAndSwap(context.Background(), "lab/pool", stale.Revision-1, stale); !errors.Is(err, ErrExecutorActivityConflict) {
		t.Fatal("stale stop won over task CAS", err)
	}
}

func TestExecutorActivityStopCommitQueuesDemandAndSurvivesRestart(t *testing.T) {
	f, now := activityDraining(t)
	o := quietObservation(now)
	o.AdmissionClosed = true
	o.Epoch = f.s.Epoch
	s := activityUpdate(t, f, now, func(s *ExecutorActivityState) error {
		return MarkExecutorStopPossibleSend(s, activityTestPolicy, "stop-1", o, now)
	})
	if s.Stop.Stage != "possible_send" {
		t.Fatal("stop not persisted")
	}
	// Serialization simulates control-plane restart after possible send, before reply.
	f = &activityFakeStore{s: cloneActivity(s)}
	s = activityApply(t, f, now.Add(time.Second), activityEvent("new-run", 1, false))
	if ExecutorActiveTasks(s, now.Add(time.Second)) != 1 || ExecutorDemandPending(s, now.Add(time.Second)) {
		t.Fatal("admitted work into uncertain stop")
	}
	if err := MarkExecutorStopPossibleSend(&s, activityTestPolicy, "stop-1", o, now.Add(time.Second)); err == nil {
		t.Fatal("duplicate stop attempt allowed")
	}
	activityQuiet(t, f, now.Add(time.Hour))
	if f.s.Stop == nil || f.s.Stop.Stage != "possible_send" {
		t.Fatal("unknown timed out into authority")
	}
}

func TestExecutorActivityStopRequiresCurrentClosedCompleteInventory(t *testing.T) {
	for _, name := range []string{"open", "epoch", "jobs", "unknown", "stale", "future"} {
		t.Run(name, func(t *testing.T) {
			f, now := activityDraining(t)
			o := quietObservation(now)
			o.AdmissionClosed = true
			o.Epoch = f.s.Epoch
			switch name {
			case "open":
				o.AdmissionClosed = false
			case "epoch":
				o.Epoch++
			case "jobs":
				o.ActiveJobs = 1
			case "unknown":
				o.Complete = false
			case "stale":
				o.ObservedAt = now.Add(-6 * time.Second)
			case "future":
				o.ObservedAt = now.Add(time.Second)
			}
			if err := MarkExecutorStopPossibleSend(&f.s, activityTestPolicy, "stop-1", o, now); err == nil {
				t.Fatal("unsafe stop permitted")
			}
		})
	}
}

func TestExecutorActivityStorageFailureConflictAndBound(t *testing.T) {
	errLost := errors.New("lost storage")
	for _, f := range []*activityFakeStore{{err: errLost}, {conflict: true}} {
		_, err := UpdateExecutorActivity(context.Background(), f, "lab/pool", activityTestPolicy, activityTestNow, func(s *ExecutorActivityState) error {
			return ApplyExecutorActivity(s, activityTestPolicy, activityEvent("run", 1, false), activityTestNow)
		})
		if err == nil || len(f.s.Tasks) != 0 {
			t.Fatal("storage error became admitted task", err)
		}
	}
	p := activityTestPolicy
	p.MaxTasks = 1
	s := ExecutorActivityState{}
	if err := ApplyExecutorActivity(&s, p, activityEvent("run", 1, false), activityTestNow); err != nil {
		t.Fatal(err)
	}
	if err := ApplyExecutorActivity(&s, p, activityEvent("run", 2, true), activityTestNow); err != nil {
		t.Fatal(err)
	}
	if err := ApplyExecutorActivity(&s, p, activityEvent("second", 1, false), activityTestNow); err == nil {
		t.Fatal("bounded replay ledger silently evicted tombstone")
	}
}

func TestExecutorActivityCASAllowsOnlyOneStopCommit(t *testing.T) {
	f, now := activityDraining(t)
	a, b := cloneActivity(f.s), cloneActivity(f.s)
	o := quietObservation(now)
	o.AdmissionClosed = true
	o.Epoch = a.Epoch
	for _, s := range []*ExecutorActivityState{&a, &b} {
		if err := MarkExecutorStopPossibleSend(s, activityTestPolicy, "stop-1", o, now); err != nil {
			t.Fatal(err)
		}
		s.Revision++
	}
	if err := f.CompareAndSwap(context.Background(), "lab/pool", a.Revision-1, a); err != nil {
		t.Fatal(err)
	}
	if err := f.CompareAndSwap(context.Background(), "lab/pool", b.Revision-1, b); !errors.Is(err, ErrExecutorActivityConflict) {
		t.Fatal("two senders committed", err)
	}
}

func TestExecutorActivityHeartbeatRenewsOnlyCurrentRun(t *testing.T) {
	f := &activityFakeStore{}
	activityApply(t, f, activityTestNow, activityEvent("run", 1, false))
	now := activityTestNow.Add(20 * time.Second)
	s := activityApply(t, f, now, activityEvent("run", 2, false))
	if !s.Tasks["run"].ExpiresAt.Equal(now.Add(activityTestPolicy.LeaseTTL)) {
		t.Fatal("current heartbeat failed to renew lease")
	}
	s = activityApply(t, f, now.Add(time.Second), activityEvent("run", 1, false))
	if !s.Tasks["run"].ExpiresAt.Equal(now.Add(activityTestPolicy.LeaseTTL)) {
		t.Fatal("out-of-order heartbeat changed expiry")
	}
}

func TestExecutorActivityRetriesCannotBridgeInventoryGap(t *testing.T) {
	f := &activityFakeStore{}
	activityApply(t, f, activityTestNow, activityEvent("run", 1, false))
	activityApply(t, f, activityTestNow, activityEvent("run", 2, true))
	activityQuiet(t, f, activityTestNow)
	for _, seconds := range []int{3, 6, 9} {
		activityApply(t, f, activityTestNow.Add(time.Duration(seconds)*time.Second), activityEvent("run", 2, true))
	}
	now := activityTestNow.Add(10 * time.Second)
	s := activityQuiet(t, f, now)
	if !s.IdleSince.Equal(now) {
		t.Fatal("non-inventory writes bridged an unobserved idle interval")
	}
	if err := ReserveExecutorStop(&s, activityTestPolicy, "stop", quietObservation(now), now); err == nil {
		t.Fatal("unobserved interval authorized stop")
	}
}

type activityBarrierStore struct {
	*activityFakeStore
	loads  atomic.Int32
	ready  chan struct{}
	resume chan struct{}
}

func (s *activityBarrierStore) Load(ctx context.Context, scope string) (ExecutorActivityState, error) {
	state, err := s.activityFakeStore.Load(ctx, scope)
	if err != nil {
		return state, err
	}
	if s.loads.Add(1) <= 2 {
		s.ready <- struct{}{}
		select {
		case <-s.resume:
		case <-ctx.Done():
			return ExecutorActivityState{}, ctx.Err()
		}
	}
	return state, nil
}

func TestExecutorActivityConcurrentIngressReloadsWithoutLostTask(t *testing.T) {
	store := &activityBarrierStore{activityFakeStore: &activityFakeStore{}, ready: make(chan struct{}, 2), resume: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type returned struct {
		id  string
		err error
	}
	results := make(chan returned, 2)
	apply := func(id string) error {
		_, err := UpdateExecutorActivity(ctx, store, "pool", activityTestPolicy, activityTestNow, func(s *ExecutorActivityState) error {
			return ApplyExecutorActivity(s, activityTestPolicy, activityEvent(id, 1, false), activityTestNow)
		})
		return err
	}
	for _, id := range []string{"run-a", "run-b"} {
		go func(id string) { results <- returned{id, apply(id)} }(id)
	}
	for range 2 {
		select {
		case <-store.ready:
		case <-ctx.Done():
			close(store.resume)
			t.Fatal("ingress rendezvous timed out")
		}
	}
	close(store.resume)
	conflicts := 0
	for range 2 {
		r := <-results
		if errors.Is(r.err, ErrExecutorActivityConflict) {
			conflicts++
			if err := apply(r.id); err != nil {
				t.Fatal(err)
			}
		} else if r.err != nil {
			t.Fatal(r.err)
		}
	}
	state, err := store.Load(ctx, "pool")
	if err != nil || conflicts != 1 || state.Revision != 2 || ExecutorActiveTasks(state, activityTestNow) != 2 {
		t.Fatal(state, conflicts, err)
	}
}
