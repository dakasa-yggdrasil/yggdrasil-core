package executoractivity

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type controllerWorld struct {
	advanceObservationClock                      bool
	store                                        *activityFakeStore
	now                                          time.Time
	resource                                     ExactResource
	state, boot                                  string
	ready, complete, closed, uncertain, failSend bool
	reject                                       bool
	epoch                                        uint64
	jobs                                         map[string]string
	commands                                     []PowerCommand
	observes                                     int
}

func newControllerWorld() (*controllerWorld, Controller) {
	w := &controllerWorld{store: &activityFakeStore{}, now: activityTestNow, resource: ExactResource{AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0123456789abcdef0", OwnershipBindingID: "fixed-operator-record"}, state: "stopped", complete: true, jobs: map[string]string{}}
	c := Controller{Binding: PowerBinding{Enabled: true, Resource: w.resource, AllowedActions: []string{"start", "stop"}}, Policy: activityTestPolicy, Transactions: w, Power: worldPower{w}, Worker: worldWorker{w}}
	return w, c
}
func (w *controllerWorld) Change(ctx context.Context, change func(*ExecutorActivityState, time.Time) error) (ExecutorActivityState, error) {
	return UpdateExecutorActivity(ctx, w.store, "pool", activityTestPolicy, w.now, func(s *ExecutorActivityState) error { return change(s, w.now) })
}

type worldPower struct{ w *controllerWorld }

func (p worldPower) Observe(_ context.Context, r ExactResource) (PowerSnapshot, error) {
	if p.w.advanceObservationClock {
		p.w.now = p.w.now.Add(time.Millisecond)
	}
	p.w.observes++
	return PowerSnapshot{Resource: p.w.resource, State: p.w.state, BootID: p.w.boot, ObservedAt: p.w.now}, nil
}
func (p worldPower) Execute(_ context.Context, cmd PowerCommand) error {
	if cmd.Resource != p.w.resource || (cmd.Action != "start" && cmd.Action != "stop") {
		return fmt.Errorf("foreign authority")
	}
	p.w.commands = append(p.w.commands, cmd)
	if p.w.reject {
		return nil
	}
	if cmd.Action == "start" {
		p.w.state = "running"
		p.w.boot = fmt.Sprintf("boot-%d", len(p.w.commands))
		p.w.jobs = map[string]string{}
		p.w.closed = false
	} else {
		p.w.state = "stopped"
	}
	if p.w.failSend {
		return fmt.Errorf("original return lost")
	}
	return nil
}
func (p worldPower) Settlement(_ context.Context, cmd PowerCommand) (PowerSettlement, error) {
	state := "succeeded"
	if p.w.reject {
		state = "rejected_no_effect"
	}
	return PowerSettlement{CommandID: cmd.ID, Resource: cmd.Resource, Action: cmd.Action, OriginalInvocationJoined: !p.w.uncertain, State: state}, nil
}

type worldWorker struct{ w *controllerWorld }

func (p worldWorker) Observe(_ context.Context, _ ExactResource) (WorkerSnapshot, error) {
	if p.w.advanceObservationClock {
		p.w.now = p.w.now.Add(time.Millisecond)
	}
	jobs := map[string]string{}
	for k, v := range p.w.jobs {
		jobs[k] = v
	}
	return WorkerSnapshot{Resource: p.w.resource, BootID: p.w.boot, ObservedAt: p.w.now, Complete: p.w.complete, Ready: p.w.ready, Closed: p.w.closed, Epoch: p.w.epoch, Jobs: jobs}, nil
}
func (p worldWorker) Close(_ context.Context, _ ExactResource, epoch uint64) error {
	if epoch < p.w.epoch {
		return fmt.Errorf("stale close")
	}
	p.w.epoch = epoch
	p.w.closed = true
	return nil
}
func (p worldWorker) Open(_ context.Context, _ ExactResource, epoch uint64) error {
	if epoch < p.w.epoch {
		return fmt.Errorf("stale open")
	}
	p.w.epoch = epoch
	p.w.closed = false
	return nil
}
func (p worldWorker) Admit(_ context.Context, _ ExactResource, id string, epoch uint64, boot string) error {
	if p.w.closed || epoch != p.w.epoch || boot != p.w.boot {
		return fmt.Errorf("admission fenced")
	}
	if _, ok := p.w.jobs[id]; !ok {
		p.w.jobs[id] = "running"
	}
	return nil
}
func (w *controllerWorld) ingress(t *testing.T, id, job string, seq uint64, release bool) {
	t.Helper()
	_, err := w.Change(context.Background(), func(s *ExecutorActivityState, now time.Time) error {
		return ApplyWorkflowOperation(s, activityTestPolicy, "capacity.record_executor_activity", "machine:agent-a", WorkflowRequest{JobID: job, Event: ExecutorActivityEvent{TaskID: id, Sequence: seq, Release: release}}, now)
	})
	if err != nil {
		t.Fatal(err)
	}
}
func reconcile(t *testing.T, c Controller) string {
	t.Helper()
	state, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatal(state, err)
	}
	return state
}

func TestExecutorControllerCompleteLifecycleAndDemandDuringSentStop(t *testing.T) {
	w, c := newControllerWorld()
	w.ingress(t, "run-1", "job-1", 1, false)
	if got := reconcile(t, c); got != "start_requested" {
		t.Fatal(got)
	}
	if got := reconcile(t, c); got != "settled" {
		t.Fatal(got)
	}
	if got := reconcile(t, c); got != "waiting_ready" {
		t.Fatal(got)
	}
	w.ready = true
	if got := reconcile(t, c); got != "job_admitted" {
		t.Fatal(got)
	}
	w.ingress(t, "run-1", "", 2, false) // heartbeat independent of durable job
	reconcile(t, c)
	w.ingress(t, "run-1", "", 3, true)
	w.now = w.now.Add(time.Minute) // session ended and TTL elapsed; job remains alive
	reconcile(t, c)
	if len(w.commands) != 1 || w.state != "running" {
		t.Fatal("session loss stopped active job")
	}
	w.jobs["job-1"] = "finished"
	for i := 0; i <= 2; i++ {
		reconcile(t, c)
		w.now = w.now.Add(5 * time.Second)
	}
	if w.store.s.Stop == nil {
		t.Fatal("grace never reserved stop")
	}
	if got := reconcile(t, c); got != "draining" {
		t.Fatal(got)
	}
	w.uncertain = true
	if got := reconcile(t, c); got != "stop_requested" {
		t.Fatal(got)
	}
	w.ingress(t, "run-2", "job-2", 1, false)
	// A new controller process reloads persisted possible-send and queued jobs.
	w.store = &activityFakeStore{s: cloneActivity(w.store.s)}
	c.Transactions = w
	if got := reconcile(t, c); got != "recovery_pending" {
		t.Fatal(got)
	}
	if len(w.commands) != 2 || w.jobs["job-2"] != "" {
		t.Fatal("new task bypassed uncertain stop")
	}
	w.uncertain = false
	reconcile(t, c) // exact original invocation joined and stopped independently read
	if got := reconcile(t, c); got != "start_requested" {
		t.Fatal(got)
	}
	reconcile(t, c)
	if got := reconcile(t, c); got != "opening_admission" {
		t.Fatal(got)
	}
	if got := reconcile(t, c); got != "job_admitted" {
		t.Fatal(got)
	}
	if len(w.commands) != 3 || w.commands[0].Action != "start" || w.commands[1].Action != "stop" || w.commands[2].Action != "start" || w.jobs["job-2"] != "running" {
		t.Fatal(w.commands, w.jobs)
	}
}

func TestExecutorControllerUnknownSendNeverRetries(t *testing.T) {
	w, c := newControllerWorld()
	w.ingress(t, "run", "job", 1, false)
	w.failSend = true
	w.uncertain = true
	if _, err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("lost return ignored")
	}
	for range 3 {
		if got := reconcile(t, c); got != "recovery_pending" {
			t.Fatal(got)
		}
	}
	if len(w.commands) != 1 || w.store.s.Power == nil {
		t.Fatal("ambiguous command replayed")
	}
	w.failSend = false
	w.uncertain = false
	if got := reconcile(t, c); got != "settled" {
		t.Fatal(got)
	}
}

func TestExecutorControllerDefaultOffAndExactAuthority(t *testing.T) {
	for _, mutate := range []func(*Controller){func(c *Controller) { c.Binding.Enabled = false }, func(c *Controller) { c.Binding.Resource.OwnershipBindingID = "" }, func(c *Controller) { c.Binding.AllowedActions = []string{"start", "terminate"} }, func(c *Controller) { c.Binding.Resource.AccountID = "999999999999" }} {
		w, c := newControllerWorld()
		w.ingress(t, "run", "job", 1, false)
		mutate(&c)
		if _, err := c.Reconcile(context.Background()); err == nil {
			t.Fatal("unapproved resource/actions admitted")
		}
		if len(w.commands) != 0 {
			t.Fatal("unauthorized power mutation")
		}
	}
}

func TestExecutorControllerUnknownInventoryBlocksStop(t *testing.T) {
	w, c := newControllerWorld()
	w.state = "running"
	w.boot = "boot-existing"
	w.ready = true
	w.complete = false
	for range 4 {
		if got := reconcile(t, c); got != "inventory_unknown" {
			t.Fatal(got)
		}
		w.now = w.now.Add(5 * time.Second)
	}
	if len(w.commands) != 0 || w.store.s.Stop != nil {
		t.Fatal("unknown inventory became idle")
	}
}

func TestExecutorControllerOldCloseCannotFenceNewDemand(t *testing.T) {
	w, c := newControllerWorld()
	w.state = "running"
	w.boot = "boot-existing"
	w.ready = true
	for range 3 {
		reconcile(t, c)
		w.now = w.now.Add(5 * time.Second)
	}
	old := w.store.s.Stop.Epoch
	reconcile(t, c) // worker closes at old epoch
	w.ingress(t, "run", "job", 1, false)
	if w.store.s.Epoch <= old {
		t.Fatal("cancel did not advance epoch")
	}
	if got := reconcile(t, c); got != "opening_admission" {
		t.Fatal(got)
	}
	if err := (worldWorker{w}).Close(context.Background(), w.resource, old); err == nil {
		t.Fatal("old close reopened shutdown race")
	}
	if got := reconcile(t, c); got != "job_admitted" {
		t.Fatal(got)
	}
}

func TestExecutorControllerRejectNoEffectNeedsOriginalJoinedReturn(t *testing.T) {
	w, c := newControllerWorld()
	w.ingress(t, "run", "job", 1, false)
	w.reject = true
	w.uncertain = true
	reconcile(t, c)
	if got := reconcile(t, c); got != "recovery_pending" {
		t.Fatal(got)
	}
	w.uncertain = false
	if got := reconcile(t, c); got != "settled" {
		t.Fatal(got)
	}
	if len(w.store.s.PowerHistory) != 1 || w.state != "stopped" {
		t.Fatal("no-effect result not retained")
	}
	w.reject = false
	if got := reconcile(t, c); got != "start_requested" {
		t.Fatal(got)
	}
	if len(w.commands) != 2 || w.commands[0].ID == w.commands[1].ID {
		t.Fatal("reused original command")
	}
}

func TestExecutorControllerCannotChangePinnedResourceOrPolicy(t *testing.T) {
	for _, mutate := range []func(*Controller){func(c *Controller) { c.Binding.Resource.InstanceID = "i-11111111111111111" }, func(c *Controller) { c.Policy.IdleAfter = time.Second }} {
		w, c := newControllerWorld()
		w.ingress(t, "run", "job", 1, false)
		reconcile(t, c)
		before := w.observes
		mutate(&c)
		if _, err := c.Reconcile(context.Background()); err == nil {
			t.Fatal("pinned configuration changed")
		}
		if w.observes != before || len(w.commands) != 1 {
			t.Fatal("foreign configuration reached provider")
		}
	}
}

func TestExecutorIngressCannotHeartbeatAnotherPrincipalTask(t *testing.T) {
	w, _ := newControllerWorld()
	w.ingress(t, "run", "job", 1, false)
	_, err := w.Change(context.Background(), func(s *ExecutorActivityState, now time.Time) error {
		return ApplyWorkflowOperation(s, activityTestPolicy, "capacity.record_executor_activity", "machine:agent-b", WorkflowRequest{Event: ExecutorActivityEvent{TaskID: "run", Sequence: 2}}, now)
	})
	if err == nil || w.store.s.Tasks["run"].Sequence != 1 {
		t.Fatal("another principal renewed task")
	}
}

func TestExecutorControllerObservationUsesClockAfterIO(t *testing.T) {
	w, c := newControllerWorld()
	w.advanceObservationClock = true
	w.ingress(t, "run", "job", 1, false)
	if got := reconcile(t, c); got != "start_requested" {
		t.Fatal(got)
	}
	reconcile(t, c)
	w.ready = true
	if got := reconcile(t, c); got != "job_admitted" {
		t.Fatal(got)
	}
}

func TestExecutorControllerHistoryBoundBlocksBeforeProviderSend(t *testing.T) {
	w, c := newControllerWorld()
	w.ingress(t, "run", "job", 1, false)
	_, err := w.Change(context.Background(), func(s *ExecutorActivityState, now time.Time) error {
		r := w.resource
		s.BoundResource = &r
		s.PowerHistory = map[string]PowerCommand{}
		for i := 0; i < activityTestPolicy.MaxTasks; i++ {
			id := fmt.Sprintf("old-%d", i)
			s.PowerHistory[id] = PowerCommand{ID: id, Action: "start", Resource: r, IssuedAt: now, Joined: true, Result: "succeeded"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Reconcile(context.Background()); err == nil || len(w.commands) != 0 {
		t.Fatal("ledger exhaustion allowed a new provider send", err)
	}
}
