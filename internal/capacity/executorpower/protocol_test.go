package executorpower

import (
	"context"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"strings"
	"testing"
	"time"
)

const operator = "11111111-1111-4111-8111-111111111111"
const instance = "22222222-2222-4222-8222-222222222222"
const typeID = "33333333-3333-4333-8333-333333333333"
const adoptionID = "44444444-4444-4444-8444-444444444444"
const grantID = "55555555-5555-4555-8555-555555555555"
const attemptID = "66666666-6666-4666-8666-666666666666"

func fixture(t *testing.T, action string) (Binding, Adoption, executoractivity.ExecutorActivityState, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	b := Binding{Mode: Kind, Enabled: true, Resource: Resource{AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0123456789abcdef0", Volumes: []string{"vol-0123456789abcdef0"}}, IntegrationID: instance, IntegrationChecksum: strings.Repeat("a", 64), TypeID: typeID, TypeChecksum: strings.Repeat("b", 64), AdapterPrincipal: "power-adapter", ControllerPrincipal: "controller", Operators: []string{operator}, AdoptionWorkflow: Workflow{Namespace: "lab", Name: "adopt"}, GrantSeconds: 30}
	a, err := Adopt(b, operator, adoptionID, Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}, now, true)
	if err != nil {
		t.Fatal(err)
	}
	r := executoractivity.ExactResource{AccountID: b.Resource.AccountID, Region: b.Resource.Region, InstanceID: b.Resource.InstanceID, OwnershipBindingID: a.ID}
	s := executoractivity.ExecutorActivityState{Epoch: 2, BoundResource: &r, Tasks: map[string]executoractivity.ExecutorTaskLease{}, Power: &executoractivity.PowerCommand{ID: "original-command", Action: action, Resource: r, IssuedAt: now}, PinnedPolicy: &executoractivity.ExecutorActivityPolicy{MaxObservationAge: 30 * time.Second, IdleAfter: time.Minute}}
	if action == "start" {
		s.Tasks["task"] = executoractivity.ExecutorTaskLease{Owner: "machine:caller", Sequence: 1, ExpiresAt: now.Add(time.Minute)}
	} else {
		s.IdleSince = now.Add(-2 * time.Minute)
		s.Stop = &executoractivity.ExecutorStopReservation{ID: s.Power.ID, Epoch: s.Epoch, Stage: "possible_send", CreatedAt: now.Add(-time.Second), SendAt: now}
	}
	return b, a, s, now
}
func grantFixture(t *testing.T, action string) (Grant, time.Time) {
	b, a, s, now := fixture(t, action)
	g, err := Issue(b, a, Scope{Namespace: "lab", Environment: "lab", Domain: "ai", Dimension: "executor", PolicyID: instance, PolicyChecksum: strings.Repeat("c", 64), WorkflowID: typeID}, "machine:controller", grantID, s.Power.ID, action, s, now, true)
	if err != nil {
		t.Fatal(err)
	}
	return g, now
}
func claimFor(g Grant) Claim {
	return Claim{GrantID: g.ID, Action: g.Action, CommandID: g.CommandID, RequestSHA: g.RequestSHA, AttemptID: attemptID, SettlementSHA: Digest(strings.Repeat("t", 32))}
}
func TestExecutorPowerAdoptionExactIndependentIdentity(t *testing.T) {
	b, _, _, now := fixture(t, "start")
	o := Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}
	cases := []struct {
		name    string
		mutate  func(*Binding, *Observation)
		op      string
		enabled bool
	}{
		{"global off", func(*Binding, *Observation) {}, operator, false},
		{"binding off", func(b *Binding, _ *Observation) { b.Enabled = false }, operator, true},
		{"wrong human", func(*Binding, *Observation) {}, "machine:controller", true},
		{"wrong account", func(_ *Binding, o *Observation) { o.Resource.AccountID = "999999999999" }, operator, true},
		{"wrong instance", func(_ *Binding, o *Observation) { o.Resource.InstanceID = "i-11111111111111111" }, operator, true},
		{"disk changed", func(_ *Binding, o *Observation) { o.Resource.Volumes = []string{"vol-11111111111111111"} }, operator, true},
		{"stale", func(_ *Binding, o *Observation) { o.ObservedAt = now.Add(-31 * time.Second) }, operator, true},
		{"future", func(_ *Binding, o *Observation) { o.ObservedAt = now.Add(time.Second) }, operator, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bb, oo := b, o
			tc.mutate(&bb, &oo)
			if _, err := Adopt(bb, tc.op, adoptionID, oo, now, tc.enabled); err == nil {
				t.Fatal("invalid adoption admitted")
			}
		})
	}
}
func TestExecutorPowerSeparateStartStopAndNoCreateDestroy(t *testing.T) {
	for _, action := range []string{"start", "stop"} {
		g, _ := grantFixture(t, action)
		if ValidateGrant(g) != nil || Capability(action) == "" {
			t.Fatal("valid power action rejected")
		}
	}
	for _, action := range []string{"create", "destroy", "terminate", "ensure_ec2_instance", "stop_ec2_instance", "*"} {
		if Capability(action) != "" {
			t.Fatal("foreign capability accepted")
		}
	}
	b, a, s, now := fixture(t, "stop")
	s.Tasks["new"] = executoractivity.ExecutorTaskLease{ExpiresAt: now.Add(time.Minute)}
	if _, err := Issue(b, a, Scope{}, "machine:controller", grantID, s.Power.ID, "stop", s, now, true); err == nil {
		t.Fatal("new demand admitted stop")
	}
}
func TestExecutorPowerCommandEpochOwnershipAndCensus(t *testing.T) {
	for _, name := range []string{"epoch", "adoption", "principal", "jobs", "drain", "stale", "idle"} {
		t.Run(name, func(t *testing.T) {
			b, a, s, now := fixture(t, "stop")
			principal := "machine:controller"
			switch name {
			case "epoch":
				s.Stop.Epoch++
			case "adoption":
				a.ID = operator
			case "principal":
				principal = "machine:other"
			case "jobs":
				s.Jobs = map[string]executoractivity.Job{"child": {State: "running"}}
			case "drain":
				s.Stop.Stage = "draining"
			case "stale":
				s.Power.IssuedAt = now.Add(-time.Minute)
			case "idle":
				s.IdleSince = now
			}
			if _, err := Issue(b, a, Scope{}, principal, grantID, s.Power.ID, "stop", s, now, true); err == nil {
				t.Fatal("unsafe stop admitted")
			}
		})
	}
}
func TestExecutorPowerOneUseRevocationAndDeadline(t *testing.T) {
	for _, name := range []string{"wrong principal", "wrong command", "wrong action", "wrong hash", "expired", "disabled", "new demand", "valid"} {
		t.Run(name, func(t *testing.T) {
			g, now := grantFixture(t, "stop")
			c := claimFor(g)
			p := g.Binding.AdapterPrincipal
			enabled, current := true, true
			switch name {
			case "wrong principal":
				p = "other"
			case "wrong command":
				c.CommandID = "foreign"
			case "wrong action":
				c.Action = "start"
			case "wrong hash":
				c.RequestSHA = strings.Repeat("0", 64)
			case "expired":
				now = g.ExpiresAt
			case "disabled":
				enabled = false
			case "new demand":
				current = false
			}
			r, err := Redeem(&g, p, c, now, enabled, current)
			if name == "valid" {
				if err != nil || r.Mode != "execute_once" {
					t.Fatalf("valid: %v %+v", err, r)
				}
				r, err = Redeem(&g, p, c, now, true, true)
				if err != nil || r.Mode != "read_only" {
					t.Fatal("duplicate obtained send")
				}
				return
			}
			if err == nil && r.Mode == "execute_once" {
				t.Fatal("invalid claim obtained send")
			}
		})
	}
}
func TestExecutorPowerOriginalSettlementAndReadback(t *testing.T) {
	g, now := grantFixture(t, "start")
	c := claimFor(g)
	_, err := Redeem(&g, g.Binding.AdapterPrincipal, c, now, true, true)
	if err != nil {
		t.Fatal(err)
	}
	o := Observation{Resource: g.Binding.Resource, State: "running", ObservedAt: now, WorkerReady: true, BootID: "qualified-boot"}
	if Confirm(&g, o, now) == nil {
		t.Fatal("readback alone settled original send")
	}
	r := Result{GrantID: g.ID, AttemptID: c.AttemptID, RequestSHA: g.RequestSHA, Outcome: "uncertain", OriginalJoined: true}
	if err = Settle(&g, g.Binding.AdapterPrincipal, strings.Repeat("t", 32), r, now); err != nil {
		t.Fatal(err)
	}
	if Confirm(&g, o, now) == nil {
		t.Fatal("uncertainty released")
	}
	if rr, e := Redeem(&g, g.Binding.AdapterPrincipal, c, g.ExpiresAt.Add(time.Hour), true, true); e != nil || rr.Mode != "read_only" {
		t.Fatal("unknown send retried")
	}
	r.Outcome = "accepted"
	r.ServiceRequestID = "aws-service-request"
	if Settle(&g, g.Binding.AdapterPrincipal, "wrong-token", r, now) == nil {
		t.Fatal("foreign settlement")
	}
	if err = Settle(&g, g.Binding.AdapterPrincipal, strings.Repeat("t", 32), r, now); err != nil {
		t.Fatal(err)
	}
	bad := o
	bad.Resource.Volumes = []string{"vol-11111111111111111"}
	if Confirm(&g, bad, now) == nil {
		t.Fatal("changed disks confirmed")
	}
	bad = o
	bad.WorkerReady = false
	if Confirm(&g, bad, now) == nil {
		t.Fatal("running without ready boot confirmed")
	}
	if err = Confirm(&g, o, now); err != nil || g.State != "confirmed" {
		t.Fatal(err)
	}
}

type fakeLedger struct {
	g    *Grant
	now  time.Time
	lost bool
}

func (f *fakeLedger) Redeem(_ context.Context, c Claim) (ClaimReply, error) {
	r, e := Redeem(f.g, f.g.Binding.AdapterPrincipal, c, f.now, true, true)
	if f.lost {
		return ClaimReply{}, errors.New("lost original response")
	}
	return r, e
}
func (f *fakeLedger) Settle(_ context.Context, token string, r Result) error {
	return Settle(f.g, f.g.Binding.AdapterPrincipal, token, r, f.now)
}

type fakeEC2 struct {
	calls  int
	action string
	fail   bool
	t      *testing.T
	want   Resource
}

func (f *fakeEC2) call(ctx context.Context, r Resource, action string) (string, error) {
	f.calls++
	f.action = action
	if !SameResource(r, f.want) {
		f.t.Fatal("wrong resource")
	}
	if _, ok := ctx.Deadline(); !ok {
		f.t.Fatal("unbounded provider context")
	}
	if f.fail {
		return "", errors.New("ambiguous network")
	}
	return "aws-request-original", nil
}
func (f *fakeEC2) StartInstances(ctx context.Context, r Resource) (string, error) {
	return f.call(ctx, r, "start")
}
func (f *fakeEC2) StopInstances(ctx context.Context, r Resource) (string, error) {
	return f.call(ctx, r, "stop")
}
func TestExecutorPowerAdapterMockSingleOriginalSend(t *testing.T) {
	for _, action := range []string{"start", "stop"} {
		t.Run(action, func(t *testing.T) {
			g, now := grantFixture(t, action)
			ledger := &fakeLedger{g: &g, now: now}
			provider := &fakeEC2{t: t, want: g.Binding.Resource}
			a := Adapter{Enabled: true, Binding: g.Binding, Ledger: ledger, EC2: provider, Now: func() time.Time { return now }}
			if err := a.Execute(context.Background(), g, attemptID, strings.Repeat("t", 32)); err != nil {
				t.Fatal(err)
			}
			if provider.calls != 1 || provider.action != action {
				t.Fatal("wrong send")
			}
			_ = a.Execute(context.Background(), g, attemptID, strings.Repeat("t", 32))
			if provider.calls != 1 {
				t.Fatal("duplicate send")
			}
		})
	}
}
func TestExecutorPowerAdapterUnknownAndLostClaimHold(t *testing.T) {
	for _, lost := range []bool{false, true} {
		g, now := grantFixture(t, "stop")
		ledger := &fakeLedger{g: &g, now: now, lost: lost}
		provider := &fakeEC2{t: t, want: g.Binding.Resource, fail: true}
		a := Adapter{Enabled: true, Binding: g.Binding, Ledger: ledger, EC2: provider, Now: func() time.Time { return now }}
		if err := a.Execute(context.Background(), g, attemptID, strings.Repeat("t", 32)); !errors.Is(err, ErrUnknown) {
			t.Fatal(err)
		}
		before := provider.calls
		_ = a.Execute(context.Background(), g, attemptID, strings.Repeat("t", 32))
		if provider.calls != before {
			t.Fatal("unknown result retried")
		}
		if lost && before != 0 {
			t.Fatal("lost claim sent")
		}
	}
}
