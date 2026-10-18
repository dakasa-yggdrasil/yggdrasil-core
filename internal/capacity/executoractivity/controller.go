package executoractivity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

type Job struct {
	TaskID string `json:"task_id"`
	Owner  string `json:"owner"`
	State  string `json:"state"`
	BootID string `json:"boot_id,omitempty"`
}
type ExactResource struct {
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
	InstanceID         string `json:"instance_id"`
	OwnershipBindingID string `json:"ownership_binding_id"`
}
type PowerBinding struct {
	Enabled        bool
	Resource       ExactResource
	AllowedActions []string
}
type PowerCommand struct {
	ID       string        `json:"id"`
	Action   string        `json:"action"`
	Resource ExactResource `json:"resource"`
	IssuedAt time.Time     `json:"issued_at"`
	Joined   bool          `json:"joined"`
	Result   string        `json:"result,omitempty"`
}
type PowerSnapshot struct {
	Resource   ExactResource
	State      string
	BootID     string
	ObservedAt time.Time
}
type PowerSettlement struct {
	CommandID                string
	Resource                 ExactResource
	Action                   string
	OriginalInvocationJoined bool
	State                    string
}
type WorkerSnapshot struct {
	Resource   ExactResource
	BootID     string
	ObservedAt time.Time
	Complete   bool
	Ready      bool
	Closed     bool
	Epoch      uint64
	Jobs       map[string]string
}

// PowerPort is a REQUIRED protected-authority boundary, not a raw EC2 client.
// Execute must redeem the existing Core power grant for this exact tuple and
// retain its original invocation/return. No production implementation is supplied:
// legacy ensure/destroy grants do not qualify power start/stop. A default-off
// repository port now uses explicit operator adoption and distinct ledger grants;
// qualified provider/worker factories remain uninstalled. Tags do not
// establish OwnershipBindingID. Observe/Settlement must independently verify it.
type PowerPort interface {
	Observe(context.Context, ExactResource) (PowerSnapshot, error)
	Execute(context.Context, PowerCommand) error
	Settlement(context.Context, PowerCommand) (PowerSettlement, error)
}

// WorkerPort must bridge the source-owned SDK admission/lifetime contract. It
// must durably dedupe Admit by job ID, fence Close by epoch, and retain completed
// jobs until the controller records them. Complete includes all child processes;
// an empty process list alone is insufficient. Only fakes are implemented here.
type WorkerPort interface {
	Observe(context.Context, ExactResource) (WorkerSnapshot, error)
	Close(context.Context, ExactResource, uint64) error
	Open(context.Context, ExactResource, uint64) error
	Admit(context.Context, ExactResource, string, uint64, string) error
}

// Change must use the existing protected PostgreSQL transaction and DB clock.
// It cannot be a local JSON file or an unguarded production in-memory store.
type Transactions interface {
	Change(context.Context, func(*ExecutorActivityState, time.Time) error) (ExecutorActivityState, error)
}

// Controller is one bounded reconcile pass to be called by the existing external
// dispatcher. It has no ticker/server/startup registration and defaults off.
type Controller struct {
	Binding      PowerBinding
	Policy       ExecutorActivityPolicy
	Transactions Transactions
	Power        PowerPort
	Worker       WorkerPort
}

func QueueJob(s *ExecutorActivityState, p ExecutorActivityPolicy, taskID, jobID, owner string, now time.Time) error {
	lease, ok := s.Tasks[taskID]
	if !ok || lease.Owner != owner || lease.Released || !lease.ExpiresAt.After(now) || !activityID(jobID) {
		return fmt.Errorf("current owned task lease required for job")
	}
	if old, exists := s.Jobs[jobID]; exists {
		if old.TaskID != taskID || old.Owner != owner {
			return fmt.Errorf("job identity conflict")
		}
		return nil
	}
	if len(s.Jobs) >= p.MaxTasks {
		return fmt.Errorf("job ledger exhausted")
	}
	if s.Jobs == nil {
		s.Jobs = map[string]Job{}
	}
	s.Jobs[jobID] = Job{TaskID: taskID, Owner: owner, State: "queued"}
	s.DemandChangedAt = now
	s.IdleSince = time.Time{}
	s.QuietObservedAt = time.Time{}
	if s.Stop != nil && s.Stop.Stage == "draining" {
		if s.Epoch == ^uint64(0) {
			return fmt.Errorf("epoch exhausted")
		}
		s.Epoch++
		s.Stop = nil
	}
	return nil
}

func (c Controller) Reconcile(ctx context.Context) (string, error) {
	if !c.Binding.Enabled || c.Transactions == nil || c.Power == nil || c.Worker == nil {
		return "disabled", fmt.Errorf("executor controller disabled or unbound")
	}
	if err := validatePowerBinding(c.Binding); err != nil {
		return "hold", err
	}
	s, err := c.Transactions.Change(ctx, func(s *ExecutorActivityState, _ time.Time) error {
		if s.PinnedPolicy != nil && *s.PinnedPolicy != c.Policy {
			return fmt.Errorf("controller policy mismatch")
		}
		if s.BoundResource != nil && *s.BoundResource != c.Binding.Resource {
			return fmt.Errorf("executor resource binding changed")
		}
		if s.BoundResource == nil {
			r := c.Binding.Resource
			s.BoundResource = &r
		}
		return nil
	})
	if err != nil {
		return "hold", err
	}
	if s.PinnedPolicy == nil || *s.PinnedPolicy != c.Policy {
		return "hold", fmt.Errorf("controller differs from operator activity policy")
	}
	observed, err := c.Power.Observe(ctx, c.Binding.Resource)
	if err != nil || observed.Resource != c.Binding.Resource {
		return "hold", fmt.Errorf("exact provider observation unavailable")
	}
	// The provider read happened after the preceding DB clock. Use a new DB
	// timestamp, so ordinary IO latency cannot look like future evidence.
	s, err = c.Transactions.Change(ctx, func(_ *ExecutorActivityState, now time.Time) error {
		if !runtimeFresh(observed.ObservedAt, now, c.Policy) {
			return fmt.Errorf("provider observation expired or future")
		}
		return nil
	})
	if err != nil {
		return "hold", err
	}
	if s.Power != nil {
		cmd := *s.Power
		if cmd.Resource != c.Binding.Resource {
			return "recovery_pending", fmt.Errorf("pending command resource changed")
		}
		settled, e := c.Power.Settlement(ctx, cmd)
		goal := "running"
		if cmd.Action == "stop" {
			goal = "stopped"
		}
		if settled.State == "rejected_no_effect" {
			goal = "stopped"
			if cmd.Action == "stop" {
				goal = "running"
			}
		}
		if e != nil || settled.CommandID != cmd.ID || settled.Resource != cmd.Resource || settled.Action != cmd.Action || !settled.OriginalInvocationJoined || (settled.State != "succeeded" && settled.State != "rejected_no_effect") || observed.State != goal || observed.ObservedAt.Before(cmd.IssuedAt) {
			return "recovery_pending", nil
		}
		_, err = c.Transactions.Change(ctx, func(current *ExecutorActivityState, now time.Time) error {
			if !runtimeFresh(observed.ObservedAt, now, c.Policy) {
				return fmt.Errorf("settlement observation expired")
			}
			if current.Power == nil || current.Power.ID != cmd.ID {
				return ErrExecutorActivityConflict
			}
			if current.PowerHistory == nil {
				current.PowerHistory = map[string]PowerCommand{}
			}
			if len(current.PowerHistory) >= c.Policy.MaxTasks {
				return fmt.Errorf("power history exhausted")
			}
			cmd.Joined = true
			cmd.Result = settled.State
			current.PowerHistory[cmd.ID] = cmd
			current.Power = nil
			if cmd.Action == "stop" {
				if current.Epoch == ^uint64(0) {
					return fmt.Errorf("epoch exhausted")
				}
				current.Epoch++
				current.Stop = nil
				current.IdleSince = time.Time{}
				current.QuietObservedAt = time.Time{}
			}
			return nil
		})
		return "settled", err
	}
	if s.Stop != nil && s.Stop.Stage == "possible_send" {
		return "recovery_pending", nil
	} // no fabricated command adoption
	demand := ExecutorActiveTasks(s, s.UpdatedAt) > 0 || activeJobs(s) > 0
	if demand && observed.State == "stopped" {
		return c.send(ctx, "start", PowerCommand{}, func(current *ExecutorActivityState, now time.Time) error {
			if !runtimeFresh(observed.ObservedAt, now, c.Policy) {
				return fmt.Errorf("start observation expired")
			}
			if current.Stop != nil || (ExecutorActiveTasks(*current, now) == 0 && activeJobs(*current) == 0) {
				return ErrExecutorActivityConflict
			}
			return nil
		})
	}
	if observed.State != "running" {
		return "waiting_provider", nil
	}
	w, err := c.Worker.Observe(ctx, c.Binding.Resource)
	if err != nil || !w.Complete || w.Resource != observed.Resource || w.BootID == "" || w.BootID != observed.BootID {
		_, writeErr := c.Transactions.Change(ctx, func(current *ExecutorActivityState, now time.Time) error {
			return ObserveExecutorQuiet(current, c.Policy, ExecutorActivityObservation{}, now)
		})
		return "inventory_unknown", writeErr
	}
	s, err = c.Transactions.Change(ctx, func(current *ExecutorActivityState, now time.Time) error {
		if !validWorker(w, observed, now, c.Policy) {
			return fmt.Errorf("worker observation expired")
		}
		for id, job := range current.Jobs {
			if job.State == "queued" || job.State == "finished" {
				continue
			}
			state, ok := w.Jobs[id]
			if !ok || job.BootID != w.BootID {
				return fmt.Errorf("owned job lifetime missing")
			}
			switch state {
			case "finished":
				job.State = "finished"
			case "running":
				job.State = "running"
			default:
				return fmt.Errorf("unknown worker job state")
			}
			current.Jobs[id] = job
		}
		return nil
	})
	if err != nil {
		return "hold", err
	}
	for id, job := range s.Jobs {
		if job.State != "queued" && job.State != "admitting" {
			continue
		}
		if !w.Ready {
			return "waiting_ready", nil
		}
		if w.Closed || w.Epoch != s.Epoch {
			return "opening_admission", c.Worker.Open(ctx, c.Binding.Resource, s.Epoch)
		}
		_, err = c.Transactions.Change(ctx, func(current *ExecutorActivityState, now time.Time) error {
			if !runtimeFresh(w.ObservedAt, now, c.Policy) {
				return fmt.Errorf("admission observation expired")
			}
			if current.Power != nil || current.Stop != nil {
				return ErrExecutorActivityConflict
			}
			j := current.Jobs[id]
			if j.State != "queued" && j.State != "admitting" {
				return ErrExecutorActivityConflict
			}
			j.State = "admitting"
			j.BootID = w.BootID
			current.Jobs[id] = j
			return nil
		})
		if err != nil {
			return "hold", err
		}
		// Job remains an independent durable shutdown blocker across any timeout.
		if err = c.Worker.Admit(ctx, c.Binding.Resource, id, s.Epoch, w.BootID); err != nil {
			return "admission_unknown", err
		}
		return "job_admitted", nil
	}
	active := 0
	for _, state := range w.Jobs {
		if state != "finished" {
			active++
		}
	}
	o := ExecutorActivityObservation{ObservedAt: w.ObservedAt, Epoch: w.Epoch, Complete: w.Complete, AdmissionClosed: w.Closed, ActiveJobs: active}
	if s.Stop == nil {
		_, err = c.Transactions.Change(ctx, func(current *ExecutorActivityState, now time.Time) error {
			if err := ObserveExecutorQuiet(current, c.Policy, o, now); err != nil {
				return err
			}
			if executorQuietReady(*current, c.Policy, o, now) {
				id, e := powerID()
				if e != nil {
					return e
				}
				return ReserveExecutorStop(current, c.Policy, id, o, now)
			}
			return nil
		})
		return "observed", err
	}
	if !w.Closed || w.Epoch != s.Stop.Epoch {
		return "draining", c.Worker.Close(ctx, c.Binding.Resource, s.Stop.Epoch)
	}
	return c.send(ctx, "stop", PowerCommand{ID: s.Stop.ID}, func(current *ExecutorActivityState, now time.Time) error {
		return MarkExecutorStopPossibleSend(current, c.Policy, s.Stop.ID, o, now)
	})
}

func (c Controller) send(ctx context.Context, action string, cmd PowerCommand, prepare func(*ExecutorActivityState, time.Time) error) (string, error) {
	if cmd.ID == "" {
		id, err := powerID()
		if err != nil {
			return "hold", err
		}
		cmd.ID = id
	}
	cmd.Action = action
	cmd.Resource = c.Binding.Resource
	_, err := c.Transactions.Change(ctx, func(s *ExecutorActivityState, now time.Time) error {
		if len(s.PowerHistory) >= c.Policy.MaxTasks {
			return fmt.Errorf("power history exhausted before send")
		}
		if s.Power != nil || s.PowerHistory[cmd.ID].ID != "" {
			return ErrExecutorActivityConflict
		}
		if err := prepare(s, now); err != nil {
			return err
		}
		cmd.IssuedAt = now
		s.Power = &cmd
		return nil
	})
	if err != nil {
		return "hold", err
	}
	// A failed/ambiguous Execute never clears the durable possible-send marker.
	return action + "_requested", c.Power.Execute(ctx, cmd)
}

func activeJobs(s ExecutorActivityState) int {
	n := 0
	for _, j := range s.Jobs {
		if j.State != "finished" {
			n++
		}
	}
	return n
}
func runtimeFresh(at, now time.Time, p ExecutorActivityPolicy) bool {
	return !at.IsZero() && !at.After(now) && now.Sub(at) <= p.MaxObservationAge
}
func validWorker(w WorkerSnapshot, power PowerSnapshot, now time.Time, p ExecutorActivityPolicy) bool {
	return w.Complete && w.Resource == power.Resource && w.BootID != "" && w.BootID == power.BootID && runtimeFresh(w.ObservedAt, now, p)
}
func powerID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
func validatePowerBinding(b PowerBinding) error {
	r := b.Resource
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(r.AccountID) || !regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+$`).MatchString(r.Region) || !regexp.MustCompile(`^i-[a-f0-9]{17}$`).MatchString(r.InstanceID) || !activityID(r.OwnershipBindingID) || len(b.AllowedActions) != 2 {
		return fmt.Errorf("exact operator power binding required")
	}
	seen := map[string]bool{}
	for _, a := range b.AllowedActions {
		if (a != "start" && a != "stop") || seen[a] {
			return fmt.Errorf("only start/stop allowed")
		}
		seen[a] = true
	}
	return nil
}
func validateRuntimeState(s ExecutorActivityState, p ExecutorActivityPolicy, now time.Time) error {
	if s.BoundResource != nil {
		if err := validatePowerBinding(PowerBinding{Resource: *s.BoundResource, AllowedActions: []string{"start", "stop"}}); err != nil {
			return err
		}
	}
	if len(s.Jobs) > p.MaxTasks || len(s.PowerHistory) > p.MaxTasks {
		return fmt.Errorf("runtime ledger exhausted")
	}
	for id, j := range s.Jobs {
		if !activityID(id) || !activityID(j.TaskID) || !activityID(j.Owner) || (j.State != "queued" && j.State != "admitting" && j.State != "running" && j.State != "finished") {
			return fmt.Errorf("invalid job record")
		}
		lease, ok := s.Tasks[j.TaskID]
		if !ok || lease.Owner != j.Owner || (j.State != "queued" && j.BootID == "") {
			return fmt.Errorf("job owner/lifetime missing")
		}
	}
	if s.Power != nil {
		cmd := s.Power
		if !activityID(cmd.ID) || (cmd.Action != "start" && cmd.Action != "stop") || cmd.IssuedAt.IsZero() || cmd.IssuedAt.After(now) || cmd.Joined {
			return fmt.Errorf("invalid pending power command")
		}
		if s.BoundResource == nil || cmd.Resource != *s.BoundResource || cmd.Result != "" {
			return fmt.Errorf("pending power binding missing")
		}
	}
	for id, cmd := range s.PowerHistory {
		if !activityID(id) || id != cmd.ID || !cmd.Joined || (cmd.Action != "start" && cmd.Action != "stop") || cmd.IssuedAt.IsZero() || cmd.IssuedAt.After(now) || (cmd.Result != "succeeded" && cmd.Result != "rejected_no_effect") || s.BoundResource == nil || cmd.Resource != *s.BoundResource {
			return fmt.Errorf("invalid power history")
		}
	}
	return nil
}
