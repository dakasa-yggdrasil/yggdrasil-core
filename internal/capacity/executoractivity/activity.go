package executoractivity

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Executor activity is demand and a shutdown prerequisite, not provider authority
// or a second autoscaler. The protected workflow must still obtain its normal
// mutation grant. No process, goroutine, timer or provider client is started here.
var ErrExecutorActivityConflict = errors.New("executor activity revision conflict")

type ExecutorActivityPolicy struct {
	LeaseTTL          time.Duration
	IdleAfter         time.Duration
	MaxObservationAge time.Duration
	MaxTasks          int // Includes tombstones; fail closed rather than forget replay protection.
}

type ExecutorTaskLease struct {
	Owner     string    `json:"owner"`
	Sequence  uint64    `json:"sequence"`
	ExpiresAt time.Time `json:"expires_at"`
	Released  bool      `json:"released"`
}

type ExecutorStopReservation struct {
	ID        string    `json:"id"`
	Epoch     uint64    `json:"epoch"`
	Stage     string    `json:"stage"` // draining or possible_send; unknown never expires into authority.
	CreatedAt time.Time `json:"created_at"`
	SendAt    time.Time `json:"send_at,omitempty"`
}

// Persist this whole value with CAS in the external control plane, never on the
// executor being stopped. Missing/corrupt storage is an error, not an idle pool.
type ExecutorActivityState struct {
	Revision        uint64                       `json:"revision"`
	UpdatedAt       time.Time                    `json:"updated_at"`
	IdleSince       time.Time                    `json:"idle_since,omitempty"`
	DemandChangedAt time.Time                    `json:"demand_changed_at,omitempty"`
	QuietObservedAt time.Time                    `json:"quiet_observed_at,omitempty"`
	Epoch           uint64                       `json:"epoch"`
	Tasks           map[string]ExecutorTaskLease `json:"tasks"`
	Stop            *ExecutorStopReservation     `json:"stop,omitempty"`
	Jobs            map[string]Job               `json:"jobs,omitempty"`
	Power           *PowerCommand                `json:"power,omitempty"`
	PowerHistory    map[string]PowerCommand      `json:"power_history,omitempty"`
	BoundResource   *ExactResource               `json:"bound_resource,omitempty"`
	PinnedPolicy    *ExecutorActivityPolicy      `json:"pinned_policy,omitempty"`
}

// Each run needs a unique TaskID and stable authenticated Owner. Sequence starts
// at 1; duplicate/lower sequences cannot extend a lease. Expired/released task IDs
// cannot be reused. A new run acquires a new ID instead of resurrecting old work.
type ExecutorActivityEvent struct {
	TaskID   string `json:"task_id"`
	Owner    string `json:"owner,omitempty"`
	Sequence uint64 `json:"sequence"`
	Release  bool   `json:"release"`
}

// Inventory must cover all builds, tests, subprocesses and queued/dispatched jobs,
// independently of the AI heartbeat. AdmissionClosed acknowledges the exact drain
// epoch at the worker; CPU idle or a disconnected agent cannot supply this proof.
type ExecutorActivityObservation struct {
	ObservedAt      time.Time `json:"observed_at"`
	Epoch           uint64    `json:"epoch"`
	Complete        bool      `json:"complete"`
	AdmissionClosed bool      `json:"admission_closed"`
	ActiveJobs      int       `json:"active_jobs"`
}

// Implementations must atomically compare Revision, persist before returning, and
// distinguish a deliberately initialized empty state from missing/lost data.
// This interface intentionally has no in-memory production fallback.
type ExecutorActivityStore interface {
	Load(context.Context, string) (ExecutorActivityState, error)
	CompareAndSwap(context.Context, string, uint64, ExecutorActivityState) error
}

// UpdateExecutorActivity is one bounded durable transaction. A conflict is returned
// to the existing dispatcher for reload/re-evaluation, never a provider retry.
// now is trusted control-plane time, not an agent-supplied heartbeat timestamp.
func UpdateExecutorActivity(ctx context.Context, store ExecutorActivityStore, scope string, p ExecutorActivityPolicy, now time.Time, change func(*ExecutorActivityState) error) (ExecutorActivityState, error) {
	if store == nil || !activityID(scope) || change == nil {
		return ExecutorActivityState{}, fmt.Errorf("executor activity store/scope/change required")
	}
	s, err := store.Load(ctx, scope)
	if err != nil {
		return ExecutorActivityState{}, err
	}
	if err = validateExecutorActivity(s, p, now); err != nil {
		return ExecutorActivityState{}, err
	}
	// Copy before invoking a reducer: failed changes cannot mutate a store's view.
	next := s
	if s.PinnedPolicy == nil {
		policy := p
		next.PinnedPolicy = &policy
	} else {
		policy := *s.PinnedPolicy
		next.PinnedPolicy = &policy
	}
	next.Tasks = make(map[string]ExecutorTaskLease, len(s.Tasks))
	for k, v := range s.Tasks {
		next.Tasks[k] = v
	}
	if s.Stop != nil {
		stop := *s.Stop
		next.Stop = &stop
	}
	next.Jobs = make(map[string]Job, len(s.Jobs))
	for k, v := range s.Jobs {
		next.Jobs[k] = v
	}
	next.PowerHistory = make(map[string]PowerCommand, len(s.PowerHistory))
	for k, v := range s.PowerHistory {
		next.PowerHistory[k] = v
	}
	if s.Power != nil {
		power := *s.Power
		next.Power = &power
	}
	if s.BoundResource != nil {
		resource := *s.BoundResource
		next.BoundResource = &resource
	}
	if err = change(&next); err != nil {
		return ExecutorActivityState{}, err
	}
	next.Revision, next.UpdatedAt = s.Revision+1, now
	if err = validateExecutorActivity(next, p, now); err != nil {
		return ExecutorActivityState{}, err
	}
	if err = ctx.Err(); err != nil {
		return ExecutorActivityState{}, err
	}
	if err = store.CompareAndSwap(ctx, scope, s.Revision, next); err != nil {
		return ExecutorActivityState{}, err
	}
	return next, nil
}

func ApplyExecutorActivity(s *ExecutorActivityState, p ExecutorActivityPolicy, e ExecutorActivityEvent, now time.Time) error {
	if err := validateExecutorActivity(*s, p, now); err != nil {
		return err
	}
	if !activityID(e.TaskID) || !activityID(e.Owner) || e.Sequence == 0 {
		return fmt.Errorf("executor task identity/sequence required")
	}
	old, exists := s.Tasks[e.TaskID]
	if exists && old.Owner != e.Owner {
		return fmt.Errorf("executor task owner mismatch")
	}
	if exists && e.Sequence <= old.Sequence {
		return nil // Retry cannot prolong demand or revive a released task.
	}
	if !exists && (e.Release || e.Sequence != 1 || len(s.Tasks) >= p.MaxTasks) {
		return fmt.Errorf("executor task acquisition refused")
	}
	if exists && (old.Released || !old.ExpiresAt.After(now)) {
		return fmt.Errorf("executor task lease ended; acquire a new run ID")
	}
	if s.Tasks == nil {
		s.Tasks = make(map[string]ExecutorTaskLease)
	}
	s.Tasks[e.TaskID] = ExecutorTaskLease{Owner: e.Owner, Sequence: e.Sequence, ExpiresAt: now.Add(p.LeaseTTL), Released: e.Release}
	s.DemandChangedAt = now
	s.IdleSince = time.Time{} // Require a new observed quiet window, even on release.
	s.QuietObservedAt = time.Time{}
	if s.Stop != nil && s.Stop.Stage == "draining" && !e.Release {
		// A demand transaction wins over a stop not yet committed. A sender with
		// the old revision/ticket must lose CAS and cannot use its stale grant.
		if s.Epoch == math.MaxUint64 {
			return fmt.Errorf("executor epoch exhausted")
		}
		s.Epoch++
		s.Stop = nil
	}
	// possible_send stays fenced: demand is queued, never admitted until settlement.
	return nil
}

func ExecutorActiveTasks(s ExecutorActivityState, now time.Time) int {
	n := 0
	for _, task := range s.Tasks {
		if !task.Released && task.ExpiresAt.After(now) {
			n++
		}
	}
	return n
}

// ObserveExecutorQuiet starts idle hysteresis only from complete fresh inventory.
// Unknown or busy resets the window; expired leases alone do not establish idle.
func ObserveExecutorQuiet(s *ExecutorActivityState, p ExecutorActivityPolicy, o ExecutorActivityObservation, now time.Time) error {
	if err := validateExecutorActivity(*s, p, now); err != nil {
		return err
	}
	if activeJobs(*s) > 0 || s.Power != nil || !executorObservationFresh(o, p, now) || ExecutorActiveTasks(*s, now) > 0 || o.ActiveJobs != 0 || o.ObservedAt.Before(s.DemandChangedAt) {
		s.IdleSince = time.Time{}
		s.QuietObservedAt = time.Time{}
		return nil
	}
	if s.IdleSince.IsZero() || s.QuietObservedAt.IsZero() || o.ObservedAt.Sub(s.QuietObservedAt) > p.MaxObservationAge {
		s.IdleSince = o.ObservedAt
	}
	s.QuietObservedAt = o.ObservedAt
	return nil
}

// ReserveExecutorStop only requests an admission drain. It authorizes no EC2 call.
func ReserveExecutorStop(s *ExecutorActivityState, p ExecutorActivityPolicy, id string, o ExecutorActivityObservation, now time.Time) error {
	if err := validateExecutorActivity(*s, p, now); err != nil {
		return err
	}
	if s.Stop != nil || !activityID(id) || s.Epoch == math.MaxUint64 || !executorQuietReady(*s, p, o, now) {
		return fmt.Errorf("executor stop reservation refused")
	}
	s.Epoch++
	s.Stop = &ExecutorStopReservation{ID: id, Epoch: s.Epoch, Stage: "draining", CreatedAt: now}
	return nil
}

// MarkExecutorStopPossibleSend must be durably CAS-committed before the existing
// mutation authority sends anything. Only the winner gets this single attempt.
// Demand after commit remains queued; no start is permitted while outcome is unknown.
func MarkExecutorStopPossibleSend(s *ExecutorActivityState, p ExecutorActivityPolicy, id string, o ExecutorActivityObservation, now time.Time) error {
	if err := validateExecutorActivity(*s, p, now); err != nil {
		return err
	}
	if s.Stop == nil || s.Stop.ID != id || s.Stop.Stage != "draining" || !o.AdmissionClosed || o.Epoch != s.Stop.Epoch || o.ObservedAt.Before(s.Stop.CreatedAt) || !executorQuietReady(*s, p, o, now) {
		return fmt.Errorf("executor stop send refused")
	}
	s.Stop.Stage, s.Stop.SendAt = "possible_send", now
	return nil
}

func ExecutorDemandPending(s ExecutorActivityState, now time.Time) bool {
	return (ExecutorActiveTasks(s, now) > 0 || activeJobs(s) > 0) && s.Stop == nil && s.Power == nil
}

// The reducer never clears an unknown ticket by timeout. Controller settlement
// requires its protected original-return port and independent power readback.
// An EC2 timeout/crash cannot permit another send or reopen admission by itself.
func executorQuietReady(s ExecutorActivityState, p ExecutorActivityPolicy, o ExecutorActivityObservation, now time.Time) bool {
	return activeJobs(s) == 0 && s.Power == nil && ExecutorActiveTasks(s, now) == 0 && executorObservationFresh(o, p, now) && !o.ObservedAt.Before(s.DemandChangedAt) && o.ActiveJobs == 0 && !s.IdleSince.IsZero() && now.Sub(s.IdleSince) >= p.IdleAfter && !s.QuietObservedAt.IsZero() && now.Sub(s.QuietObservedAt) <= p.MaxObservationAge
}

func executorObservationFresh(o ExecutorActivityObservation, p ExecutorActivityPolicy, now time.Time) bool {
	return o.Complete && o.ActiveJobs >= 0 && !o.ObservedAt.IsZero() && !o.ObservedAt.After(now) && now.Sub(o.ObservedAt) <= p.MaxObservationAge
}

func validateExecutorActivity(s ExecutorActivityState, p ExecutorActivityPolicy, now time.Time) error {
	if s.PinnedPolicy != nil && *s.PinnedPolicy != p {
		return fmt.Errorf("executor activity policy changed")
	}
	if err := validateRuntimeState(s, p, now); err != nil {
		return err
	}
	if now.IsZero() || p.LeaseTTL < 5*time.Second || p.LeaseTTL > 5*time.Minute || p.IdleAfter < time.Second || p.IdleAfter > 24*time.Hour || p.MaxObservationAge < time.Second || p.MaxObservationAge > p.LeaseTTL || p.MaxTasks < 1 || p.MaxTasks > 100000 || s.Revision == math.MaxUint64 || s.DemandChangedAt.After(now) || s.UpdatedAt.After(now) || s.IdleSince.After(now) || s.QuietObservedAt.After(now) || (!s.IdleSince.IsZero() && (s.QuietObservedAt.IsZero() || s.QuietObservedAt.Before(s.IdleSince))) || len(s.Tasks) > p.MaxTasks {
		return fmt.Errorf("invalid executor activity policy/state/clock")
	}
	for id, task := range s.Tasks {
		if !activityID(id) || !activityID(task.Owner) || task.Sequence == 0 || task.ExpiresAt.IsZero() {
			return fmt.Errorf("invalid executor task state")
		}
	}
	if stop := s.Stop; stop != nil {
		if !activityID(stop.ID) || stop.Epoch == 0 || stop.Epoch != s.Epoch || stop.CreatedAt.IsZero() || stop.CreatedAt.After(now) || (stop.Stage != "draining" && stop.Stage != "possible_send") || (stop.Stage == "possible_send" && (stop.SendAt.Before(stop.CreatedAt) || stop.SendAt.After(now))) {
			return fmt.Errorf("invalid executor stop state")
		}
	}
	return nil
}

func activityID(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\t")
}
