package executoractivity

import "time"

// WorkflowResult is bounded independently of the durable task roster. No task
// identities or lease owners are projected into subsequent workflow templates.
// DemandPending is a wake signal, never permission to invoke a provider.
type WorkflowResult struct {
	Revision         uint64                   `json:"revision"`
	Epoch            uint64                   `json:"epoch"`
	ActiveTasks      int                      `json:"active_tasks"`
	ActiveJobs       int                      `json:"active_jobs"`
	Power            *PowerCommand            `json:"power,omitempty"`
	DemandPending    bool                     `json:"demand_pending"`
	Stop             *ExecutorStopReservation `json:"stop,omitempty"`
	RecoveryRequired bool                     `json:"recovery_required"`
	RecoveryDeadline *time.Time               `json:"recovery_deadline,omitempty"`
}

func ResultFor(s ExecutorActivityState, p ExecutorActivityPolicy, now time.Time) WorkflowResult {
	r := WorkflowResult{Revision: s.Revision, Epoch: s.Epoch, ActiveTasks: ExecutorActiveTasks(s, now), DemandPending: ExecutorDemandPending(s, now)}
	r.ActiveJobs = activeJobs(s)
	if s.Stop != nil {
		stop := *s.Stop
		r.Stop = &stop
		deadline := stop.CreatedAt.Add(p.IdleAfter)
		r.RecoveryDeadline = &deadline
		r.RecoveryRequired = !now.Before(deadline)
	}
	if s.Power != nil {
		cmd := *s.Power
		r.Power = &cmd
		deadline := cmd.IssuedAt.Add(p.IdleAfter)
		r.RecoveryDeadline = &deadline
		r.RecoveryRequired = !now.Before(deadline)
	}
	return r
}
