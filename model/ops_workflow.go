package model

import "time"

type OpsWorkflowRun struct {
	RunID         string     `json:"run_id"`
	WorkflowName  string     `json:"workflow_name"`
	Integration   string     `json:"integration"`
	Status        string     `json:"status"`
	StartedAt     *time.Time `json:"started_at"`
	DurationMS    *int64     `json:"duration_ms"`
	TriggerSource string     `json:"trigger_source"`
	Error         string     `json:"error,omitempty"`
}

type OpsWorkflowsResponse struct {
	Runs       []OpsWorkflowRun `json:"runs"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type ListOpsWorkflowsFilter struct {
	Status      []string
	Integration string
	Search      string
	Limit       int
	Cursor      string
}
