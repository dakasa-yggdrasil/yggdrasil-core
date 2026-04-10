package model

import "time"

// WorkflowDispatchOperation is the canonical operation used to dispatch one workflow run through an integration.
const WorkflowDispatchOperation = "dispatch_workflow"

// WorkflowManifestSpec defines one orchestration workflow stored in the core.
type WorkflowManifestSpec struct {
	Trigger     WorkflowTriggerSpec     `json:"trigger,omitempty"`
	InputSchema WorkflowInputSchemaSpec `json:"input_schema,omitempty"`
	Defaults    map[string]any          `json:"defaults,omitempty"`
	Steps       []WorkflowStepSpec      `json:"steps"`
}

// WorkflowTriggerSpec describes how a workflow can be started.
// Mode is one of: "manual", "schedule", "event". When Mode is "schedule",
// the Schedule sub-object is required. When Mode is "event", the Event
// sub-object is required. Manual mode uses neither.
type WorkflowTriggerSpec struct {
	Mode     string                     `json:"mode,omitempty"`
	Enabled  *bool                      `json:"enabled,omitempty"`
	Schedule *WorkflowScheduleTriggerSpec `json:"schedule,omitempty"`
	Event    *WorkflowEventTriggerSpec    `json:"event,omitempty"`
}

// WorkflowScheduleTriggerSpec configures a cron-based scheduled trigger.
// The core scheduler addon fires this workflow at each tick matching the
// cron expression (in the configured timezone). CatchupPolicy controls what
// happens when the scheduler catches up after downtime: "skip" (default)
// fires only the next tick; "catch_up" fires every missed tick.
type WorkflowScheduleTriggerSpec struct {
	CronExpression string         `json:"cron_expression"`
	Timezone       string         `json:"timezone,omitempty"`
	StartAt        string         `json:"start_at,omitempty"`
	EndAt          string         `json:"end_at,omitempty"`
	CatchupPolicy  string         `json:"catchup_policy,omitempty"`
	DefaultInputs  map[string]any `json:"default_inputs,omitempty"`
}

// WorkflowEventTriggerSpec configures an event-driven trigger. The core
// event subscription loop watches the event stream (see Gap 1) and fires
// the workflow when events matching Types + AggregateFilter + PayloadFilters
// are emitted. Debounce consolidates bursts of matching events into a single
// dispatch.
type WorkflowEventTriggerSpec struct {
	Types           []string                `json:"types"`
	AggregateFilter *WorkflowEventAggregateFilter `json:"aggregate_filter,omitempty"`
	PayloadFilters  []WorkflowEventPayloadFilter  `json:"payload_filters,omitempty"`
	DebounceSeconds int                     `json:"debounce_seconds,omitempty"`
	DefaultInputs   map[string]any          `json:"default_inputs,omitempty"`
}

// WorkflowEventAggregateFilter scopes an event trigger by aggregate type
// and/or name pattern (glob).
type WorkflowEventAggregateFilter struct {
	AggregateType string `json:"aggregate_type,omitempty"`
	NamePattern   string `json:"name_pattern,omitempty"`
}

// WorkflowEventPayloadFilter is a single condition over an event's payload.
// Path is a dotted key lookup; Operator is one of eq/neq/in/not_in/contains/
// matches; Value is the comparison target (typed at JSON level).
type WorkflowEventPayloadFilter struct {
	Path     string      `json:"path"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// WorkflowInputSchemaSpec validates runtime inputs passed to a workflow run.
type WorkflowInputSchemaSpec struct {
	Required   []string                             `json:"required,omitempty"`
	Properties map[string]IntegrationSchemaProperty `json:"properties,omitempty"`
}

// WorkflowStepSpec defines one ordered step inside a workflow.
type WorkflowStepSpec struct {
	ID             string              `json:"id"`
	Description    string              `json:"description,omitempty"`
	Use            WorkflowStepUseSpec `json:"use"`
	With           map[string]any      `json:"with,omitempty"`
	DependsOn      []string            `json:"depends_on,omitempty"`
	Retry          WorkflowRetrySpec   `json:"retry,omitempty"`
	TimeoutSeconds int                 `json:"timeout_seconds,omitempty"`
}

// WorkflowStepUseSpec declares how one step is executed.
type WorkflowStepUseSpec struct {
	Kind        string            `json:"kind"`
	InstanceRef *ManifestSelector `json:"instance_ref,omitempty"`
	Capability  string            `json:"capability,omitempty"`
	Operation   string            `json:"operation,omitempty"`
}

// WorkflowRetrySpec configures retries for one step.
type WorkflowRetrySpec struct {
	MaxAttempts    int `json:"max_attempts,omitempty"`
	BackoffSeconds int `json:"backoff_seconds,omitempty"`
}

// RunWorkflowRequest asks the core to execute one stored workflow definition.
type RunWorkflowRequest struct {
	Workflow ManifestSelector     `json:"workflow"`
	Inputs   map[string]any       `json:"inputs,omitempty"`
	Auth     WorkflowDispatchAuth `json:"auth,omitempty"`
	Metadata map[string]any       `json:"metadata,omitempty"`
}

// WorkflowRunStepResult captures the result of one workflow step.
type WorkflowRunStepResult struct {
	ID                  string             `json:"id"`
	Kind                string             `json:"kind"`
	Operation           string             `json:"operation,omitempty"`
	Capability          string             `json:"capability,omitempty"`
	Status              string             `json:"status"`
	Attempts            int                `json:"attempts,omitempty"`
	Error               string             `json:"error,omitempty"`
	Metadata            map[string]any     `json:"metadata,omitempty"`
	IntegrationInstance *ManifestReference `json:"integration_instance,omitempty"`
	IntegrationType     *ManifestReference `json:"integration_type,omitempty"`
	StartedAt           time.Time          `json:"started_at"`
	FinishedAt          time.Time          `json:"finished_at"`
}

// RunWorkflowResponse returns the step-by-step outcome of one workflow run.
type RunWorkflowResponse struct {
	Workflow   ManifestReference       `json:"workflow"`
	Status     string                  `json:"status"`
	Steps      []WorkflowRunStepResult `json:"steps"`
	Metadata   map[string]any          `json:"metadata,omitempty"`
	StartedAt  time.Time               `json:"started_at"`
	FinishedAt time.Time               `json:"finished_at"`
}

// WorkflowDispatchAuth carries transitional caller credentials used during dispatch.
type WorkflowDispatchAuth struct {
	Token string `json:"token,omitempty"`
}

// WorkflowDispatchSpec describes one workflow run request.
type WorkflowDispatchSpec struct {
	ComponentID string         `json:"component_id,omitempty"`
	Repository  string         `json:"repository"`
	Workflow    string         `json:"workflow"`
	Ref         string         `json:"ref,omitempty"`
	Inputs      map[string]any `json:"inputs,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// DispatchWorkflowRequest asks the core to dispatch one workflow through a configured integration instance.
type DispatchWorkflowRequest struct {
	Runner     ManifestSelector     `json:"runner"`
	Operation  string               `json:"operation,omitempty"`
	Capability string               `json:"capability,omitempty"`
	Workflow   WorkflowDispatchSpec `json:"workflow"`
	Auth       WorkflowDispatchAuth `json:"auth,omitempty"`
}

// DispatchWorkflowResponse returns the normalized dispatch result.
type DispatchWorkflowResponse struct {
	Operation       string               `json:"operation"`
	Status          string               `json:"status"`
	Runner          ManifestReference    `json:"runner"`
	IntegrationType ManifestReference    `json:"integration_type"`
	Workflow        WorkflowDispatchSpec `json:"workflow"`
	Metadata        map[string]any       `json:"metadata,omitempty"`
}

// AdapterDispatchWorkflowIntegrationContext gives the adapter the resolved integration manifests it needs.
type AdapterDispatchWorkflowIntegrationContext struct {
	Type         ManifestReference               `json:"type"`
	TypeSpec     IntegrationTypeManifestSpec     `json:"type_spec"`
	Instance     ManifestReference               `json:"instance"`
	InstanceSpec IntegrationInstanceManifestSpec `json:"instance_spec"`
}

// AdapterDispatchWorkflowRequest is sent to an integration execute queue to dispatch one workflow.
type AdapterDispatchWorkflowRequest struct {
	Operation   string                                    `json:"operation"`
	Capability  string                                    `json:"capability,omitempty"`
	Workflow    WorkflowDispatchSpec                      `json:"workflow"`
	Auth        WorkflowDispatchAuth                      `json:"auth,omitempty"`
	Integration AdapterDispatchWorkflowIntegrationContext `json:"integration"`
}

// AdapterDispatchWorkflowResponse is returned by an integration after dispatching one workflow.
type AdapterDispatchWorkflowResponse struct {
	Operation string               `json:"operation,omitempty"`
	Status    string               `json:"status"`
	Workflow  WorkflowDispatchSpec `json:"workflow,omitempty"`
	Metadata  map[string]any       `json:"metadata,omitempty"`
}
