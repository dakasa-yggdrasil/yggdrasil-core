package model

import (
	"time"

	"github.com/google/uuid"
)

// WorkflowDispatchOperation is the canonical operation used to dispatch one workflow run through an integration.
const WorkflowDispatchOperation = "dispatch_workflow"

// WorkflowManifestSpec defines one orchestration workflow stored in the core.
//
// DispatchMode controls the default behaviour of `POST /api/v1/workflow-runs`
// when the request does not explicitly opt into a mode. Allowed values are
// "sync" (block until the run finishes, return 201 + full RunWorkflowResponse;
// the historical default and still the default when the field is empty) and
// "async" (return 202 + {run_id, status: pending, workflow} immediately, run
// the workflow in a background goroutine, expose the final result via
// `GET /api/v1/workflow-runs/{run_id}`). Per-request overrides — the
// `?async=true|false` query parameter and the `X-Yggdrasil-Workflow-Mode`
// header — always win, so ops escapes still work regardless of the manifest
// value. Workflows whose observable step budgets exceed the ingress timeout
// (≈30s, e.g. `deploy-via-kustomize-source` with its 180s observe poll)
// should set this to "async" so legitimate callers see a 202 with a
// `run_id` instead of a 502 from the gateway.
type WorkflowManifestSpec struct {
	Trigger      WorkflowTriggerSpec     `json:"trigger,omitempty"`
	InputSchema  WorkflowInputSchemaSpec `json:"input_schema,omitempty"`
	Defaults     map[string]any          `json:"defaults,omitempty"`
	DispatchMode string                  `json:"dispatch_mode,omitempty"`
	Steps        []WorkflowStepSpec      `json:"steps"`
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
//
// The optional Condition field is evaluated before the step runs. When
// empty the step always runs. When set, the condition may use template
// references ({{ inputs.x }}, {{ steps.y.metadata.z }}) and two comparison
// operators: `==` and `!=` (with spaces around them). Without an operator
// the rendered value is evaluated for truthiness. A step whose condition
// evaluates to false is recorded with status "skipped" and downstream
// steps continue normally. A condition that fails to render (e.g.
// unresolvable template) fails the step fail-loud so broken workflows
// surface early.
type WorkflowStepSpec struct {
	ID             string                `json:"id"`
	Description    string                `json:"description,omitempty"`
	Condition      string                `json:"condition,omitempty"`
	Use            WorkflowStepUseSpec   `json:"use"`
	With           map[string]any        `json:"with,omitempty"`
	DependsOn      []string              `json:"depends_on,omitempty"`
	Retry          WorkflowRetrySpec     `json:"retry,omitempty"`
	TimeoutSeconds int                   `json:"timeout_seconds,omitempty"`
	ForEach        *WorkflowForEachSpec  `json:"for_each,omitempty"`
}

// WorkflowForEachSpec turns a step into a series of iterations driven by
// a slice resolved from `Items` (a workflow template). Each iteration
// gets a per-item execution context exposing `{{ each.<As> }}` to inner
// templates. The engine emits one WorkflowRunStepResult per iteration,
// with id `<step.id>[<index>]`, fail-fast on the first iteration error.
type WorkflowForEachSpec struct {
	Items string `json:"items"`
	As    string `json:"as"`
}

// WorkflowStepUseSpec declares how one step is executed. The target integration
// can be addressed in one of three resolution modes — exactly one is required:
//
//  1. InstanceRef — explicit pin to a concrete integration_instance. Used when
//     the workflow knows exactly which deployed instance to hit.
//  2. Family + Operation — contract-driven resolution. The runtime finds the
//     active integration_type whose family_ref matches Family and whose
//     implemented_operations contains Operation, then the active
//     integration_instance of that type. If more than one provider implements
//     the operation, resolution fails explicitly and the caller must pin via
//     ProviderRef.
//  3. Family + Operation + ProviderRef — same as (2) but pinned to one
//     provider, used as an escape hatch when the ambiguity above is intentional.
type WorkflowStepUseSpec struct {
	Kind        string            `json:"kind"`
	InstanceRef *ManifestSelector `json:"instance_ref,omitempty"`
	Family      string            `json:"family,omitempty"`
	ProviderRef *ManifestSelector `json:"provider_ref,omitempty"`
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

// WorkflowRunRecord persists one async workflow execution. The HTTP layer
// returns this shape from GET /api/v1/workflow-runs/{id}.
type WorkflowRunRecord struct {
	ID                uuid.UUID            `json:"id"`
	WorkflowNamespace string               `json:"workflow_namespace"`
	WorkflowName      string               `json:"workflow_name"`
	WorkflowVersion   *int                 `json:"workflow_version,omitempty"`
	Status            string               `json:"status"`
	Inputs            map[string]any       `json:"inputs,omitempty"`
	Metadata          map[string]any       `json:"metadata,omitempty"`
	Result            *RunWorkflowResponse `json:"result,omitempty"`
	Error             string               `json:"error,omitempty"`
	StartedAt         *time.Time           `json:"started_at,omitempty"`
	FinishedAt        *time.Time           `json:"finished_at,omitempty"`
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
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
