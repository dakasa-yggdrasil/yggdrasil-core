package model

const (
	RemediationBundleKindWorkflowPatch          = "workflow_patch"
	RemediationBundleKindIntegrationComposition = "integration_composition"
	RemediationBundleKindEphemeralExecutor      = "ephemeral_executor"
)

const (
	RemediationBundleStatusProposed        = "proposed"
	RemediationBundleStatusPendingApproval = "pending_approval"
	RemediationBundleStatusApproved        = "approved"
	RemediationBundleStatusRejected        = "rejected"
	RemediationBundleStatusExecuting       = "executing"
	RemediationBundleStatusExecuted        = "executed"
	RemediationBundleStatusExecutionFailed = "execution_failed"
	RemediationBundleStatusExpired         = "expired"
)

type RemediationBundleExecutionSpec struct {
	AttemptedAt   string   `json:"attempted_at,omitempty"`
	CompletedAt   string   `json:"completed_at,omitempty"`
	Error         string   `json:"error,omitempty"`
	ExecutedSteps []string `json:"executed_steps,omitempty"`
}

type RemediationBundleReasonSpec struct {
	Kind       string         `json:"kind,omitempty"`
	Status     string         `json:"status,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Comment    string         `json:"comment,omitempty"`
	Source     string         `json:"source,omitempty"`
	Actor      string         `json:"actor,omitempty"`
	RecordedAt string         `json:"recorded_at,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type RemediationBundleStepSpec struct {
	Name               string                             `json:"name"`
	Mode               string                             `json:"mode"`
	Description        string                             `json:"description,omitempty"`
	BlastRadius        string                             `json:"blast_radius,omitempty"`
	WorkflowDispatch   *RemediationWorkflowDispatchSpec   `json:"workflow_dispatch,omitempty"`
	IntegrationExecute *RemediationIntegrationExecuteSpec `json:"integration_execute,omitempty"`
	Metadata           map[string]any                     `json:"metadata,omitempty"`
}

// RemediationBundleManifestSpec stores one generated hotfix executor that Heimdall
// may propose when no bounded built-in execute path is sufficient.
type RemediationBundleManifestSpec struct {
	GuardianRef        ManifestSelector               `json:"guardian_ref"`
	Status             string                         `json:"status,omitempty"`
	Source             string                         `json:"source,omitempty"`
	BundleKind         string                         `json:"bundle_kind"`
	Summary            string                         `json:"summary,omitempty"`
	ComponentKind      string                         `json:"component_kind,omitempty"`
	ComponentNamespace string                         `json:"component_namespace,omitempty"`
	ComponentName      string                         `json:"component_name,omitempty"`
	ExpiresAt          string                         `json:"expires_at"`
	TriggerAction      map[string]any                 `json:"trigger_action,omitempty"`
	Incident           map[string]any                 `json:"incident,omitempty"`
	CreationReason     *RemediationBundleReasonSpec   `json:"creation_reason,omitempty"`
	ApprovalDecision   *RemediationBundleReasonSpec   `json:"approval_decision,omitempty"`
	PromotionReview    *RemediationBundleReasonSpec   `json:"promotion_review,omitempty"`
	Steps              []RemediationBundleStepSpec    `json:"steps"`
	Execution          RemediationBundleExecutionSpec `json:"execution,omitempty"`
	Metadata           map[string]any                 `json:"metadata,omitempty"`
}
