package model

const (
	RemediationContractActionModeWorkflowDispatch = "workflow_dispatch"
	RemediationContractActionModeIntegrationExecute = "integration_execute"
)

// RemediationContractManifestSpec declares which bounded remediation paths one component exposes.
type RemediationContractManifestSpec struct {
	ComponentKind      string                          `json:"component_kind"`
	ComponentNamespace string                          `json:"component_namespace,omitempty"`
	ComponentName      string                          `json:"component_name"`
	Actions            []RemediationContractActionSpec `json:"actions"`
	Metadata           map[string]any                  `json:"metadata,omitempty"`
}

// RemediationContractActionSpec declares one executable remediation action for one component.
type RemediationContractActionSpec struct {
	Name             string                           `json:"name"`
	Mode             string                           `json:"mode"`
	AutoExecute      bool                             `json:"auto_execute,omitempty"`
	WorkflowDispatch *RemediationWorkflowDispatchSpec `json:"workflow_dispatch,omitempty"`
	IntegrationExecute *RemediationIntegrationExecuteSpec `json:"integration_execute,omitempty"`
}

// RemediationWorkflowDispatchSpec dispatches a repository workflow as the remediation entrypoint.
type RemediationWorkflowDispatchSpec struct {
	Repository string         `json:"repository,omitempty"`
	Workflow   string         `json:"workflow,omitempty"`
	Ref        string         `json:"ref,omitempty"`
	Inputs     map[string]any `json:"inputs,omitempty"`
}

// RemediationIntegrationExecuteSpec calls another integration directly as the
// remediation entrypoint, enabling target-specific healing paths.
type RemediationIntegrationExecuteSpec struct {
	Integration ManifestSelector `json:"integration"`
	Operation   string           `json:"operation"`
	Capability  string           `json:"capability,omitempty"`
	Input       map[string]any   `json:"input,omitempty"`
}
