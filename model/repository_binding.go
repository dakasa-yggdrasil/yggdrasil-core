package model

// RepositoryBindingManifestSpec associates one ecosystem component with one source repository.
// Heimdall uses these bindings to observe custom repositories and to target bounded remediation
// actions such as workflow dispatches against the correct repo.
type RepositoryBindingManifestSpec struct {
	ComponentKind      string                          `json:"component_kind"`
	ComponentNamespace string                          `json:"component_namespace,omitempty"`
	ComponentName      string                          `json:"component_name"`
	Repository         string                          `json:"repository"`
	DefaultBranch      string                          `json:"default_branch,omitempty"`
	DeployWorkflow     string                          `json:"deploy_workflow,omitempty"`
	Automation         RepositoryBindingAutomationSpec `json:"automation,omitempty"`
	Metadata           map[string]any                  `json:"metadata,omitempty"`
}

// RepositoryBindingAutomationSpec declares what automated actions are permitted for one repository.
type RepositoryBindingAutomationSpec struct {
	Observe                    bool `json:"observe,omitempty"`
	AllowDispatchWorkflow      bool `json:"allow_dispatch_workflow,omitempty"`
	AllowPullRequestAutomation bool `json:"allow_pull_request_automation,omitempty"`
	AllowDirectPush            bool `json:"allow_direct_push,omitempty"`
}
