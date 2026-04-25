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
	Deploy             *RepositoryBindingDeploySpec    `json:"deploy,omitempty"`
}

// RepositoryBindingAutomationSpec declares what automated actions are permitted for one repository.
type RepositoryBindingAutomationSpec struct {
	Observe                    bool `json:"observe,omitempty"`
	AllowDispatchWorkflow      bool `json:"allow_dispatch_workflow,omitempty"`
	AllowPullRequestAutomation bool `json:"allow_pull_request_automation,omitempty"`
	AllowDirectPush            bool `json:"allow_direct_push,omitempty"`
}

// RepositoryBindingDeploySpec configures auto-deploy on push events. When set on a
// RepositoryBindingManifestSpec, the GitHub webhook handler dispatches a workflow
// with inputs templated from the push payload.
type RepositoryBindingDeploySpec struct {
	// WorkflowKind is the dispatch target. Currently supported:
	//   "yggdrasil"      — dispatches a Yggdrasil workflow_run via WorkflowRef.
	//   "github_actions" — reserved for future use; webhook returns 501 in v2.0.0.
	WorkflowKind string `json:"workflow_kind"`

	// WorkflowRef identifies the Yggdrasil workflow manifest to run.
	// Required when WorkflowKind == "yggdrasil".
	WorkflowRef *ManifestRef `json:"workflow_ref,omitempty"`

	// DefaultInputs are passed as workflow inputs after substituting
	// {{ push.* }} placeholders against the GitHub push payload.
	// Non-string scalars are passed through unchanged.
	DefaultInputs map[string]any `json:"default_inputs,omitempty"`

	// BranchFilter restricts dispatch to pushes whose `ref` matches one of
	// the listed branches (exact match against `refs/heads/<branch>`).
	// After NormalizeRepositoryBindingSpec, missing or empty defaults to ["main"].
	// Set to ["*"] to accept any branch.
	BranchFilter []string `json:"branch_filter,omitempty"`

	// PathFilter, if non-empty, requires at least one modified file in the
	// head commit to match one of the listed glob patterns
	// (path/filepath.Match semantics). Empty means no path filtering.
	PathFilter []string `json:"path_filter,omitempty"`
}

// ManifestRef names another manifest in the same Yggdrasil instance.
type ManifestRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// RepositoryBindingManifest is the persisted shape of a repository_binding,
// returned by the BindingStore lookup path.
type RepositoryBindingManifest struct {
	Metadata ManifestMetadata              `json:"metadata"`
	Spec     RepositoryBindingManifestSpec `json:"spec"`
}
