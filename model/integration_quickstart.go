package model

// IntegrationQuickstartManifestSpec is the product-facing onboarding contract.
//
// Each integration repository SHOULD ship a yggdrasil-quickstart.yaml at its
// root that adopters consume via:
//
//   POST /api/v1/integrations/install
//   { "repo_ref": "<owner>/<repo>", "provider_id": "<id>", "inputs": {...} }
//
// The Yggdrasil core fetches the manifest, validates that all `requires` are
// met by the caller's installation, prompts/accepts the inputs, then compiles
// the providers' steps into a one-shot workflow that executes via existing
// integrations (aws, github, kubernetes, etc.). A successful run leaves the
// integration_instance registered, the adapter pod running, and a smoke_test
// confirming end-to-end reachability.
//
// Why server-side: we keep adopters CLI-agnostic. A `yggdrasil` CLI is a
// pretty TUI on top of this same API, but `curl` works too.
type IntegrationQuickstartManifestSpec struct {
	DisplayName string                 `json:"display_name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Providers   []ProviderQuickstart   `json:"providers"`
}

// ProviderQuickstart is the per-provider entry point. A quickstart manifest
// can declare multiple providers (e.g. integration-secrets-management has
// `aws-secrets-manager` and `gcp-secret-manager`); the install request picks
// one by ID.
type ProviderQuickstart struct {
	ID          string                  `json:"id"`
	DisplayName string                  `json:"display_name,omitempty"`
	Description string                  `json:"description,omitempty"`

	// Requires lists what must already exist on the cluster before this
	// provider can install. The processor checks every entry up front and
	// returns a clear error listing what's missing.
	Requires []QuickstartRequirement `json:"requires,omitempty"`

	// Inputs declares the questions the user (or automation) must answer.
	// Order matters — earlier inputs are available as `{{ inputs.X }}` in
	// later inputs' defaults and validators, enabling cascading prompts.
	Inputs []QuickstartInput `json:"inputs,omitempty"`

	// Steps are executed in order. Each step uses an EXISTING family or
	// integration_instance to do the actual work; the processor compiles
	// them into a workflow manifest that runs through the standard engine.
	Steps []QuickstartStep `json:"steps"`

	// SmokeTest is appended as the final workflow step. A failure here
	// signals that the install completed in form but the provider isn't
	// actually reachable — a strong signal for the adopter to debug.
	SmokeTest *QuickstartSmokeTest `json:"smoke_test,omitempty"`

	// PostInstallHints render after success and tell the adopter what to
	// try next ("now run `yggdrasil secrets upsert ...`"). Pure UX —
	// nothing in the runtime consumes them.
	PostInstallHints []string `json:"post_install_hints,omitempty"`
}

// QuickstartRequirement is a precondition checked BEFORE inputs are collected
// so we fail fast. Three flavors:
//
//   - integration_family : an active integration_type implementing the
//     named family must exist
//   - integration_type   : a specific type (e.g. "aws") must be installed
//   - cluster_capability : the cluster must expose a capability — opaque
//     string the runtime maps to its own checks ("kubernetes", "rds", ...)
type QuickstartRequirement struct {
	Kind       string `json:"kind"`              // integration_family | integration_type | cluster_capability
	Name       string `json:"name,omitempty"`    // family/type name (kind=integration_*)
	Capability string `json:"capability,omitempty"` // cluster capability name (kind=cluster_capability)
	Reason     string `json:"reason,omitempty"`  // human-readable explanation surfaced when missing
}

// QuickstartInput is one question. Type drives both the TUI widget (text /
// number / boolean / select) and the validator. Sensitive flips redaction in
// logs and TUI display.
type QuickstartInput struct {
	ID          string             `json:"id"`
	Label       string             `json:"label"`
	Description string             `json:"description,omitempty"`
	Help        string             `json:"help,omitempty"`
	Type        string             `json:"type,omitempty"`        // string (default) | integer | boolean | select
	Default     any                `json:"default,omitempty"`     // template-rendered against earlier inputs
	Required    bool               `json:"required,omitempty"`
	Sensitive   bool               `json:"sensitive,omitempty"`
	Choices     []QuickstartChoice `json:"choices,omitempty"`     // type=select
	Validate    *QuickstartValidate `json:"validate,omitempty"`
}

type QuickstartChoice struct {
	Value       string `json:"value"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
}

type QuickstartValidate struct {
	Regex   string `json:"regex,omitempty"`
	Min     *int   `json:"min,omitempty"`
	Max     *int   `json:"max,omitempty"`
	Message string `json:"message,omitempty"`
}

// QuickstartStep mirrors one entry in the compiled workflow's spec.steps.
// The fields parallel WorkflowStep but with template-friendly types — the
// processor renders {{ inputs.X }} and {{ steps.Y.outputs.Z }} placeholders
// then writes the resolved values into a real WorkflowStep.
type QuickstartStep struct {
	ID          string                 `json:"id"`
	Description string                 `json:"description,omitempty"`
	Condition   string                 `json:"condition,omitempty"` // template, evaluated by workflow engine

	// Uses is one of the WorkflowStepUseSpec shapes (instance_ref OR
	// family+operation OR family+capability OR kind:product/installation.apply).
	// We keep it as map[string]any so the processor can pass it through to
	// the workflow without re-modeling every variant.
	Uses map[string]any `json:"uses"`
	With map[string]any `json:"with,omitempty"`

	// OutputTo names a key under which subsequent steps can reference this
	// step's result via {{ steps.<id>.outputs.<OutputTo> }}. Optional.
	OutputTo string `json:"output_to,omitempty"`

	Retry          *WorkflowRetrySpec `json:"retry,omitempty"`
	TimeoutSeconds int                `json:"timeout_seconds,omitempty"`
}

// QuickstartSmokeTest is appended as the last workflow step. It MUST hit the
// freshly-deployed provider via family resolution (so it exercises the
// runtime resolver too), not via a direct instance_ref.
type QuickstartSmokeTest struct {
	Description string                 `json:"description,omitempty"`
	Uses        map[string]any         `json:"uses"`
	With        map[string]any         `json:"with,omitempty"`
	// Expect is forwarded to the workflow engine's value-equality check.
	// Empty means "any successful response".
	Expect map[string]any `json:"expect,omitempty"`
	TimeoutSeconds int     `json:"timeout_seconds,omitempty"`
}

// =========================================================================
// Install request / response (used by the HTTP endpoint)
// =========================================================================

// InstallIntegrationRequest is what the API endpoint accepts.
type InstallIntegrationRequest struct {
	// RepoRef identifies where to fetch the yggdrasil-quickstart.yaml from.
	// Supported forms (resolved by the github integration):
	//   - "owner/repo"               → default branch, root path
	//   - "owner/repo@ref"           → specific branch/tag/sha
	//   - "owner/repo:path/to/file"  → custom path inside the repo
	RepoRef string `json:"repo_ref"`

	// ProviderID picks ONE provider from the manifest's providers list.
	// Required when the manifest declares more than one.
	ProviderID string `json:"provider_id,omitempty"`

	// Inputs maps QuickstartInput.ID → user-supplied value. Missing
	// required inputs fail validation.
	Inputs map[string]any `json:"inputs,omitempty"`

	// DryRun=true compiles the workflow and returns it without dispatching.
	// Used by the CLI to preview what would run.
	DryRun bool `json:"dry_run,omitempty"`
}

// InstallIntegrationResponse is what the endpoint returns. When DryRun is
// false, RunID/RunURL point at the workflow run created. When DryRun is true,
// CompiledWorkflow contains the rendered workflow manifest for inspection.
type InstallIntegrationResponse struct {
	ProviderID       string                  `json:"provider_id"`
	RunID            string                  `json:"run_id,omitempty"`
	RunURL           string                  `json:"run_url,omitempty"`
	CompiledWorkflow *WorkflowManifestSpec   `json:"compiled_workflow,omitempty"`
	Hints            []string                `json:"hints,omitempty"`
}
